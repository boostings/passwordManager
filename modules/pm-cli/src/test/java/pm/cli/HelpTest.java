package pm.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.module.ModuleDescriptor;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import pm.domain.env.Env;
import pm.vault.VaultException;

/**
 * M7.7 help and version (SR-135). The coverage test walks the {@link Command} table, which is also
 * the dispatch table: every entry is listed in the usage, has help reachable as {@code pm help
 * <words>} and {@code pm <words> --help} with exit 0, resolves back to itself, and is dispatched
 * (never answered with "unknown command"). Every usage and help line fits in 80 columns.
 */
class HelpTest {
    private static final Instant NOW = Instant.parse("2026-10-06T09:00:00Z");

    @TempDir
    Path tmp;

    private final List<Path> opened = new ArrayList<>();

    private int run(FakeConsoleIo io, String... args) {
        List<String> all = new ArrayList<>(List.of("--vault", tmp.resolve("v").resolve("vault.pmv").toString()));
        all.addAll(List.of(args));
        Cli cli = new Cli(Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, tmp.toString(),
                "user.dir", tmp.toString(), "user.name", "alice")::get, Clock.fixed(NOW, ZoneOffset.UTC), p -> { })
                .withEnvironment(Env.of(Map.of()));
        return cli.run(all.toArray(String[]::new), io, (path, creating) -> {
            opened.add(path);
            return new FakeVaultPort().failing(VaultException.Code.STORAGE);
        });
    }

    private static String[] with(List<String> words, String... more) {
        List<String> all = new ArrayList<>(words);
        all.addAll(List.of(more));
        return all.toArray(String[]::new);
    }

    @ParameterizedTest
    @EnumSource(Command.class)
    void everyEntryIsListedHasHelpAndIsDispatched(Command command) throws UsageException {
        assertTrue(Command.usage().contains(command.usageLine() + "\n"), command::usageLine);
        assertTrue(command.help().startsWith("usage: pm " + command.word()), command::help);

        FakeConsoleIo viaHelp = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(viaHelp, with(List.of("help"), command.words().toArray(String[]::new))),
                viaHelp::errText);
        assertTrue(viaHelp.outText().contains(command.help()), viaHelp::outText);
        FakeConsoleIo viaOption = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(viaOption, with(command.words(), "--help")), viaOption::errText);
        assertTrue(viaOption.outText().contains(command.help()), viaOption::outText);
        FakeConsoleIo shortOption = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(shortOption, with(command.words(), "-h")), shortOption::errText);
        assertEquals(viaOption.outText(), shortOption.outText());

        assertSame(command, Command.resolve(command.word(), command.sub().map(List::of).orElse(List.of())));
        FakeConsoleIo dispatched = new FakeConsoleIo();
        run(dispatched, command.words().toArray(String[]::new));
        assertFalse(dispatched.errText().contains(Messages.UNKNOWN_COMMAND.text()), dispatched::errText);
    }

    @Test
    void everyUsageAndHelpLineFitsIn80Columns() {
        List<String> lines = new ArrayList<>(Command.lines(Command.usage()));
        for (Command c : Command.values()) {
            lines.addAll(Command.lines(c.help()));
        }
        for (String line : lines) {
            assertTrue(line.length() <= Command.MAX_COLUMNS, () -> line.length() + ": " + line);
            assertFalse(line.contains("\t"), line);
        }
        assertTrue(Command.lines(Command.usage()).size() > Command.values().length, "multi-line, grouped by area");
        for (Command.Area area : Command.Area.values()) {
            assertTrue(Command.usage().contains("\n" + area.heading() + "\n"), area::heading);
        }
    }

    /** A row of an option table: {@code --name [<arg>]}, two or more spaces, then its description. */
    private static boolean isOptionRow(String line) {
        String text = line.stripLeading();
        return text.startsWith("--") && text.contains("  ") && !text.endsWith(" ");
    }

    @Test
    void everyOptionTableIsIndentedAndUnbroken() {
        for (Command c : Command.values()) {
            List<String> lines = Command.lines(c.help());
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                if (isOptionRow(line)) {
                    assertTrue(line.startsWith("  --"), () -> c + ": " + line);
                    if (i >= 2 && lines.get(i - 1).isEmpty()) {
                        String before = lines.get(i - 2);
                        assertFalse(isOptionRow(before), () -> c + ": blank line inside its options: " + line);
                    }
                }
            }
        }
    }

    @Test
    void everyHelpSpellingExitsZeroWithoutAVault() {
        for (String[] args : List.of(new String[] {"--help"}, new String[] {"-h"}, new String[] {"help"})) {
            FakeConsoleIo io = new FakeConsoleIo();
            assertEquals(ExitCodes.OK, run(io, args), io::errText);
            assertEquals(Command.usage(), io.outText().strip(), String.join(" ", args));
        }
        FakeConsoleIo nested = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(nested, "help", "ssh"));
        assertTrue(nested.outText().contains(Command.SSH_ADD.help()) && nested.outText().contains(
                Command.SSH_LIST.help()), "help for a word covers all its subcommands");
        FakeConsoleIo sub = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(sub, "env", "run", "--help"));
        assertEquals(Command.ENV_RUN.help(), sub.outText().strip());
        FakeConsoleIo afterOperands = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(afterOperands, "show", "GitHub", "--help"));
        assertEquals(Command.SHOW.help(), afterOperands.outText().strip());
        assertEquals(List.of(), opened, "help never opens the vault");
    }

    @Test
    void helpForSomethingUnknownIsUsage() {
        FakeConsoleIo unknown = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(unknown, "help", "frobnicate"));
        assertTrue(unknown.errText().contains(Messages.UNKNOWN_COMMAND.text()));
        FakeConsoleIo badSub = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(badSub, "help", "ssh", "frobnicate"));
        assertTrue(badSub.errText().contains(Messages.UNKNOWN_COMMAND.text()));
        FakeConsoleIo tooMany = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(tooMany, "help", "ssh", "add", "x"));
        FakeConsoleIo command = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(command, "frobnicate"));
        assertTrue(command.errText().contains(Command.usage()), "an unknown command shows the usage on stderr");
        assertEquals("", command.outText());
    }

    @Test
    void helpAfterTheEndOfOptionsIsAnOperand() {
        FakeConsoleIo io = new FakeConsoleIo();
        run(io, "search", "--", "--help");
        assertFalse(io.outText().contains(Command.SEARCH.help()), "-- ends the options, so --help is the query");
        assertEquals(1, opened.size(), "the search ran");
    }

    @Test
    void versionPrintsTheRuntimeVersion() {
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, "--version"), io::errText);
        assertEquals("pm " + Version.current(), io.outText().strip());
        assertEquals(List.of(), opened);
        FakeConsoleIo extra = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(extra, "list", "--version"));
    }

    @Test
    void theVersionComesFromTheModuleThenTheJarAndIsNeverMadeUp() {
        ModuleDescriptor versioned = ModuleDescriptor.newModule("pm.cli").version("1.2.3-M7").build();
        ModuleDescriptor unversioned = ModuleDescriptor.newModule("pm.cli").build();
        assertEquals("1.2.3-M7", Version.of(Optional.of(versioned), Optional.of("9.9")));
        assertEquals("9.9", Version.of(Optional.of(unversioned), Optional.of("9.9")));
        assertEquals("9.9", Version.of(Optional.empty(), Optional.of("9.9")));
        assertEquals(Version.UNKNOWN, Version.of(Optional.empty(), Optional.empty()));
    }

    @Test
    void helpAndVersionWorkWithoutATerminal() {
        Cli cli = new Cli(Map.<String, String>of()::get, Clock.fixed(NOW, ZoneOffset.UTC), p -> { });
        Charset cs = Charset.defaultCharset();
        for (String[] args : List.of(new String[] {"--help"}, new String[] {"help", "backup"},
                new String[] {"restore", "--help"}, new String[] {"--version"})) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            try (PrintStream o = new PrintStream(out, true, cs); PrintStream e = new PrintStream(err, true, cs)) {
                assertEquals(ExitCodes.OK, cli.run(args, Optional.empty(), o, e), () -> err.toString(cs));
            }
            assertFalse(out.toString(cs).isBlank(), String.join(" ", args));
        }
    }

    /** m77-006: the README's command table has a row for every entry the CLI dispatches. */
    @ParameterizedTest
    @EnumSource(Command.class)
    void theReadmeListsEveryCommand(Command command) throws IOException {
        String readme = Files.readString(Path.of("../../README.md"), StandardCharsets.UTF_8);
        String row = "| `" + String.join(" ", command.words());
        assertTrue(readme.lines().anyMatch(l -> l.startsWith(row)), "README.md has no row for " + command.words());
    }
}
