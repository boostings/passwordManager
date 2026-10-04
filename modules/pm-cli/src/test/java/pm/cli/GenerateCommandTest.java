package pm.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import pm.domain.generate.CharClass;

/** plan.md §13 M4.4: {@code pm generate} prints one secret on stdout and its entropy on stderr. */
class GenerateCommandTest {
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");

    private static int run(FakeConsoleIo io, String... args) {
        Map<String, String> props = Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, "/nonexistent-home");
        return new Cli(props::get, Clock.fixed(NOW, ZoneOffset.UTC), p -> { })
                .run(args, io, (path, creating) -> {
                    throw new AssertionError("generate must not open the vault");
                });
    }

    private static String generated(String... args) {
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, args), io::errText);
        String out = io.outText();
        assertTrue(out.endsWith("\n"), out);
        assertEquals(1, out.lines().count(), "stdout holds exactly the secret");
        assertTrue(io.errText().startsWith(Messages.GENERATED_ENTROPY.text()), io::errText);
        return out.strip();
    }

    @Test
    void defaultPasswordIsTwentyCharactersFromAllClasses() {
        String drawn = generated("generate");
        assertEquals(20, drawn.length());
        assertTrue(drawn.chars().anyMatch(Character::isLowerCase));
        assertTrue(drawn.chars().anyMatch(Character::isUpperCase));
        assertTrue(drawn.chars().anyMatch(Character::isDigit));
    }

    @Test
    void lengthClassesAndAmbiguityAreHonoured() {
        String drawn = generated("generate", "--length", "64", "--classes", "lower,digits", "--exclude-ambiguous");
        assertEquals(64, drawn.length());
        for (int i = 0; i < drawn.length(); i++) {
            char c = drawn.charAt(i);
            assertTrue(Character.isLowerCase(c) || Character.isDigit(c), drawn);
            assertTrue(CharClass.AMBIGUOUS.indexOf(c) < 0, drawn);
        }
    }

    @Test
    void passphraseUsesWordsAndSeparator() {
        String phrase = generated("generate", "--passphrase", "--words", "5", "--separator", ".");
        assertEquals(5, phrase.split("\\.", -1).length, phrase);
        assertFalse(phrase.contains("-"), phrase);
    }

    @Test
    void generateRunsWithoutATerminalSoItCanBePiped() {
        Map<String, String> props = Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, "/nonexistent-home");
        Cli cli = new Cli(props::get, Clock.fixed(NOW, ZoneOffset.UTC), p -> { });
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        Charset cs = Charset.defaultCharset();
        try (PrintStream o = new PrintStream(out, true, cs); PrintStream e = new PrintStream(err, true, cs)) {
            assertEquals(ExitCodes.OK, cli.run(new String[] {"generate", "--length", "32"}, Optional.empty(), o, e));
            assertEquals(32, out.toString(cs).strip().length(), () -> out.toString(cs));
            assertEquals(1, out.toString(cs).lines().count(), "stdout holds exactly the secret: pm generate | pbcopy");
            assertTrue(err.toString(cs).startsWith(Messages.GENERATED_ENTROPY.text()), () -> err.toString(cs));

            out.reset();
            err.reset();
            assertEquals(ExitCodes.USAGE, cli.run(new String[] {"list"}, Optional.empty(), o, e));
            assertTrue(err.toString(cs).contains(Messages.NO_TERMINAL.text()), "other commands still need a terminal");
            assertEquals(0, out.size());
            assertEquals(ExitCodes.USAGE, cli.run(new String[0], Optional.empty(), o, e));
        }
    }

    @Test
    void pipedIoReadsNothing() {
        PipedIo io = new PipedIo(new ByteArrayOutputStream(), new ByteArrayOutputStream(), Charset.defaultCharset());
        assertEquals(null, io.readLine("x"));
        assertEquals(0, io.readPassword("x").length);
    }

    @Test
    void twoRunsDiffer() {
        assertFalse(generated("generate").equals(generated("generate")));
    }

    @Test
    void badPoliciesAndMixedOptionsAreUsageErrors() {
        String[][] cases = {
            {"generate", "--length", "3"},
            {"generate", "--length", "2000"},
            {"generate", "--length", "x"},
            {"generate", "--classes", "lower,emoji"},
            {"generate", "--classes", ""},
            {"generate", "--passphrase", "--words", "2"},
            {"generate", "--passphrase", "--separator", "ab"},
        };
        for (String[] args : cases) {
            FakeConsoleIo io = new FakeConsoleIo();
            assertEquals(ExitCodes.USAGE, run(io, args), String.join(" ", args));
            assertEquals("", io.outText(), String.join(" ", args));
        }
        FakeConsoleIo mixed = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(mixed, "generate", "--passphrase", "--length", "30"));
        assertTrue(mixed.errText().contains(Messages.GENERATE_MIXED_OPTIONS.text()), mixed::errText);
        FakeConsoleIo mixed2 = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(mixed2, "generate", "--words", "4"));
        FakeConsoleIo dup = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(dup, "generate", "--length", "30", "--length", "31"));
        assertTrue(dup.errText().contains(Messages.DUPLICATE_OPTION.text()), dup::errText);
        FakeConsoleIo extra = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(extra, "generate", "loose"));
    }

    @Test
    void aFailingTerminalIsReported() {
        FakeConsoleIo io = new FakeConsoleIo().failingOut();
        assertEquals(ExitCodes.STORAGE, run(io, "generate"));
        assertTrue(io.errText().contains(Messages.ERR_TERMINAL.text()), io::errText);
    }
}
