package pm.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.approval.AuditLog;
import pm.crypto.Argon2Params;
import pm.domain.env.Env;
import pm.tui.lan.BrowserWindow;

/** Each LAN command's argument checks, refusals and prompts, without a second device (M3.6). */
class LanCommandsTest {
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final String VAULT_PASSPHRASE = "lan commands passphrase";
    private static final String LOGIN_SECRET = "lan-commands-secret-value";
    private static final String NO_SHARE_ID = "0123456789abcdef0123456789abcdef";

    @TempDir
    Path tmp;

    private Path vault;
    private Path xdg;

    @BeforeEach
    void newVault() throws IOException {
        vault = tmp.resolve("v").resolve("vault.pmv");
        xdg = Files.createDirectory(tmp.resolve("xdg"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo().secret(VAULT_PASSPHRASE).secret(VAULT_PASSPHRASE), "init"));
        FakeConsoleIo add = unlocking().line("GitHub").line("octocat").secret(LOGIN_SECRET).line("").line("");
        assertEquals(ExitCodes.OK, run(add, "add-login"), add::errText);
    }

    @Test
    void usageNamesEveryLanCommand() {
        for (String shape : List.of("devices", "devices remove", "pair --listen", "share <title> --to <device>",
                "share <title> --browser", "receive <ip:port>", "revoke <share-id>")) {
            assertTrue(Command.usage().contains(shape) || Command.helpFor(shape.split(" ", -1)[0]).contains(shape), shape);
        }
    }

    @Test
    void theShareTimeToLiveIsShownAsTypedNotAsIso8601() {
        assertEquals("2m", LanCommands.ttlText(java.time.Duration.ofMinutes(2)));
        assertEquals("10m", LanCommands.ttlText(pm.sharing.share.Shares.DEFAULT_TTL));
        assertEquals("90s", LanCommands.ttlText(java.time.Duration.ofSeconds(90)));
        assertEquals("1h", LanCommands.ttlText(java.time.Duration.ofHours(1)));
        assertEquals("24h", LanCommands.ttlText(java.time.Duration.ofHours(24)));
        assertEquals("0s", LanCommands.ttlText(java.time.Duration.ZERO));
    }

    @Test
    void devicesShowsThisDeviceAndNoPeersAndKeepsTheIdentityOutOfTheList() {
        FakeConsoleIo devices = unlocking();
        assertEquals(ExitCodes.OK, run(devices, "devices"), devices::errText);
        assertTrue(devices.outText().contains(Messages.THIS_DEVICE.text() + "pm tester"), devices::outText);
        assertTrue(devices.outText().contains(Messages.NO_DEVICES.text()));
        FakeConsoleIo again = unlocking();
        assertEquals(ExitCodes.OK, run(again, "devices"));
        assertEquals(line(devices, Messages.THIS_DEVICE), line(again, Messages.THIS_DEVICE),
                "the identity is created once and kept in the vault");

        assertEquals(List.of("GitHub"), listed(), "only the login is listed");
        FakeConsoleIo search = unlocking();
        assertEquals(ExitCodes.OK, run(search, "search", "pm tester"));
        assertFalse(search.outText().contains("pm tester"), "the device identity is not searchable");
    }

    @Test
    @SuppressWarnings("PMD.AvoidUsingHardCodedIP") // CE-036: --bind must refuse these literal addresses
    void refusalsAreUsageErrorsWithTheirOwnMessage() {
        usage(Messages.UNKNOWN_COMMAND, "devices", "extra");
        usage(Messages.WRONG_ARG_COUNT, "devices", "remove");
        usage(Messages.NO_SUCH_DEVICE, "devices", "remove", "nobody");
        usage(Messages.UNKNOWN_OPTION, "pair", "--nope");
        usage(Messages.WRONG_ARG_COUNT, "pair");
        usage(Messages.WRONG_ARG_COUNT, "pair", "--listen", "127.0.0.1:1");
        usage(Messages.BAD_ADDRESS, "pair", "not-an-address");
        usage(Messages.BAD_BIND, "pair", "--listen", "--bind", "example.org");
        usage(Messages.BAD_BIND, "pair", "--listen", "--bind", "0.0.0.0"); // never every interface
        usage(Messages.BAD_BIND, "pair", "--listen", "--bind", "::");
        usage(Messages.BAD_BIND, "share", "GitHub", "--browser", "--bind", "0.0.0.0");
        usage(Messages.BAD_BIND, "pair", "--listen", "--bind", "192.0.2.1"); // RFC 5737: not this machine's
        usage(Messages.WRONG_ARG_COUNT, "pair", "--listen", "--name");
        usage(Messages.SHARE_TARGET_NEEDED, "share", "GitHub");
        usage(Messages.SHARE_TARGET_NEEDED, "share", "GitHub", "--browser", "--to", "x");
        usage(Messages.BAD_TTL, "share", "GitHub", "--browser", "--ttl", "3d");
        usage(Messages.BAD_TTL, "share", "GitHub", "--browser", "--ttl", "0m");
        usage(Messages.NO_SUCH_ITEM, "share", "Nothing", "--browser");
        usage(Messages.NO_SUCH_DEVICE, "share", "GitHub", "--to", "nobody");
        usage(Messages.BAD_ADDRESS, "receive", "999.1.1.1:80");
        usage(Messages.WRONG_ARG_COUNT, "receive");
        usage(Messages.BAD_SHARE_ID, "revoke", "nope");
        usage(Messages.NO_SUCH_SHARE, "revoke", NO_SHARE_ID);
        usage(Messages.WRONG_ARG_COUNT, "revoke");
    }

    @Test
    void aDeniedBrowserShareOpensNothingButShowedEveryWarningFirst() throws IOException {
        FakeConsoleIo io = unlocking().line("no");
        assertEquals(ExitCodes.DENIED, run(io, "share", "GitHub", "--browser", "--bind", InetAddress.getLoopbackAddress().getHostAddress()), io::errText);
        String out = io.outText();
        assertTrue(out.contains(Messages.BROWSER_HEADER.text()));
        for (String warning : BrowserWindow.WARNINGS) {
            assertTrue(out.contains(warning), warning);
            assertTrue(out.indexOf(warning) < out.indexOf(Messages.SHARE_CONFIRM.text()), "warned before asking");
        }
        assertFalse(out.contains(Messages.BROWSER_URL.text()), "no link without approval");
        assertFalse(out.contains(LOGIN_SECRET) || io.errText().contains(LOGIN_SECRET));
        assertTrue(markers().isEmpty(), "no share id was issued");
    }

    @Test
    void anApprovedShareRefusedByABrokenAuditLogSaysWhereItBrokeAndOpensNothing() throws IOException {
        // m712-002: the user is told the log is broken and after which entry, not just that it failed.
        Path log = Files.createFile(vault.resolveSibling(AuditLog.FILE_NAME),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.writeString(log, "not a log\n", StandardCharsets.US_ASCII);
        FakeConsoleIo io = unlocking().line(LanCommands.CONFIRM);
        assertEquals(ExitCodes.USAGE, run(io, "share", "GitHub", "--browser", "--bind",
                InetAddress.getLoopbackAddress().getHostAddress()), io::errText);
        assertEquals(UsageException.brokenLog(0), io.errText().strip());
        assertTrue(io.errText().startsWith("audit log tampered or truncated after entry 0,"), io::errText);
        assertFalse(io.outText().contains(Messages.BROWSER_URL.text()), "no audit, no share");
        assertTrue(markers().isEmpty(), "no share id was issued");
    }

    @Test
    void receiveFromNobodyFailsWithoutTouchingTheVault() {
        FakeConsoleIo io = unlocking().line("y");
        assertEquals(ExitCodes.NOT_DONE, run(io, "receive", "127.0.0.1:1"), io::outText);
        assertTrue(io.errText().contains(Messages.RECEIVE_UNREACHABLE.text()), io::errText);
        assertEquals(List.of("GitHub"), listed());
    }

    @Test
    void argsParseOptionsOperandsAndTheEndOfOptions() throws UsageException {
        LanCommands.Args a = LanCommands.Args.parse(List.of("x", "--to", "dev", "--ttl", "5m", "--", "--y"));
        assertEquals(List.of("x", "--y"), a.operands());
        assertEquals("dev", a.to().orElseThrow());
        assertEquals("5m", a.ttl().orElseThrow());
        assertThrows(UsageException.class, () -> LanCommands.Args.parse(List.of("--to", "a", "--to", "b")));
        assertThrows(UsageException.class, () -> LanCommands.Args.parse(List.of("--to", " ")));
        assertThrows(UsageException.class, () -> LanCommands.Args.parse(List.of("a" + Character.toString(0x202E) + "b")));
        assertThrows(UsageException.class, () -> LanCommands.Args.parse(List.of("a")).none());
    }

    // ---- helpers -----------------------------------------------------------------------------

    private void usage(Messages expected, String... command) {
        FakeConsoleIo io = unlocking().line("n");
        assertEquals(ExitCodes.USAGE, run(io, command), () -> String.join(" ", command) + ": " + io.errText());
        assertTrue(io.errText().contains(expected.text()), () -> String.join(" ", command) + ": " + io.errText());
    }

    /** Titles {@code pm list} prints, read from the rows under its {@code id  type  title  updated} header. */
    private List<String> listed() {
        FakeConsoleIo list = unlocking();
        assertEquals(ExitCodes.OK, run(list, "list"));
        return list.outText().lines().map(l -> l.split("  ")).filter(cols -> cols.length == 4).skip(1)
                .map(cols -> cols[2]).toList();
    }

    private static String line(FakeConsoleIo io, Messages prefix) {
        String out = io.outText();
        int start = out.indexOf(prefix.text());
        assertTrue(start >= 0, out);
        return out.substring(start, out.indexOf('\n', start));
    }

    private List<Path> markers() throws IOException {
        Path run = xdg.resolve("pm");
        if (!Files.isDirectory(run)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(run)) {
            return files.filter(p -> String.valueOf(p.getFileName()).startsWith(LanCommands.MARKER_PREFIX)).toList();
        }
    }

    private static FakeConsoleIo unlocking() {
        return new FakeConsoleIo().secret(VAULT_PASSPHRASE);
    }

    private int run(FakeConsoleIo io, String... command) {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        Cli cli = new Cli(Map.of("user.name", "tester")::get, clock, port -> fail("never launches the TUI"))
                .withEnvironment(Env.of(Map.of("XDG_RUNTIME_DIR", xdg.toString())));
        List<String> args = new ArrayList<>(List.of("--vault", vault.toString()));
        args.addAll(List.of(command));
        return cli.run(args.toArray(String[]::new), io,
                (path, creating) -> new FileVaultPort(path, clock, Cli.kdfFor(creating, () -> Argon2Params.FLOOR)));
    }
}
