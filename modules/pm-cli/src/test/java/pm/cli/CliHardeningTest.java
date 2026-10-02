package pm.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import pm.crypto.Argon2Params;
import pm.vault.record.LoginRecord;
import pm.vault.record.VaultRecord;

/**
 * Regression tests for the M1 adversarial review of pm-cli: lost recovery key on a failing stdout
 * (ADR 0004), internal errors (SR-501), record ownership on a refused put (SR-505), invisible and
 * bidi characters (IDS01-J), {@code --vault}/{@code --} handling, and KDF tuning only for init
 * (ADR 0007).
 */
class CliHardeningTest {
    private static final String CANARY = MainArgsTest.CANARY;
    private static final String LOGIN_SECRET = "hunter2-login-secret";
    private static final Instant NOW = Instant.parse("2026-10-02T12:00:00Z");

    private final List<Path> opened = new ArrayList<>();
    private final List<Boolean> creating = new ArrayList<>();
    private TuiLauncher launcher = p -> { };

    private int run(FakeConsoleIo io, FakeVaultPort port, String... args) {
        return run(io, (path, forCreate) -> {
            opened.add(path);
            creating.add(forCreate);
            return port;
        }, args);
    }

    private int run(FakeConsoleIo io, VaultOpener opener, String... args) {
        Cli cli = new Cli(Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, "/home/alice")::get,
                Clock.fixed(NOW, ZoneOffset.UTC), p -> launcher.launch(p));
        return cli.run(args, io, opener);
    }

    // ---- finding 1: recovery key lost on a failing stdout -------------------------------------

    @Test
    void initWithFailingStdoutReportsTheLostRecoveryKey() {
        FakeVaultPort port = new FakeVaultPort();
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY).secret(CANARY).failingOut();

        assertEquals(ExitCodes.RECOVERY_NOT_SHOWN, run(io, port, "init"));

        assertTrue(port.exists(), "the vault was created");
        assertEquals(Messages.ERR_RECOVERY_NOT_SHOWN.text(), io.errText().strip());
        assertFalse(io.errText().contains(FakeVaultPort.RECOVERY_KEY));
        assertTrue(port.recoveryKey().isClosed());
        assertTrue(port.session().isLocked());
        assertTrue(io.allSecretsZeroed());
    }

    @Test
    void recoveryKeyExitCodeIsDistinctFromEveryOther() {
        List<Integer> others = List.of(ExitCodes.OK, ExitCodes.WRONG_CREDENTIAL, ExitCodes.USAGE,
                ExitCodes.CORRUPT, ExitCodes.STORAGE, ExitCodes.INTERNAL);
        assertFalse(others.contains(ExitCodes.RECOVERY_NOT_SHOWN));
        assertFalse(List.of(ExitCodes.OK, ExitCodes.WRONG_CREDENTIAL, ExitCodes.USAGE, ExitCodes.CORRUPT,
                ExitCodes.STORAGE).contains(ExitCodes.INTERNAL));
    }

    // ---- finding 2: unexpected runtime exceptions ---------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"init", "list", "add-login"})
    void runtimeExceptionFromPortIsInternalErrorWithCatalogueTextOnly(String command) {
        FakeVaultPort port = new FakeVaultPort().buggy();
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY).secret(CANARY);

        assertEquals(ExitCodes.INTERNAL, run(io, port, command));

        assertEquals(Messages.ERR_INTERNAL.text(), io.errText().strip());
        assertFalse(io.outText().contains(CANARY));
        assertFalse(io.outText().contains("IllegalStateException"));
        assertTrue(io.allSecretsZeroed());
    }

    @Test
    void runtimeExceptionFromOpenerIsInternalError() {
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

        assertEquals(ExitCodes.INTERNAL, run(io, (path, forCreate) -> {
            throw new IllegalStateException("kdf benchmark failed");
        }, "list"));
        assertEquals(Messages.ERR_INTERNAL.text(), io.errText().strip());
    }

    @Test
    void runtimeExceptionFromTuiLauncherIsInternalError() {
        launcher = p -> {
            throw new IllegalStateException("lanterna blew up " + CANARY);
        };
        FakeConsoleIo io = new FakeConsoleIo();

        assertEquals(ExitCodes.INTERNAL, run(io, new FakeVaultPort(), "tui"));
        assertEquals(Messages.ERR_INTERNAL.text(), io.errText().strip());
        assertEquals("", io.outText());
    }

    @Test
    void lastResortReportPrintsCatalogueTextOnly() {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (PrintStream err = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
            Cli.reportInternalError(err);
        }
        assertEquals(Messages.ERR_INTERNAL.text(), bytes.toString(StandardCharsets.UTF_8).strip());
    }

    // ---- finding 5: a refused put closes the new record ---------------------------------------

    @Test
    void refusedPutClosesTheNewRecordAndItsPassword() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY).refusingPut();
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY)
                .line("GitHub").line("alice").secret(LOGIN_SECRET).line("https://github.com").line("");

        assertEquals(ExitCodes.INTERNAL, run(io, port, "add-login"));

        assertEquals(1, port.refused.size());
        try (VaultRecord refused = port.refused.get(0)) {
            assertTrue(assertInstanceOf(LoginRecord.class, refused).password().isClosed(),
                    "password zeroed when the session refused the record");
        }
        assertTrue(port.stored.isEmpty());
        assertEquals(0, port.saves);
        assertTrue(port.session().isLocked());
        assertTrue(io.allSecretsZeroed());
    }

    // ---- finding 7: bidi, zero-width and separator characters ---------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"\u202E", "\u200B", "\u2028", "\u2029", "\u061C", "\uDB40\uDC41"})
    void listReplacesInvisibleAndBidiCharacters(String unsafe) {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        port.stored.add(FakeVaultPort.login("ab" + unsafe + "exe.txt", LOGIN_SECRET, NOW));
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

        assertEquals(ExitCodes.OK, run(io, port, "list"));

        assertFalse(io.outText().contains(unsafe));
        assertTrue(io.outText().contains("ab?exe.txt"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\u202E", "\u200B", "\u2028", "\u2029", "\u061C", "\uDB40\uDC41"})
    void searchReplacesInvisibleAndBidiCharacters(String unsafe) {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        port.stored.add(FakeVaultPort.login("site" + unsafe + "x", LOGIN_SECRET, NOW));
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

        assertEquals(ExitCodes.OK, run(io, port, "search", "site"));

        assertFalse(io.outText().contains(unsafe));
        assertTrue(io.outText().contains("site?x"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\u202E", "\u200B", "\u2028", "\u2029", "\u061C", "\uDB40\uDC41"})
    void addLoginRejectsInvisibleAndBidiCharactersInEveryTextField(String unsafe) {
        String bad = "a" + unsafe + "b";
        List<FakeConsoleIo> scripts = List.of(
                new FakeConsoleIo().secret(CANARY).line(bad),
                new FakeConsoleIo().secret(CANARY).line("T").line(bad),
                new FakeConsoleIo().secret(CANARY).line("T").line("u").secret(LOGIN_SECRET).line(bad),
                new FakeConsoleIo().secret(CANARY).line("T").line("u").secret(LOGIN_SECRET).line("").line(bad));
        for (FakeConsoleIo io : scripts) {
            FakeVaultPort port = new FakeVaultPort().withVault(CANARY);

            assertEquals(ExitCodes.USAGE, run(io, port, "add-login"));

            assertTrue(port.stored.isEmpty());
            assertEquals(Messages.INVALID_TEXT.text(), io.errText().strip());
            assertTrue(io.allSecretsZeroed());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"\u202E", "\u200B", "\u2028", "\u061C"})
    void searchRejectsInvisibleCharactersInTheQuery(String unsafe) {
        FakeConsoleIo io = new FakeConsoleIo();

        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort(), "search", "a" + unsafe + "b"));
        assertEquals(Messages.INVALID_TEXT.text(), io.errText().strip());
        assertTrue(opened.isEmpty());
    }

    @Test
    void displaySafeKeepsOrdinaryUnicode() {
        assertEquals("Caf\u00E9 \u6771\u4EAC \uD83D\uDE00 ?",
                Cli.displaySafe("Caf\u00E9 \u6771\u4EAC \uD83D\uDE00 \u202E"));
    }

    // ---- finding 8: --vault values and "--" ---------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {".", "..", "sub/.", "sub/..", "/", "sub/"})
    void vaultValueNamingADirectoryIsUsage(String value) {
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort().withVault(CANARY), "--vault", value, "list"));
        assertEquals(Messages.VAULT_PATH_NOT_FILE.text(), io.errText().strip());
        assertTrue(opened.isEmpty());
    }

    @Test
    void vaultValueThatIsAnExistingDirectoryIsUsage(@TempDir Path dir) throws IOException {
        Path sub = Files.createDirectory(dir.resolve("vault.pmv"));
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort().withVault(CANARY), "--vault", sub.toString(), "list"));
        assertEquals(Messages.VAULT_PATH_NOT_FILE.text(), io.errText().strip());
        assertTrue(opened.isEmpty());
    }

    @Test
    void vaultValueThatIsAFileInATempDirIsAccepted(@TempDir Path dir) {
        Path file = dir.resolve("vault.pmv");

        assertEquals(ExitCodes.OK, run(new FakeConsoleIo().secret(CANARY), new FakeVaultPort().withVault(CANARY),
                "--vault", file.toString(), "list"));
        assertEquals(List.of(file.toAbsolutePath().normalize()), opened);
    }

    @ParameterizedTest
    @ValueSource(strings = {"~/v.pmv", "~", "~alice/v.pmv"})
    void tildeIsNotExpandedAndIsUsage(String value) {
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort().withVault(CANARY), "--vault", value, "list"));
        assertEquals(Messages.VAULT_PATH_TILDE.text(), io.errText().strip());
        assertTrue(opened.isEmpty());
    }

    @Test
    void fileNamedWithLeadingTildeCanStillBeReached() {
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo().secret(CANARY), new FakeVaultPort().withVault(CANARY),
                "--vault", "./~v.pmv", "list"));
        assertEquals("~v.pmv", opened.get(0).getFileName().toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"--help", "-h", "--", "--vault", "-x"})
    void optionLookingVaultValueIsUsage(String value) {
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort().withVault(CANARY), "--vault", value, "list"));
        assertEquals(Messages.MISSING_VAULT_PATH.text(), io.errText().strip());
        assertFalse(io.outText().contains(Messages.USAGE.text()), "--help after --vault is not help");
        assertTrue(opened.isEmpty());
    }

    @Test
    void doubleDashLetsSearchTakeADashQuery() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        try (VaultRecord hit = FakeVaultPort.login("x-foo", LOGIN_SECRET, NOW);
                VaultRecord miss = FakeVaultPort.login("Bank", LOGIN_SECRET, NOW)) {
            port.stored.addAll(List.of(hit, miss));
            FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

            assertEquals(ExitCodes.OK, run(io, port, "search", "--", "-foo"));

            assertTrue(io.outText().contains(hit.id().toString()));
            assertFalse(io.outText().contains(miss.id().toString()));
        }
    }

    @Test
    void doubleDashBeforeCommandAndAfterOptionsWorks() {
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo().secret(CANARY), new FakeVaultPort().withVault(CANARY),
                "--vault", "/data/v.pmv", "--", "list"));
        assertEquals(List.of(Path.of("/data/v.pmv").toAbsolutePath().normalize()), opened);
    }

    @Test
    void optionsAfterDoubleDashAreOperands() {
        FakeConsoleIo io = new FakeConsoleIo();

        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort(), "list", "--", "--vault", "x.pmv"));
        assertEquals(Messages.WRONG_ARG_COUNT.text(), io.errText().strip());
        assertTrue(opened.isEmpty());
    }

    @Test
    void dashQueryWithoutDoubleDashIsStillAnUnknownOption() {
        FakeConsoleIo io = new FakeConsoleIo();

        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort(), "search", "-foo"));
        assertEquals(Messages.UNKNOWN_OPTION.text(), io.errText().strip());
    }

    // ---- latency: KDF tuning only for init (ADR 0007) -----------------------------------------

    @Test
    void onlyInitOpensTheVaultForCreation() {
        FakeVaultPort port = new FakeVaultPort();
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo().secret(CANARY).secret(CANARY), port, "init"));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo().secret(CANARY), port, "list"));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo().secret(CANARY), port, "search", "x"));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), port, "tui"));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo().secret(CANARY).line("T").line("u").secret(LOGIN_SECRET)
                .line("").line(""), port, "add-login"));

        assertEquals(List.of(true, false, false, false, false), creating);
    }

    @Test
    void kdfIsTunedOnlyWhenCreating() {
        AtomicInteger tunes = new AtomicInteger();
        Argon2Params tuned = new Argon2Params(Argon2Params.FLOOR.memoryKiB() * 2, Argon2Params.FLOOR.iterations(),
                Argon2Params.FLOOR.parallelism());

        assertSame(Argon2Params.FLOOR, Cli.kdfFor(false, () -> {
            tunes.incrementAndGet();
            return tuned;
        }));
        assertEquals(0, tunes.get(), "unlock never benchmarks the KDF");
        assertSame(tuned, Cli.kdfFor(true, () -> {
            tunes.incrementAndGet();
            return tuned;
        }));
        assertEquals(1, tunes.get());
    }
}
