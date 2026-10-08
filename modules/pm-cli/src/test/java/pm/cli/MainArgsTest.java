package pm.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import pm.storage.StorageException;
import pm.tui.VaultPort;
import pm.vault.VaultException;
import pm.vault.record.LoginRecord;
import pm.vault.record.VaultRecord;

class MainArgsTest {
    static final String CANARY = "CANARY-pw-7f3a";
    private static final String LOGIN_SECRET = "hunter2-login-secret";
    private static final Instant NOW = Instant.parse("2026-10-02T12:00:00Z");
    private static final String HOME = "/home/alice";

    private final Map<String, String> props = new HashMap<>(Map.of(
            VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, HOME));
    private final List<Path> opened = new ArrayList<>();
    private final List<Boolean> creating = new ArrayList<>();
    private final List<VaultPort> launched = new ArrayList<>();
    private TuiLauncher launcher = launched::add;
    private boolean vaultOnDisk;

    private int run(FakeConsoleIo io, FakeVaultPort port, String... args) {
        Cli cli = new Cli(props::get, Clock.fixed(NOW, ZoneOffset.UTC), p -> launcher.launch(p), p -> vaultOnDisk);
        return cli.run(args, io, (path, forCreate) -> {
            opened.add(path);
            creating.add(forCreate);
            return port;
        });
    }

    private static int count(String haystack, String needle) {
        int n = 0;
        for (int i = haystack.indexOf(needle); i >= 0; i = haystack.indexOf(needle, i + 1)) {
            n++;
        }
        return n;
    }

    // ---- init --------------------------------------------------------------------------------

    @Test
    void initCreatesVaultAndPrintsRecoveryKeyExactlyOnce() {
        FakeVaultPort port = new FakeVaultPort();
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY).secret(CANARY);

        assertEquals(ExitCodes.OK, run(io, port, "init"));

        assertTrue(port.exists());
        assertEquals(1, count(io.outText(), FakeVaultPort.RECOVERY_KEY));
        assertFalse(io.errText().contains(FakeVaultPort.RECOVERY_KEY));
        assertTrue(port.recoveryKey().isClosed(), "recovery key closed after display");
        assertTrue(port.session().isLocked(), "session locked after init");
        assertTrue(io.allSecretsZeroed());
    }

    @Test
    void initMismatchCreatesNothing() {
        FakeVaultPort port = new FakeVaultPort();
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY).secret(CANARY + "x");

        assertEquals(ExitCodes.USAGE, run(io, port, "init"));

        assertFalse(port.exists());
        assertEquals(0, port.creates);
        assertTrue(io.errText().contains(Messages.PASSPHRASE_MISMATCH.text()));
        assertFalse(io.outText().contains(FakeVaultPort.RECOVERY_KEY));
        assertTrue(io.allSecretsZeroed());
    }

    @Test
    void initRejectsEmptyPassphrase() {
        FakeVaultPort port = new FakeVaultPort();
        FakeConsoleIo io = new FakeConsoleIo().secret("").secret("");

        assertEquals(ExitCodes.USAGE, run(io, port, "init"));
        assertFalse(port.exists());
        assertTrue(io.errText().contains(Messages.EMPTY_PASSPHRASE.text()));
    }

    @Test
    void initWithClosedInputIsUsage() {
        FakeVaultPort port = new FakeVaultPort();
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

        assertEquals(ExitCodes.USAGE, run(io, port, "init"));
        assertFalse(port.exists());
        assertTrue(io.errText().contains(Messages.INPUT_CLOSED.text()));
        assertTrue(io.allSecretsZeroed());
    }

    @Test
    void initOverExistingVaultIsUsage() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY).secret(CANARY);

        assertEquals(ExitCodes.USAGE, run(io, port, "init"));
        assertTrue(io.errText().contains(Messages.ERR_ALREADY_EXISTS.text()));
    }

    @Test
    void initOverAVaultOnDiskRefusesBeforeAskingForAPassphrase() {
        vaultOnDisk = true;
        FakeConsoleIo io = new FakeConsoleIo();

        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort(), "init"));
        assertTrue(io.errText().contains(Messages.ERR_ALREADY_EXISTS.text()));
        assertFalse(io.outText().contains(Messages.PROMPT_NEW_PASSPHRASE.text()), io::outText);
        assertTrue(opened.isEmpty(), "the vault is not opened");
    }

    // ---- add-login ---------------------------------------------------------------------------

    @Test
    void addLoginStoresAndSavesRecord() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY)
                .line("GitHub").line("alice").secret(LOGIN_SECRET)
                .line("https://github.com, https://gist.github.com ,").line("work, dev");

        assertEquals(ExitCodes.OK, run(io, port, "add-login"));

        assertEquals(1, port.stored.size());
        try (LoginRecord login = assertInstanceOf(LoginRecord.class, port.stored.get(0))) {
            assertEquals("GitHub", login.title());
            assertEquals("alice", login.username());
            assertEquals(List.of("https://github.com", "https://gist.github.com"), login.urls());
            assertEquals(List.of("work", "dev"), login.tags());
            assertEquals("", login.notes());
            assertEquals(NOW, login.created());
            assertEquals(NOW, login.updated());
            login.password().withBytes(b -> assertArrayEquals(LOGIN_SECRET.getBytes(StandardCharsets.UTF_8), b));
            assertTrue(io.outText().contains(Messages.LOGIN_ADDED.text() + login.id()));
        }
        assertEquals(1, port.saves);
        assertTrue(port.session().isLocked());
        assertFalse(io.outText().contains(LOGIN_SECRET));
        assertTrue(io.allSecretsZeroed());
    }

    @Test
    void addLoginRejectsEmptyTitle() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY).line("   ");

        assertEquals(ExitCodes.USAGE, run(io, port, "add-login"));
        assertTrue(port.stored.isEmpty());
        assertTrue(port.session().isLocked());
        assertTrue(io.errText().contains(Messages.EMPTY_TITLE.text()));
    }

    @Test
    void addLoginRejectsControlCharacters() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY).line("Git\u001b[2JHub");

        assertEquals(ExitCodes.USAGE, run(io, port, "add-login"));
        assertTrue(port.stored.isEmpty());
        assertTrue(io.errText().contains(Messages.INVALID_TEXT.text()));
    }

    @Test
    void addLoginInputClosedAfterPasswordStoresNothing() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY).line("GitHub").line("alice").secret(LOGIN_SECRET);

        assertEquals(ExitCodes.USAGE, run(io, port, "add-login"));
        assertTrue(port.stored.isEmpty());
        assertEquals(0, port.saves);
        assertTrue(io.allSecretsZeroed());
    }

    @Test
    void addLoginWrongPassphraseIsExitOne() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        FakeConsoleIo io = new FakeConsoleIo().secret("not-the-passphrase");

        assertEquals(ExitCodes.WRONG_CREDENTIAL, run(io, port, "add-login"));
        assertTrue(port.stored.isEmpty());
        assertTrue(io.errText().contains(Messages.ERR_WRONG_CREDENTIAL.text()));
    }

    // ---- list / search -----------------------------------------------------------------------

    @Test
    void listPrintsMetadataOnly() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        try (VaultRecord a = FakeVaultPort.login("GitHub", LOGIN_SECRET, NOW);
                VaultRecord b = FakeVaultPort.login("Bank", LOGIN_SECRET, NOW)) {
            port.stored.addAll(List.of(a, b));
            FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

            assertEquals(ExitCodes.OK, run(io, port, "list"));

            String out = io.outText();
            assertTrue(out.contains(Messages.LIST_HEADER.text()));
            assertTrue(out.contains(a.id() + "  login  GitHub  " + NOW));
            assertTrue(out.contains(b.id() + "  login  Bank  " + NOW));
            assertFalse(out.contains(LOGIN_SECRET));
            assertFalse(out.contains("alice"), "username is not a list column");
        }
        assertTrue(port.session().isLocked());
    }

    @Test
    void listNeutralisesControlCharactersInTitles() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        port.stored.add(FakeVaultPort.login("evil\u001b[2J", LOGIN_SECRET, NOW));
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

        assertEquals(ExitCodes.OK, run(io, port, "list"));
        assertFalse(io.outText().contains("\u001b"));
        assertTrue(io.outText().contains("evil?[2J"));
    }

    @Test
    void searchPrintsOnlyMatches() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        try (VaultRecord hit = FakeVaultPort.login("GitHub", LOGIN_SECRET, NOW);
                VaultRecord miss = FakeVaultPort.login("Bank", LOGIN_SECRET, NOW)) {
            port.stored.addAll(List.of(hit, miss));
            FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

            assertEquals(ExitCodes.OK, run(io, port, "search", "git"));
            assertTrue(io.outText().contains(hit.id().toString()));
            assertFalse(io.outText().contains(miss.id().toString()));
        }
        assertTrue(port.session().isLocked());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "a\u0007b"})
    void searchRejectsBlankOrControlQuery(String query) {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

        assertEquals(ExitCodes.USAGE, run(io, port, "search", query));
        assertTrue(opened.isEmpty(), "vault not opened on bad input");
    }

    // ---- tui ---------------------------------------------------------------------------------

    @Test
    void tuiLaunchesOverOpenedPort() {
        FakeVaultPort port = new FakeVaultPort();
        FakeConsoleIo io = new FakeConsoleIo();

        assertEquals(ExitCodes.OK, run(io, port, "tui"));
        assertEquals(1, launched.size());
        assertSame(port, launched.get(0));
        assertEquals(0, io.secretsRead(), "the TUI does its own unlock");
    }

    @Test
    void tuiTerminalFailureIsExitFour() {
        launcher = p -> {
            throw new IOException("tty gone");
        };
        FakeConsoleIo io = new FakeConsoleIo();

        assertEquals(ExitCodes.STORAGE, run(io, new FakeVaultPort(), "tui"));
        assertEquals(Messages.ERR_TERMINAL.text(), io.errText().strip());
    }

    // ---- argument shape ----------------------------------------------------------------------

    static Stream<List<String>> wrongOperandCounts() {
        return Stream.of(List.of("init", "extra"), List.of("add-login", "extra"), List.of("list", "extra"),
                List.of("tui", "extra"), List.of("search"), List.of("search", "a", "b"));
    }

    @ParameterizedTest
    @MethodSource("wrongOperandCounts")
    void wrongOperandCountIsUsage(List<String> args) {
        FakeConsoleIo io = new FakeConsoleIo();

        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort(), args.toArray(String[]::new)));
        assertTrue(io.errText().contains(Messages.WRONG_ARG_COUNT.text()));
        assertTrue(opened.isEmpty());
    }

    @Test
    void unknownCommandIsUsage() {
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort(), "explode"));
        assertTrue(io.errText().contains(Messages.UNKNOWN_COMMAND.text()));
        assertTrue(opened.isEmpty());
    }

    // ---- bare pm: the whole app ----------------------------------------------------------------

    @Test
    void bareCommandWithAVaultOpensTheTuiWithoutTuningOrPrompting() {
        vaultOnDisk = true;
        FakeVaultPort port = new FakeVaultPort();
        FakeConsoleIo io = new FakeConsoleIo();

        assertEquals(ExitCodes.OK, run(io, port));

        assertEquals(List.of(port), launched);
        assertEquals(List.of(false), creating, "unlock reads Argon2 parameters from the header");
        assertEquals(List.of(Path.of(HOME, ".local", "share", "pm", "vault.pmv")), opened);
        assertEquals(0, io.secretsRead(), "the TUI does its own unlock");
        assertEquals("", io.outText());
    }

    @Test
    void bareCommandWithoutAVaultCreatesOneShowsTheKeyThenOpensTheTui() {
        FakeVaultPort port = new FakeVaultPort();
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY).secret(CANARY).line("");

        assertEquals(ExitCodes.OK, run(io, port, "--vault", "/tmp/new.pmv"));

        assertTrue(port.exists());
        assertEquals(List.of(true), creating, "a new vault is tuned to this machine");
        assertEquals(1, count(io.outText(), FakeVaultPort.RECOVERY_KEY));
        assertTrue(io.outText().indexOf(FakeVaultPort.RECOVERY_KEY) > io.outText().indexOf(Messages.FIRST_RUN.text()));
        assertTrue(port.recoveryKey().isClosed(), "recovery key closed before the TUI opens");
        assertTrue(port.session().isLocked(), "the TUI unlocks on its own");
        assertEquals(List.of(port), launched);
        assertTrue(io.allSecretsZeroed());
        assertFalse(io.outText().contains(CANARY));
    }

    @Test
    void bareCommandFirstRunWithMismatchedPassphrasesNeverOpensTheTui() {
        FakeVaultPort port = new FakeVaultPort();
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY).secret(CANARY + "x");

        assertEquals(ExitCodes.USAGE, run(io, port));

        assertFalse(port.exists());
        assertTrue(launched.isEmpty());
        assertTrue(io.errText().contains(Messages.PASSPHRASE_MISMATCH.text()));
    }

    @Test
    void bareCommandFirstRunWithInputClosedAtTheKeyPromptKeepsTheVaultButSkipsTheTui() {
        FakeVaultPort port = new FakeVaultPort();
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY).secret(CANARY);

        assertEquals(ExitCodes.USAGE, run(io, port));

        assertTrue(port.exists(), "the vault and its shown key stand");
        assertTrue(launched.isEmpty());
        assertTrue(io.errText().contains(Messages.INPUT_CLOSED.text()));
    }

    @Test
    void bareCommandWithABadVaultPathIsUsageAndTouchesNothing() {
        FakeConsoleIo io = new FakeConsoleIo();

        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort(), "--vault", "~/v.pmv"));

        assertTrue(opened.isEmpty());
        assertTrue(launched.isEmpty());
        assertTrue(io.errText().contains(Messages.VAULT_PATH_TILDE.text()));
    }

    @Test
    void unknownOptionIsUsage() {
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort(), "--verbose", "list"));
        assertTrue(io.errText().contains(Messages.UNKNOWN_OPTION.text()));
    }

    @Test
    void helpPrintsUsageAndSucceeds() {
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, new FakeVaultPort(), "--help"));
        assertTrue(io.outText().contains(Command.usage()));
        assertTrue(opened.isEmpty());
    }

    // ---- --vault -----------------------------------------------------------------------------

    @Test
    void vaultOptionBeforeOrAfterCommandIsNormalised() {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);
        Path expected = Path.of("/data/vaults/main.pmv").toAbsolutePath().normalize();

        assertEquals(ExitCodes.OK, run(new FakeConsoleIo().secret(CANARY), port,
                "--vault", "/data/vaults/../vaults/./main.pmv", "list"));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo().secret(CANARY), port,
                "list", "--vault", "/data/vaults/main.pmv"));

        assertEquals(List.of(expected, expected), opened);
    }

    @Test
    void relativeVaultPathBecomesAbsolute() {
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo().secret(CANARY),
                new FakeVaultPort().withVault(CANARY), "--vault", "v.pmv", "list"));
        assertTrue(opened.get(0).isAbsolute());
    }

    @Test
    void vaultOptionWithoutValueIsUsage() {
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort(), "list", "--vault"));
        assertTrue(io.errText().contains(Messages.MISSING_VAULT_PATH.text()));
    }

    @Test
    void duplicateVaultOptionIsUsage() {
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort(), "--vault", "a.pmv", "--vault", "b.pmv", "list"));
        assertTrue(io.errText().contains(Messages.DUPLICATE_VAULT_OPTION.text()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    void emptyVaultPathIsUsage(String value) {
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort(), "--vault", value, "list"));
        assertTrue(io.errText().contains(Messages.EMPTY_VAULT_PATH.text()));
        assertTrue(opened.isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"vault\u0000.pmv", "va\nult.pmv", "va\u202Eult.pmv"})
    void invalidVaultPathIsUsage(String value) {
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort(), "--vault", value, "list"));
        assertTrue(io.errText().contains(Messages.INVALID_VAULT_PATH.text()));
        assertTrue(opened.isEmpty());
    }

    // ---- default path ------------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({
        "Mac OS X, Library/Application Support/pm/vault.pmv",
        "Darwin, Library/Application Support/pm/vault.pmv",
        "Windows 11, AppData/Roaming/pm/vault.pmv",
        "Linux, .local/share/pm/vault.pmv",
        "FreeBSD, .local/share/pm/vault.pmv"
    })
    void defaultPathPerOs(String osName, String relative) {
        props.put(VaultPaths.OS_NAME, osName);
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY);

        assertEquals(ExitCodes.OK, run(new FakeConsoleIo().secret(CANARY), port, "list"));

        Path expected = Path.of(HOME).resolve(relative).toAbsolutePath().normalize();
        assertEquals(List.of(expected), opened);
    }

    @Test
    void missingOsNameFallsBackToXdg() throws UsageException {
        Map<String, String> onlyHome = Map.of(VaultPaths.USER_HOME, HOME);
        assertEquals(Path.of(HOME, ".local", "share", "pm", "vault.pmv").toAbsolutePath().normalize(),
                VaultPaths.defaultPath(onlyHome::get));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "  "})
    void blankHomeIsUsage(String home) {
        props.put(VaultPaths.USER_HOME, home);
        FakeConsoleIo io = new FakeConsoleIo();

        assertEquals(ExitCodes.USAGE, run(io, new FakeVaultPort(), "list"));
        assertTrue(io.errText().contains(Messages.NO_HOME_DIR.text()));
    }

    @Test
    void missingHomeIsUsage() {
        UsageException e = assertThrows(UsageException.class,
                () -> VaultPaths.defaultPath(Map.of(VaultPaths.OS_NAME, "Linux")::get));
        assertEquals(Messages.NO_HOME_DIR, e.reason());
    }

    // ---- exit-code mapping -------------------------------------------------------------------

    private static final Map<VaultException.Code, Integer> EXPECTED_EXIT = expectedExit();

    private static Map<VaultException.Code, Integer> expectedExit() {
        Map<VaultException.Code, Integer> m = new EnumMap<>(VaultException.Code.class);
        m.put(VaultException.Code.WRONG_CREDENTIAL, 1);
        m.put(VaultException.Code.CORRUPT, 3);
        m.put(VaultException.Code.UNSUPPORTED_VERSION, 3);
        m.put(VaultException.Code.ALREADY_EXISTS, 2);
        m.put(VaultException.Code.LOCKED, 4);
        m.put(VaultException.Code.STORAGE, 4);
        m.put(VaultException.Code.INSUFFICIENT_MEMORY, 7);
        m.put(VaultException.Code.CONFLICT, 4);
        m.put(VaultException.Code.PASSPHRASE_CHANGED_UNCONFIRMED, 4);
        m.put(VaultException.Code.PASSPHRASE_CHANGE_UNKNOWN, 4);
        return m;
    }

    @ParameterizedTest
    @EnumSource(VaultException.Code.class)
    void everyVaultCodeMapsToDocumentedExitAndCatalogueMessage(VaultException.Code code) {
        FakeVaultPort port = new FakeVaultPort().withVault(CANARY).failing(code);
        FakeConsoleIo io = new FakeConsoleIo().secret(CANARY);

        int exit = run(io, port, "list");

        assertEquals(EXPECTED_EXIT.get(code).intValue(), exit);
        assertEquals(EXPECTED_EXIT.get(code).intValue(), ExitCodes.of(code));
        assertEquals(ExitCodes.messageFor(new VaultException(code, null)).text(), io.errText().strip());
        assertFalse(io.errText().contains(code.name()), "never the exception message");
        assertTrue(io.allSecretsZeroed());
    }

    @Test
    void storageNotFoundGetsItsOwnMessage() {
        VaultException e = new VaultException(VaultException.Code.STORAGE,
                new StorageException(StorageException.Code.NOT_FOUND, null));
        assertEquals(Messages.ERR_NOT_FOUND, ExitCodes.messageFor(e));
        assertEquals(Messages.ERR_STORAGE, ExitCodes.messageFor(new VaultException(VaultException.Code.STORAGE,
                new StorageException(StorageException.Code.IO, null))));
    }

    @ParameterizedTest
    @EnumSource(StorageException.Code.class)
    void storageCodesMapToVaultCodes(StorageException.Code code) {
        VaultException.Code expected = code == StorageException.Code.LOCKED_BY_OTHER
                ? VaultException.Code.LOCKED
                : VaultException.Code.STORAGE;
        assertEquals(expected, FileVaultPort.vaultCode(code));
    }
}
