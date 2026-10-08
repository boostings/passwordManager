package pm.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.approval.AuditException;
import pm.approval.AuditLog;
import pm.crypto.Argon2Params;

/**
 * M7.7 {@code pm passphrase} and {@code pm recover} over the real file stack (SR-134, SR-130,
 * SR-131): the current passphrase or the recovery key unlocks first and a wrong one changes
 * nothing; the new passphrase is typed twice; the recovery key keeps working; the change is
 * audited; earlier backups keep the old passphrase and the user is told so; no secret is printed
 * and every typed buffer is zeroed.
 */
class PassphraseCommandsTest {
    private static final String OLD = "old-phrase-c3d1";
    private static final String NEW = "new-phrase-77ab";
    private static final String LOGIN_SECRET = "passphrase-test-login-9e";
    private static final Instant NOW = Instant.parse("2026-10-06T09:00:00Z");

    @TempDir
    Path tmp;

    private Path vault;
    private String recoveryKey;

    @BeforeEach
    void vaultWithOneLogin() {
        vault = tmp.resolve("v").resolve("vault.pmv");
        FakeConsoleIo init = new FakeConsoleIo().secret(OLD).secret(OLD);
        assertEquals(ExitCodes.OK, run(init, "init"), init::errText);
        List<String> lines = init.outText().lines().toList();
        int notice = lines.indexOf(Messages.RECOVERY_KEY_NOTICE.text());
        assertTrue(notice >= 0, init::outText);
        recoveryKey = lines.get(notice + 1);
        FakeConsoleIo add = new FakeConsoleIo().secret(OLD).line("GitHub").line("octocat").secret(LOGIN_SECRET)
                .line("").line("");
        assertEquals(ExitCodes.OK, run(add, "add-login"), add::errText);
    }

    private int run(FakeConsoleIo io, String... command) {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        Map<String, String> properties = Map.of("user.name", "alice");
        Cli cli = new Cli(properties::get, clock, port -> fail("never launches the TUI"));
        List<String> args = new ArrayList<>(List.of("--vault", vault.toString()));
        args.addAll(List.of(command));
        return cli.run(args.toArray(String[]::new), io,
                (path, creating) -> new FileVaultPort(path, clock, Cli.kdfFor(creating, () -> Argon2Params.FLOOR)));
    }

    private boolean opensWith(String passphrase) {
        FakeConsoleIo list = new FakeConsoleIo().secret(passphrase);
        int code = run(list, "list");
        assertTrue(code == ExitCodes.OK || code == ExitCodes.WRONG_CREDENTIAL, list::errText);
        return code == ExitCodes.OK && list.outText().contains("GitHub");
    }

    private Path auditLog() {
        return vault.resolveSibling(AuditLog.FILE_NAME);
    }

    private long auditEntries() throws AuditException {
        return Files.exists(auditLog()) ? AuditLog.check(auditLog()) : 0;
    }

    /** The last entry's CBOR bytes as Latin-1 text, to look for the names in it. */
    private String lastAuditEntry() throws IOException {
        List<String> lines = Files.readAllLines(auditLog(), StandardCharsets.US_ASCII);
        return new String(Base64.getDecoder().decode(lines.get(lines.size() - 1)), StandardCharsets.ISO_8859_1);
    }

    private static void noSecretPrinted(FakeConsoleIo io, String... secrets) {
        for (String s : secrets) {
            assertFalse(io.outText().contains(s) || io.errText().contains(s), "printed: " + s);
        }
        assertTrue(io.allSecretsZeroed(), "every typed buffer is zeroed");
    }

    @Test
    void theCurrentPassphraseThenTheNewOneTwiceChangesItAndKeepsEverythingElse() throws IOException, AuditException {
        long before = auditEntries();
        FakeConsoleIo io = new FakeConsoleIo().secret(OLD).secret(NEW).secret(NEW);
        assertEquals(ExitCodes.OK, run(io, "passphrase"), io::errText);
        assertTrue(io.outText().contains(Messages.PROMPT_CURRENT_PASSPHRASE.text()), io::outText);
        assertTrue(io.outText().contains(Messages.CHANGE_DONE.text()), io::outText);
        assertTrue(io.outText().contains(Messages.CHANGE_OLD_BACKUPS.text()), "told about older backups");
        noSecretPrinted(io, OLD, NEW, LOGIN_SECRET, recoveryKey);
        assertEquals(3, io.secretsRead());

        assertTrue(opensWith(NEW));
        assertFalse(opensWith(OLD), "the old passphrase no longer opens the vault");
        assertTrue(Files.exists(Path.of(vault + ".bak.1")), "saved with .bak rotation");

        assertEquals(before + 1, auditEntries(), "one audit entry for the change");
        String entry = lastAuditEntry();
        assertTrue(entry.contains(PassphraseCommands.AUDIT_KIND) && entry.contains(PassphraseCommands.CHANGED)
                && entry.contains("pm passphrase"), entry);
        assertFalse(entry.contains(PassphraseCommands.CHANGED_WITH_RECOVERY_KEY), entry);
        assertFalse(entry.contains(OLD) || entry.contains(NEW), "the audit entry holds no secret");
    }

    @Test
    void aWrongCurrentPassphraseAsksForNoNewOneAndChangesNothing() throws IOException, AuditException {
        byte[] bytes = Files.readAllBytes(vault);
        long before = auditEntries();
        FakeConsoleIo io = new FakeConsoleIo().secret("not-the-phrase").secret(NEW).secret(NEW);
        assertEquals(ExitCodes.WRONG_CREDENTIAL, run(io, "passphrase"));
        assertEquals(1, io.secretsRead(), "no new passphrase is asked for");
        assertArrayEquals(bytes, Files.readAllBytes(vault));
        assertEquals(before, auditEntries());
        assertTrue(opensWith(OLD));
    }

    @Test
    void aMismatchOrAnEmptyNewPassphraseChangesNothing() throws IOException {
        byte[] bytes = Files.readAllBytes(vault);
        FakeConsoleIo mismatch = new FakeConsoleIo().secret(OLD).secret(NEW).secret(NEW + "x");
        assertEquals(ExitCodes.USAGE, run(mismatch, "passphrase"));
        assertTrue(mismatch.errText().contains(Messages.CHANGE_MISMATCH.text()), mismatch::errText);
        noSecretPrinted(mismatch, OLD, NEW);

        FakeConsoleIo empty = new FakeConsoleIo().secret(OLD).secret("");
        assertEquals(ExitCodes.USAGE, run(empty, "passphrase"));
        assertTrue(empty.errText().contains(Messages.EMPTY_PASSPHRASE.text()), empty::errText);
        assertTrue(empty.allSecretsZeroed());

        FakeConsoleIo closed = new FakeConsoleIo().secret(OLD).secret(NEW);
        assertEquals(ExitCodes.USAGE, run(closed, "passphrase"), "input ends before the repeat");
        assertTrue(closed.allSecretsZeroed(), "the first new passphrase is zeroed too");

        assertArrayEquals(bytes, Files.readAllBytes(vault));
        assertTrue(opensWith(OLD));
    }

    @Test
    void theRecoveryKeySetsANewPassphraseAndStaysValid() throws IOException {
        FakeConsoleIo recovery = new FakeConsoleIo().secret(recoveryKey).secret(NEW).secret(NEW);
        assertEquals(ExitCodes.OK, run(recovery, "passphrase", "--recovery"), recovery::errText);
        assertTrue(recovery.outText().contains(Messages.PROMPT_RECOVERY_KEY.text()), recovery::outText);
        noSecretPrinted(recovery, NEW, recoveryKey);
        assertTrue(opensWith(NEW));

        String third = "third-phrase-0f";
        FakeConsoleIo recover = new FakeConsoleIo().secret(recoveryKey).secret(third).secret(third);
        assertEquals(ExitCodes.OK, run(recover, "recover"), recover::errText);
        assertTrue(recover.outText().contains(Messages.CHANGE_DONE.text()), recover::outText);
        noSecretPrinted(recover, third, recoveryKey);
        assertTrue(opensWith(third), "the same recovery key worked twice: the recovery slot is unchanged");
        String entry = lastAuditEntry();
        assertTrue(entry.contains(PassphraseCommands.CHANGED_WITH_RECOVERY_KEY) && entry.contains("pm recover"), entry);
        assertFalse(opensWith(NEW));
    }

    @Test
    void aWrongRecoveryKeyChangesNothing() throws IOException {
        byte[] bytes = Files.readAllBytes(vault);
        FakeConsoleIo io = new FakeConsoleIo().secret("AAAA-BBBB-CCCC").secret(NEW).secret(NEW);
        assertEquals(ExitCodes.WRONG_CREDENTIAL, run(io, "recover"));
        assertEquals(1, io.secretsRead());
        assertArrayEquals(bytes, Files.readAllBytes(vault));
    }

    @Test
    void anEarlierBackupStillOpensWithTheOldPassphrase() throws IOException {
        Path backups = tmp.resolve("backups");
        FakeConsoleIo create = new FakeConsoleIo().secret(OLD);
        assertEquals(ExitCodes.OK, run(create, "backup", "create", backups.toString()), create::errText);
        FakeConsoleIo change = new FakeConsoleIo().secret(OLD).secret(NEW).secret(NEW);
        assertEquals(ExitCodes.OK, run(change, "passphrase"), change::errText);

        Path backup;
        try (Stream<Path> files = Files.list(backups)) {
            backup = files.findFirst().orElseThrow();
        }
        FakeConsoleIo old = new FakeConsoleIo().secret(OLD);
        assertEquals(ExitCodes.OK, run(old, "backup", "verify", backup.toString()), old::errText);
        FakeConsoleIo fresh = new FakeConsoleIo().secret(NEW);
        assertEquals(ExitCodes.WRONG_CREDENTIAL, run(fresh, "backup", "verify", backup.toString()));
    }

    @Test
    void anAuditFailureAfterTheChangeSaysThePassphraseWasChanged() throws IOException {
        Files.createDirectory(auditLog());
        FakeConsoleIo io = new FakeConsoleIo().secret(OLD).secret(NEW).secret(NEW);
        assertEquals(ExitCodes.NOT_AUDITED, run(io, "passphrase"));
        assertTrue(io.errText().contains(Messages.CHANGE_AUDIT_FAILED.text()), io::errText);
        assertFalse(io.errText().contains(Messages.AUDIT_UNAVAILABLE.text()), "not 'nothing was exported'");
        assertTrue(opensWith(NEW), "the message is true: it was changed");
    }

    @Test
    void operandsAreRefusedBeforeAnyPromptAndAMissingVaultLeavesNothing() {
        for (String[] command : List.of(new String[] {"passphrase", "extra"}, new String[] {"recover", "x"},
                new String[] {"recover", "--recovery"})) {
            FakeConsoleIo io = new FakeConsoleIo().secret(OLD);
            assertEquals(ExitCodes.USAGE, run(io, command), String.join(" ", command));
            assertEquals(0, io.secretsRead());
        }
        vault = tmp.resolve("nowhere").resolve("vault.pmv");
        FakeConsoleIo io = new FakeConsoleIo().secret(OLD).secret(NEW).secret(NEW);
        assertEquals(ExitCodes.STORAGE, run(io, "passphrase"));
        assertEquals(0, io.secretsRead(), "the missing vault is found before any prompt");
        assertFalse(Files.exists(vault.getParent()), "no folder or lock file");
    }
}
