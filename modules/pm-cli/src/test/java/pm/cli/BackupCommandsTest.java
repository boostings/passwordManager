package pm.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.Argon2Params;
import pm.vault.VaultBackups;

/**
 * M7.7 backup commands over the real file stack (SR-134): {@code backup create} writes and
 * rotates through {@link VaultBackups}, {@code backup verify} writes nothing, and {@code restore}
 * verifies first and replaces a vault only with {@code --overwrite}, keeping it as
 * {@code .bak.1}. A missing vault is reported without leaving a lock file behind.
 */
class BackupCommandsTest {
    private static final String VAULT_PASSPHRASE = "backup-test-phrase-4e";
    private static final String LOGIN_SECRET = "backup-login-secret-08";
    private static final Instant NOW = Instant.parse("2026-10-06T09:00:00Z");

    @TempDir
    Path tmp;

    private Path vault;
    private Path backups;

    @BeforeEach
    void vaultWithOneLogin() {
        vault = tmp.resolve("v").resolve("vault.pmv");
        backups = tmp.resolve("backups");
        FakeConsoleIo init = new FakeConsoleIo().secret(VAULT_PASSPHRASE).secret(VAULT_PASSPHRASE);
        assertEquals(ExitCodes.OK, run(vault, init, "init"), init::errText);
        addLogin("GitHub");
    }

    private void addLogin(String title) {
        FakeConsoleIo add = unlocking().line(title).line("octocat").secret(LOGIN_SECRET).line("").line("");
        assertEquals(ExitCodes.OK, run(vault, add, "add-login"), add::errText);
    }

    private static FakeConsoleIo unlocking() {
        return new FakeConsoleIo().secret(VAULT_PASSPHRASE);
    }

    private static int run(Path vaultPath, FakeConsoleIo io, String... command) {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        Cli cli = new Cli(Map.<String, String>of()::get, clock, port -> fail("never launches the TUI"));
        List<String> args = new ArrayList<>(List.of("--vault", vaultPath.toString()));
        args.addAll(List.of(command));
        return cli.run(args.toArray(String[]::new), io,
                (path, creating) -> new FileVaultPort(path, clock, Cli.kdfFor(creating, () -> Argon2Params.FLOOR)));
    }

    private Path create(String... extra) {
        List<String> args = new ArrayList<>(List.of("backup", "create", backups.toString()));
        args.addAll(List.of(extra));
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(vault, io, args.toArray(String[]::new)), io::errText);
        // The passphrase prompt is on the same line: FakeConsoleIo echoes no line break.
        String line = io.outText().lines().filter(l -> l.contains(Messages.BACKUP_WRITTEN.text())).findFirst()
                .orElseThrow();
        return Path.of(line.substring(line.indexOf(Messages.BACKUP_WRITTEN.text())
                + Messages.BACKUP_WRITTEN.text().length()));
    }

    private List<String> titles(Path at) {
        FakeConsoleIo list = unlocking();
        assertEquals(ExitCodes.OK, run(at, list, "list"), list::errText);
        return list.outText().lines().skip(1).map(l -> l.split("  ", -1)[2]).toList();
    }

    /** Every file under {@code root} with its size and modification time. */
    private static Map<Path, String> snapshot(Path root) throws IOException {
        Map<Path, String> files = new TreeMap<>();
        try (Stream<Path> walk = Files.walk(root)) {
            for (Path p : walk.filter(Files::isRegularFile).toList()) {
                FileTime modified = Files.getLastModifiedTime(p);
                files.put(p, Files.size(p) + "@" + modified.toMillis());
            }
        }
        return files;
    }

    @Test
    void createWritesAnOwnerOnlyBackupThatVerifiesWithoutWritingAnything() throws IOException {
        Path file = create();
        assertEquals(backups.toRealPath(), file.getParent().toRealPath());
        assertTrue(file.getFileName().toString().startsWith(VaultBackups.PREFIX), file::toString);
        assertTrue(file.getFileName().toString().endsWith(VaultBackups.EXTENSION), file::toString);
        assertFalse(new String(Files.readAllBytes(file), java.nio.charset.StandardCharsets.ISO_8859_1)
                .contains(LOGIN_SECRET), "encrypted at rest");

        Map<Path, String> before = snapshot(tmp);
        FakeConsoleIo verify = new FakeConsoleIo().secret(VAULT_PASSPHRASE);
        assertEquals(ExitCodes.OK, run(vault, verify, "backup", "verify", file.toString()), verify::errText);
        assertTrue(verify.outText().contains(Messages.BACKUP_VERIFIED.text()), verify::outText);
        assertTrue(verify.outText().contains(Messages.BACKUP_MADE.text() + NOW), verify::outText);
        assertTrue(verify.outText().contains(Messages.BACKUP_RECORDS.text()), verify::outText);
        assertEquals(before, snapshot(tmp), "verify wrote nothing");
        assertFalse(verify.outText().contains(LOGIN_SECRET) || verify.outText().contains(VAULT_PASSPHRASE));
        assertTrue(verify.allSecretsZeroed());

        FakeConsoleIo wrong = new FakeConsoleIo().secret("not-the-passphrase");
        assertEquals(ExitCodes.WRONG_CREDENTIAL, run(vault, wrong, "backup", "verify", file.toString()));
    }

    @Test
    void aDamagedBackupIsNamedAsTheBackupAndNeverRestored() throws IOException {
        Path file = create();
        byte[] bytes = Files.readAllBytes(file);
        bytes[bytes.length - 1] ^= 0x01;
        Path damaged = Files.write(tmp.resolve("damaged.pmbackup"), bytes);
        byte[] vaultBefore = Files.readAllBytes(vault);

        FakeConsoleIo verify = new FakeConsoleIo().secret(VAULT_PASSPHRASE);
        assertEquals(ExitCodes.CORRUPT, run(vault, verify, "backup", "verify", damaged.toString()));
        assertTrue(verify.errText().contains(Messages.BACKUP_CORRUPT.text()), verify::errText);
        FakeConsoleIo restore = new FakeConsoleIo().secret(VAULT_PASSPHRASE);
        assertEquals(ExitCodes.CORRUPT, run(vault, restore, "restore", damaged.toString(), "--overwrite"));
        assertTrue(restore.errText().contains(Messages.BACKUP_CORRUPT.text()), restore::errText);
        assertArrayEquals(vaultBefore, Files.readAllBytes(vault), "the vault is untouched");
    }

    @Test
    void restoreNeedsOverwriteToReplaceAVaultAndKeepsTheOldOneAsBak1() throws IOException {
        Path file = create();
        addLogin("Saved after the backup");
        byte[] newer = Files.readAllBytes(vault);

        FakeConsoleIo refused = new FakeConsoleIo(); // refused before any passphrase is asked for
        assertEquals(ExitCodes.USAGE, run(vault, refused, "restore", file.toString()));
        assertTrue(refused.errText().contains(Messages.RESTORE_EXISTS.text()), refused::errText);
        assertFalse(refused.outText().contains(Messages.PROMPT_BACKUP_PASSPHRASE.text()), refused::outText);
        assertArrayEquals(newer, Files.readAllBytes(vault));

        FakeConsoleIo restore = new FakeConsoleIo().secret(VAULT_PASSPHRASE);
        assertEquals(ExitCodes.OK, run(vault, restore, "restore", file.toString(), "--overwrite"), restore::errText);
        assertTrue(restore.outText().contains(Messages.RESTORED.text() + vault), restore::outText);
        assertTrue(restore.outText().contains(Messages.RESTORE_KEPT.text() + vault + ".bak.1"), restore::outText);
        assertTrue(restore.outText().contains(Messages.RESTORE_OPENS_WITH.text()), "m77-007: says which passphrase");
        assertTrue(restore.errText().contains(Messages.RESTORE_ROLLBACK.text()), "the restore went back in time");
        assertArrayEquals(newer, Files.readAllBytes(Path.of(vault + ".bak.1")));
        assertEquals(List.of("GitHub"), titles(vault));
    }

    @Test
    void aMissingBackupIsNamedAsTheBackupBeforeAnyPrompt() {
        // m77-003: it used to say "no vault at this path; run 'pm init' first", after the prompt.
        Path nowhere = tmp.resolve("typo.pmbackup");
        for (String[] command : List.of(new String[] {"backup", "verify", nowhere.toString()},
                new String[] {"restore", nowhere.toString()}, new String[] {"restore", nowhere.toString(), "--overwrite"})) {
            FakeConsoleIo io = unlocking();
            assertEquals(ExitCodes.STORAGE, run(vault, io, command), io::errText);
            assertTrue(io.errText().contains(Messages.BACKUP_NOT_FOUND.text() + nowhere), io::errText);
            assertFalse(io.errText().contains(Messages.ERR_NOT_FOUND.text()), io::errText);
            assertEquals(0, io.secretsRead(), "refused before the passphrase is asked for");
        }
        assertEquals(List.of("GitHub"), titles(vault));
    }

    @Test
    void restoreOverAVaultInUseSaysItIsInUse() throws IOException, pm.storage.StorageException {
        Path file = create();
        byte[] before = Files.readAllBytes(vault);
        try (pm.storage.VaultFileStore held = pm.storage.VaultFileStore.open(vault)) {
            FakeConsoleIo io = new FakeConsoleIo().secret(VAULT_PASSPHRASE);
            assertEquals(ExitCodes.STORAGE, run(vault, io, "restore", file.toString(), "--overwrite"));
            assertTrue(io.errText().contains(Messages.ERR_LOCKED.text()), io::errText);
            assertFalse(io.outText().contains(Messages.RESTORED.text()), io::outText);
            assertTrue(held.exists(), "the holder still has the vault");
        }
        assertArrayEquals(before, Files.readAllBytes(vault));
    }

    @Test
    void restoreToAPathWithNoVaultInstallsTheBackup() {
        Path file = create();
        Path fresh = tmp.resolve("new").resolve("vault.pmv");
        FakeConsoleIo restore = new FakeConsoleIo().secret(VAULT_PASSPHRASE);
        assertEquals(ExitCodes.OK, run(fresh, restore, "restore", file.toString()), restore::errText);
        assertFalse(restore.outText().contains(Messages.RESTORE_KEPT.text()), restore::outText);
        assertTrue(restore.outText().contains(Messages.RESTORE_OPENS_WITH.text()), restore::outText);
        assertEquals(List.of("GitHub"), titles(fresh));
    }

    @Test
    void keepRotatesOldBackupsAndIsBounded() throws IOException {
        create("--keep", "2");
        create("--keep", "2");
        FakeConsoleIo third = unlocking();
        assertEquals(ExitCodes.OK, run(vault, third, "backup", "create", backups.toString(), "--keep", "2"),
                third::errText);
        assertTrue(third.outText().contains(Messages.BACKUP_DELETED.text()), third::outText);
        try (Stream<Path> files = Files.list(backups)) {
            assertEquals(2, files.count());
        }
        for (String keep : List.of("0", "1000", "ten", "-1")) {
            FakeConsoleIo bad = unlocking();
            assertEquals(ExitCodes.USAGE, run(vault, bad, "backup", "create", backups.toString(), "--keep", keep));
            assertTrue(bad.errText().contains(Messages.BAD_KEEP.text()) || bad.errText().contains(
                    Messages.UNKNOWN_OPTION.text()), keep + ": " + bad.errText());
            assertEquals(0, bad.secretsRead(), "refused before the passphrase is asked for");
        }
    }

    @Test
    void aMissingVaultIsReportedAndLeavesNoLockFileOrFolderBehind() {
        Path missing = tmp.resolve("nowhere").resolve("vault.pmv");
        for (String[] command : List.of(new String[] {"list"}, new String[] {"show", "x"},
                new String[] {"backup", "create", backups.toString()})) {
            FakeConsoleIo io = unlocking();
            assertEquals(ExitCodes.STORAGE, run(missing, io, command), io::errText);
            assertTrue(io.errText().contains(Messages.ERR_NOT_FOUND.text()), io::errText);
            assertFalse(Files.exists(Path.of(missing + ".lock")), "no lock file at a path with no vault");
            assertFalse(Files.exists(missing.getParent()), "no folder either");
        }
        assertFalse(Files.exists(backups), "no backup folder for a vault that is not there");
        Path noFolder = tmp.resolve("v").resolve("other.pmv");
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.STORAGE, run(noFolder, io, "list"));
        assertFalse(Files.exists(Path.of(noFolder + ".lock")), "nor next to an existing vault folder");
    }
}
