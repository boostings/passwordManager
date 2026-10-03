package pm.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** SR-040/041: backups retain encrypted prior versions and owner-only permissions. */
final class BackupRotationTest {
    @TempDir Path root;

    @Test
    void fiveSavesKeepThreePreviousVersions() throws IOException, StorageException {
        Path file = root.resolve("private/vault.pmv");
        try (VaultFileStore store = VaultFileStore.open(file)) {
            store.backup();
            assertFalse(store.exists());
            for (byte version = 1; version <= 5; version++) {
                store.backup();
                store.writeAtomically(new byte[] {version});
            }
            assertArrayEquals(new byte[] {5}, store.readAll());
            for (int index = 1; index <= 3; index++) {
                Path backup = file.resolveSibling("vault.pmv.bak." + index);
                assertArrayEquals(new byte[] {(byte) (5 - index)}, Files.readAllBytes(backup));
                assertTrue(OwnerOnly.isOwnerOnly(backup));
            }
            assertFalse(Files.exists(file.resolveSibling("vault.pmv.bak.4")));
            assertTrue(OwnerOnly.isOwnerOnly(file));
            assertTrue(OwnerOnly.isOwnerOnly(file.getParent()));
            assertTrue(OwnerOnly.isOwnerOnly(file.resolveSibling("vault.pmv.lock")));
        }
    }

    // A save that fails after its backup is retried with the same vault on disk. The retries
    // must not push the older generations out with copies of the unchanged vault.
    @Test
    void repeatedBackupOfAnUnchangedVaultKeepsOlderGenerations()
            throws IOException, StorageException {
        Path file = root.resolve("private/vault.pmv");
        try (VaultFileStore store = VaultFileStore.open(file)) {
            saveVersions(store, 4);
            store.backup();
            store.backup();
            store.backup();
            assertArrayEquals(new byte[] {4}, store.readAll());
            assertGenerations(file, 4, 3, 2);
            store.writeAtomically(new byte[] {5});
            store.backup();
            assertGenerations(file, 5, 4, 3);
        }
    }

    // The new backup is staged before the older generations move, so a write that fails (a full
    // disk) leaves every generation where it was.
    @Test
    void failedBackupWriteKeepsEveryGeneration() throws IOException, StorageException {
        Path file = root.resolve("private/vault.pmv");
        AtomicBoolean failing = new AtomicBoolean();
        try (VaultFileStore store = VaultFileStore.open(file, 32, step -> {
            if (failing.get() && step == VaultFileStore.Step.TMP_WRITTEN) {
                throw new IOException("SIMULATED_FULL_DISK");
            }
        })) {
            saveVersions(store, 4);
            failing.set(true);
            for (int attempt = 0; attempt < 3; attempt++) {
                StorageException error = assertThrows(StorageException.class, store::backup);
                assertEquals(StorageException.Code.IO, error.code());
                assertGenerations(file, 3, 2, 1);
            }
            assertFalse(Files.exists(file.resolveSibling("vault.pmv.bak.1.tmp")));
            failing.set(false);
            store.backup();
            assertGenerations(file, 4, 3, 2);
            assertArrayEquals(new byte[] {4}, store.readAll());
        }
    }

    // ADR 0003 write rule 1: a stale regular staging file is deleted, however it is protected.
    @Test
    void removesAStaleTemporaryFileThatIsNotOwnerOnly() throws IOException, StorageException {
        Path file = root.resolve("private/vault.pmv");
        try (VaultFileStore store = VaultFileStore.open(file)) {
            Path tmp = Files.createFile(file.resolveSibling("vault.pmv.tmp"));
            Path written = Files.write(tmp, new byte[] {99});
            assumeFalse(OwnerOnly.isOwnerOnly(written), "platform default is already owner-only");
            store.writeAtomically(new byte[] {1, 2});
            assertArrayEquals(new byte[] {1, 2}, store.readAll());
            assertFalse(Files.exists(tmp));
        }
    }

    private static void saveVersions(VaultFileStore store, int count) throws StorageException {
        for (byte version = 1; version <= count; version++) {
            store.backup();
            store.writeAtomically(new byte[] {version});
        }
    }

    private static void assertGenerations(Path file, int... expected) throws IOException {
        for (int index = 1; index <= expected.length; index++) {
            assertArrayEquals(new byte[] {(byte) expected[index - 1]},
                    Files.readAllBytes(file.resolveSibling("vault.pmv.bak." + index)));
        }
    }

    @Test
    void removesAnOwnerOnlyStaleTemporaryFile() throws IOException, StorageException {
        Path file = root.resolve("private/vault.pmv");
        try (VaultFileStore store = VaultFileStore.open(file)) {
            Path tmp = Files.createFile(file.resolveSibling("vault.pmv.tmp"),
                    OwnerOnly.creationAttributes(file.getParent(), false));
            Path written = Files.write(tmp, new byte[] {99});
            assertEquals(tmp, written);
            store.writeAtomically(new byte[] {1, 2});
            assertArrayEquals(new byte[] {1, 2}, store.readAll());
            assertFalse(Files.exists(tmp));
        }
    }
}
