package pm.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
