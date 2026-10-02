package pm.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exclusive-lock ownership and explicit resource lifecycle (FIO04-J, OBJ14-J). */
final class LockTest {
    @TempDir Path root;

    @Test
    void duplicateOpenFailsAndCloseAllowsReopening() throws StorageException {
        Path file = root.resolve("private/vault.pmv");
        try (VaultFileStore first = VaultFileStore.open(file)) {
            StorageException error = assertThrows(StorageException.class, () -> {
                try (VaultFileStore unexpected = VaultFileStore.open(file)) {
                    assertFalse(unexpected.exists());
                }
            });
            assertEquals(StorageException.Code.LOCKED_BY_OTHER, error.code());
            first.writeAtomically(new byte[] {1});
            assertTrue(first.exists());
        }
        assertTrue(Files.exists(file.resolveSibling("vault.pmv.lock")));
        try (VaultFileStore next = VaultFileStore.open(file)) {
            assertTrue(next.exists());
        }
    }

    @Test
    void closedStoreRejectsEveryOperationAndCloseIsIdempotent() throws StorageException {
        try (VaultFileStore store = VaultFileStore.open(root.resolve("private/vault.pmv"))) {
            closeTwice(store);
            assertThrows(IllegalStateException.class, store::exists);
            assertThrows(IllegalStateException.class, store::readAll);
            assertThrows(IllegalStateException.class, store::backup);
            assertThrows(IllegalStateException.class, () -> store.writeAtomically(new byte[] {1}));
        }
    }

    // Close early to test use-after-close; the surrounding scope still guarantees cleanup.
    private static void closeTwice(VaultFileStore store) {
        store.close();
        store.close();
    }
}
