package pm.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Caller-named private siblings, used for the pre-migration rollback copy (ADR 0015). */
final class SiblingTest {
    private static final String SUFFIX = ".pre-migration-v0";

    @TempDir Path root;

    @Test
    void createReadDeleteRoundTripIsOwnerOnlyAndCreateNew() throws IOException, StorageException {
        Path file = root.resolve("vault.pmv");
        try (VaultFileStore store = VaultFileStore.open(file)) {
            assertFalse(store.siblingExists(SUFFIX));
            assertFalse(store.deleteSibling(SUFFIX));
            store.createSibling(SUFFIX, new byte[] {1, 2, 3});
            Path sibling = root.resolve("vault.pmv" + SUFFIX);
            assertTrue(store.siblingExists(SUFFIX));
            assertTrue(OwnerOnly.isOwnerOnly(sibling));
            assertArrayEquals(new byte[] {1, 2, 3}, store.readSibling(SUFFIX));
            assertFalse(Files.exists(root.resolve("vault.pmv" + SUFFIX + ".tmp")));

            StorageException again = assertThrows(StorageException.class,
                    () -> store.createSibling(SUFFIX, new byte[] {9}));
            assertEquals(StorageException.Code.IO, again.code());
            assertArrayEquals(new byte[] {1, 2, 3}, store.readSibling(SUFFIX));

            assertTrue(store.deleteSibling(SUFFIX));
            assertFalse(Files.exists(sibling));
            assertEquals(StorageException.Code.NOT_FOUND,
                    assertThrows(StorageException.class, () -> store.readSibling(SUFFIX)).code());
        }
    }

    @Test
    void suffixesThatCouldNameAnotherStoreFileAreRefused() throws StorageException {
        try (VaultFileStore store = VaultFileStore.open(root.resolve("vault.pmv"))) {
            for (String bad : new String[] {".lock", ".tmp", ".bak.1", "x", ".", ".UPPER", "./x", ".a/b",
                    "." + "a".repeat(33)}) {
                assertThrows(IllegalArgumentException.class, () -> store.siblingExists(bad), bad);
            }
            assertThrows(NullPointerException.class, () -> store.createSibling(SUFFIX, null));
            assertThrows(NullPointerException.class, () -> store.siblingExists(null));
        }
    }

    @Test
    void oversizedSiblingIsRefused() throws StorageException {
        try (VaultFileStore store = VaultFileStore.open(root.resolve("vault.pmv"), 4, step -> { /* no crash */ })) {
            assertEquals(StorageException.Code.TOO_LARGE, assertThrows(StorageException.class,
                    () -> store.createSibling(SUFFIX, new byte[5])).code());
            assertFalse(store.siblingExists(SUFFIX));
        }
    }

    @Test
    void crashBeforeRenameLeavesNoSibling() throws StorageException {
        try (VaultFileStore store = VaultFileStore.open(root.resolve("vault.pmv"), 64, step -> {
            if (step == VaultFileStore.Step.TMP_SYNCED) {
                throw new IOException("injected");
            }
        })) {
            assertThrows(StorageException.class, () -> store.createSibling(SUFFIX, new byte[] {1}));
            assertFalse(store.siblingExists(SUFFIX));
            assertFalse(Files.exists(root.resolve("vault.pmv" + SUFFIX + ".tmp")));
        }
    }
}
