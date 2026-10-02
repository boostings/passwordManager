package pm.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** FIO00/16-J: reject links at vault, lock, staging, and backup boundaries. */
final class SymlinkRefusedTest {
    @TempDir Path root;

    @ParameterizedTest
    @ValueSource(strings = {"vault.pmv", "vault.pmv.lock"})
    void refusesLinksDuringOpenIncludingDanglingLinks(String name)
            throws IOException, StorageException {
        Path directory = Files.createDirectory(root.resolve("private"));
        OwnerOnly.apply(directory);
        makeLink(directory.resolve(name), root.resolve("missing-target"));
        StorageException error = assertThrows(StorageException.class, () -> {
            try (VaultFileStore store = VaultFileStore.open(directory.resolve("vault.pmv"))) {
                assertFalse(store.exists());
            }
        });
        assertEquals(StorageException.Code.SYMLINK_REFUSED, error.code());
    }

    @ParameterizedTest
    @ValueSource(strings = {"vault.pmv.tmp", "vault.pmv.bak.1", "vault.pmv.bak.2",
            "vault.pmv.bak.3", "vault.pmv.bak.1.tmp"})
    void refusesLinksDuringWritesWithoutChangingTheirTargets(String name)
            throws IOException, StorageException {
        Path file = root.resolve("private/vault.pmv");
        Path outside = Files.write(root.resolve("outside"), new byte[] {99});
        try (VaultFileStore store = VaultFileStore.open(file)) {
            store.writeAtomically(new byte[] {1});
            makeLink(file.resolveSibling(name), outside);
            StorageException error = assertThrows(StorageException.class, () -> {
                if (name.equals("vault.pmv.tmp")) {
                    store.writeAtomically(new byte[] {2});
                } else {
                    store.backup();
                }
            });
            assertEquals(StorageException.Code.SYMLINK_REFUSED, error.code());
            assertArrayEquals(new byte[] {99}, Files.readAllBytes(outside));
            assertArrayEquals(new byte[] {1}, store.readAll());
        }
    }

    @Test
    void refusesVaultReplacedWithLinkAfterOpen() throws IOException, StorageException {
        Path file = root.resolve("private/vault.pmv");
        try (VaultFileStore store = VaultFileStore.open(file)) {
            makeLink(file, root.resolve("missing-target"));
            assertEquals(StorageException.Code.SYMLINK_REFUSED,
                    assertThrows(StorageException.class, store::readAll).code());
            assertEquals(StorageException.Code.SYMLINK_REFUSED,
                    assertThrows(StorageException.class,
                            () -> store.writeAtomically(new byte[] {1})).code());
        }
    }

    @Test
    void canonicalParentAliasesShareOneLock() throws IOException, StorageException {
        Path file = root.resolve("private/vault.pmv");
        try (VaultFileStore store = VaultFileStore.open(file)) {
            makeLink(root.resolve("alias"), file.getParent());
            assertFalse(store.exists());
            assertEquals(StorageException.Code.LOCKED_BY_OTHER,
                    assertThrows(StorageException.class, () -> {
                        try (VaultFileStore duplicate = VaultFileStore.open(root.resolve("alias/vault.pmv"))) {
                            assertFalse(duplicate.exists());
                        }
                    }).code());
        }
    }

    @Test
    void sharedExistingDirectoryIsRejectedWithoutChangingItsPermissions()
            throws IOException {
        assumeTrue(root.getFileSystem().supportedFileAttributeViews().contains("posix"));
        Path directory = Files.createDirectory(root.resolve("shared"));
        Path changed = Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwxr-xr-x"));
        assertEquals(StorageException.Code.PERMISSIONS,
                assertThrows(StorageException.class, () -> {
                    try (VaultFileStore store = VaultFileStore.open(changed.resolve("vault.pmv"))) {
                        assertFalse(store.exists());
                    }
                }).code());
        assertEquals(PosixFilePermissions.fromString("rwxr-xr-x"), Files.getPosixFilePermissions(directory));
    }

    private static void makeLink(Path link, Path target) throws IOException {
        try {
            Path created = Files.createSymbolicLink(link, target);
            assertTrue(Files.isSymbolicLink(created));
        } catch (UnsupportedOperationException ex) {
            assumeTrue(false, "Filesystem does not support symlinks");
        } catch (IOException ex) {
            if (System.getProperty("os.name").startsWith("Windows")) {
                assumeTrue(false, "Windows runner lacks permission to create symlinks");
            } else {
                throw ex;
            }
        }
    }
}
