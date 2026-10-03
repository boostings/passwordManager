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
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** FIO16-J / FIO02-J: alternate spellings and unusable paths end in a code, never a crash. */
final class PathHandlingTest {
    @TempDir Path root;

    // Windows stores "private." as "private". The store must keep working with the stored
    // spelling instead of mistaking the difference for a redirected directory.
    @Test
    void directoryCreatedUnderAnAlteredSpellingStaysUsable() throws StorageException {
        Path file = root.resolve("private.").resolve("vault.pmv");
        try (VaultFileStore store = VaultFileStore.open(file)) {
            assertFalse(store.exists());
            store.writeAtomically(new byte[] {1});
            store.backup();
            assertArrayEquals(new byte[] {1}, store.readAll());
        }
        try (VaultFileStore reopened = VaultFileStore.open(file)) {
            assertTrue(reopened.exists());
        }
    }

    // A trailing dot or space is dropped by Windows, so "vault.pmv." would be the vault
    // "vault.pmv" guarded by a second lock file, "vault.pmv..lock".
    @ParameterizedTest
    @ValueSource(strings = {"vault.pmv.", "vault.pmv..", ".", ".."})
    void vaultNameTheFilesystemMayAlterIsRefused(String name) throws IOException, StorageException {
        Path directory = root.resolve("private");
        try (VaultFileStore store = VaultFileStore.open(directory.resolve("vault.pmv"))) {
            store.writeAtomically(new byte[] {1});
            StorageException error = assertThrows(StorageException.class, () -> {
                try (VaultFileStore alias = VaultFileStore.open(directory.resolve(name))) {
                    alias.writeAtomically(new byte[] {2});
                }
            });
            assertEquals(StorageException.Code.IO, error.code());
            assertArrayEquals(new byte[] {1}, store.readAll());
        }
        try (Stream<Path> children = Files.list(directory)) {
            assertEquals(2, children.count());
        }
    }

    // On Windows the root of a path can be absent (an unplugged or unmapped drive).
    @Test
    void missingFilesystemRootIsNotFound() {
        Optional<Path> absent = absentRoot();
        assumeTrue(absent.isPresent(), "every filesystem root exists on this platform");
        for (String relative : new String[] {"vault.pmv", "pm/vault.pmv"}) {
            StorageException error = assertThrows(StorageException.class, () -> {
                try (VaultFileStore store = VaultFileStore.open(absent.get().resolve(relative))) {
                    assertFalse(store.exists());
                }
            });
            assertEquals(StorageException.Code.NOT_FOUND, error.code());
        }
    }

    private static Optional<Path> absentRoot() {
        if (!System.getProperty("os.name").startsWith("Windows")) {
            return Optional.empty();
        }
        for (char letter = 'Z'; letter >= 'D'; letter--) {
            Path candidate = Path.of(letter + ":\\");
            if (!Files.exists(candidate)) {
                return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }
}
