package pm.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** T-FS-02: deterministic interruption at each atomic-write boundary (not process killing). */
final class AtomicWriteCrashTest {
    private static final byte[] VERSION_ONE = {1, 2, 3, (byte) 0xff};
    private static final byte[] VERSION_TWO = {4, 5, 6, 7, 8};
    @TempDir Path root;

    @ParameterizedTest
    @EnumSource(VaultFileStore.Step.class)
    void failedReplacementLeavesExactlyAnOldOrNewVault(VaultFileStore.Step checkpoint)
            throws StorageException {
        Path file = root.resolve("private/vault.pmv");
        AtomicReference<VaultFileStore.Step> armed = new AtomicReference<>();
        try (VaultFileStore store = VaultFileStore.open(file, 32, step -> {
            if (step == armed.get()) {
                throw new IOException("SIMULATED_CRASH");
            }
        })) {
            store.writeAtomically(VERSION_ONE);
            armed.set(checkpoint);
            StorageException error = assertThrows(StorageException.class,
                    () -> store.writeAtomically(VERSION_TWO));
            assertEquals(StorageException.Code.IO, error.code());
        }
        try (VaultFileStore reopened = VaultFileStore.open(file)) {
            boolean renamed = checkpoint == VaultFileStore.Step.RENAMED
                    || checkpoint == VaultFileStore.Step.DIR_SYNCED;
            assertArrayEquals(renamed ? VERSION_TWO : VERSION_ONE, reopened.readAll());
            reopened.writeAtomically(VERSION_TWO);
            assertArrayEquals(VERSION_TWO, reopened.readAll());
            assertFalse(Files.exists(file.resolveSibling("vault.pmv.tmp")));
            assertTrue(OwnerOnly.isOwnerOnly(file));
        }
    }

    @ParameterizedTest
    @EnumSource(VaultFileStore.Step.class)
    void stagingFileIsPrivateBeforeAnyBytesAreWritten(VaultFileStore.Step checkpoint)
            throws StorageException {
        Path file = root.resolve("private/vault.pmv");
        try (VaultFileStore store = VaultFileStore.open(file, 32, step -> {
            if (step == checkpoint && (step == VaultFileStore.Step.TMP_CREATED
                    || step == VaultFileStore.Step.TMP_WRITTEN
                    || step == VaultFileStore.Step.TMP_SYNCED)) {
                try {
                    assertTrue(OwnerOnly.isOwnerOnly(file.resolveSibling("vault.pmv.tmp")));
                } catch (StorageException ex) {
                    throw new IOException("PERMISSIONS", ex);
                }
            }
        })) {
            store.writeAtomically(VERSION_ONE);
            assertTrue(store.exists());
        }
    }
}
