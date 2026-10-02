package pm.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** ADR 0003 / FIO08/10-J: bounded reads include size changes and partial reads. */
final class SizeLimitTest {
    private static final int LIMIT = 4;
    @TempDir Path root;

    @Test
    void rejectsOversizedDiskFilesAndWrites() throws StorageException, IOException {
        Path file = root.resolve("private/vault.pmv");
        try (VaultFileStore store = VaultFileStore.open(file, LIMIT, step -> { })) {
            store.writeAtomically(new byte[LIMIT]);
            assertEquals(LIMIT, store.readAll().length);
            StorageException writeError = assertThrows(StorageException.class,
                    () -> store.writeAtomically(new byte[LIMIT + 1]));
            assertEquals(StorageException.Code.TOO_LARGE, writeError.code());
            assertEquals(LIMIT, store.readAll().length);
            Path changed = Files.write(file, new byte[LIMIT + 1]);
            assertEquals(file, changed);
            StorageException readError = assertThrows(StorageException.class, store::readAll);
            assertEquals(StorageException.Code.TOO_LARGE, readError.code());
        }
    }

    @Test
    void streamedByteCountEnforcesLimitIndependentlyOfInitialFileSize() {
        ByteArrayInputStream input = new ByteArrayInputStream(new byte[LIMIT + 1]);
        StorageException error = assertThrows(StorageException.class,
                () -> VaultFileStore.readBounded(input, LIMIT));
        assertEquals(StorageException.Code.TOO_LARGE, error.code());
    }

    @Test
    void shortReadsAndByte255ArePreserved() throws IOException, StorageException {
        byte[] data = {1, (byte) 0xff, 3, 4};
        ByteArrayInputStream input = new ByteArrayInputStream(data) {
            @Override
            public int read(byte[] output, int offset, int length) {
                return super.read(output, offset, Math.min(length, 1));
            }
        };
        assertArrayEquals(data, VaultFileStore.readBounded(input, LIMIT));
    }

    @Test
    void missingVaultHasSafeNotFoundCode() throws StorageException {
        try (VaultFileStore store = VaultFileStore.open(root.resolve("private/vault.pmv"))) {
            StorageException error = assertThrows(StorageException.class, store::readAll);
            assertEquals(StorageException.Code.NOT_FOUND, error.code());
        }
    }
}
