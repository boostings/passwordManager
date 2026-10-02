package pm.storage;

import java.nio.file.Path;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane B replaces this file.
 *
 * <p>Single-vault file store implementing the ADR 0003 write rules (SR-041). One instance per
 * vault path.
 */
@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)
public final class VaultFileStore implements AutoCloseable {
    /** Largest vault file accepted by {@link #readAll()}. */
    public static final long MAX_FILE_BYTES = 256L * 1024 * 1024;

    private VaultFileStore() {
    }

    /** Opens the store for {@code vaultFile} and takes the exclusive lock. */
    public static VaultFileStore open(Path vaultFile) throws StorageException {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Whether the vault file exists. */
    public boolean exists() {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Reads the whole vault file. */
    public byte[] readAll() throws StorageException {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Replaces the vault file atomically. */
    public void writeAtomically(byte[] data) throws StorageException {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Rotates backups and copies the current file to the first backup slot. */
    public void backup() throws StorageException {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Releases the lock. */
    @Override
    public void close() {
        throw new UnsupportedOperationException("M1 stub");
    }
}
