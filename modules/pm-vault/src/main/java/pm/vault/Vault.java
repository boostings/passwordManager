package pm.vault;

import java.util.List;
import java.util.UUID;
import pm.vault.record.VaultRecord;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane C/D replace this file.
 *
 * <p>An unlocked vault (ADR 0003, ADR 0008). {@link #close()} locks it: zeroes the vault key and
 * closes every record's secrets.
 */
@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)
public final class Vault implements AutoCloseable {

    private Vault() {
    }

    /** Unmodifiable snapshot of all records. */
    public List<VaultRecord> records() {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Records matching {@code query}; delegates to {@code RecordSearch}. */
    public List<VaultRecord> search(String query) {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Inserts {@code r}, or replaces the record with the same id. */
    public void put(VaultRecord r) {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Removes the record with {@code id}; returns whether one was removed. */
    public boolean remove(UUID id) {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Backs up the current file, then writes the vault atomically. */
    public void save() throws VaultException {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Whether {@link #close()} has run. */
    public boolean isLocked() {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Locks the vault. */
    @Override
    public void close() {
        throw new UnsupportedOperationException("M1 stub");
    }
}
