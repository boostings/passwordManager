package pm.tui;

import java.util.List;
import java.util.UUID;
import pm.vault.VaultException;
import pm.vault.record.VaultRecord;

/**
 * Lane E port over an unlocked vault, so the TUI and CLI can be tested with in-memory fakes
 * ({@code pm.vault.Vault} is final). {@link #close()} locks the vault (ADR 0008, SR-504).
 */
public interface Session extends AutoCloseable {

    /** Unmodifiable snapshot of all records. */
    List<VaultRecord> records();

    /** Records whose non-secret fields match {@code query} (SR-503). */
    List<VaultRecord> search(String query);

    /** Inserts {@code r}, or replaces the record with the same id. */
    void put(VaultRecord r);

    /** Removes the record with {@code id}; returns whether one was removed. */
    boolean remove(UUID id);

    /** Persists the vault (ADR 0003 write rules). */
    void save() throws VaultException;

    /** Whether the session has been locked. */
    boolean isLocked();

    /** Locks the vault. */
    @Override
    void close();
}
