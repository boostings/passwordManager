package pm.tui;

import java.util.List;
import java.util.UUID;
import pm.crypto.SecretChars;
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

    /**
     * Changes the master passphrase (SR-130, ADR 0004 addendum) after checking {@code current}, the
     * passphrase or the recovery key, against the vault file, so an unattended unlocked session
     * cannot be used to lock its owner out. Neither argument is closed.
     *
     * @throws VaultException {@code WRONG_CREDENTIAL} if {@code current} opens nothing; otherwise as
     *     {@code VaultService.changePassphrase}, including {@code PASSPHRASE_CHANGED_UNCONFIRMED}
     *     and {@code PASSPHRASE_CHANGE_UNKNOWN}
     * @throws IllegalArgumentException {@code EMPTY_PASSPHRASE} or {@code MALFORMED_CHARS} for
     *     {@code fresh}; nothing is written
     */
    void changePassphrase(SecretChars current, SecretChars fresh) throws VaultException;

    /** Whether the session has been locked. */
    boolean isLocked();

    /** Locks the vault. */
    @Override
    void close();
}
