package pm.tui;

import pm.crypto.SecretChars;
import pm.vault.VaultException;

/**
 * Lane E port over {@code pm.vault.VaultService} (ADR 0003, ADR 0004), so the TUI and CLI can be
 * tested with in-memory fakes. Production uses {@link VaultServiceAdapter}.
 */
public interface VaultPort {

    /** Creates a new vault; refuses if one exists. */
    CreatedSession create(SecretChars passphrase) throws VaultException;

    /** Unlocks through the passphrase slot. */
    Session unlockWithPassphrase(SecretChars passphrase) throws VaultException;

    /** Unlocks through the recovery-key slot. */
    Session unlockWithRecoveryKey(SecretChars recoveryKey) throws VaultException;
}
