package pm.vault;

import java.time.Clock;
import java.util.Objects;
import pm.crypto.Argon2Params;
import pm.crypto.SecretChars;
import pm.storage.VaultFileStore;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane C/D replace this file.
 *
 * <p>Creates and unlocks the vault file through its passphrase or recovery-key slot (ADR 0003,
 * ADR 0004, ADR 0007). Production passes {@code Kdf.tune(500 ms)}; tests pass
 * {@link Argon2Params#FLOOR}.
 */
@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)
public final class VaultService {

    /** Binds the service to one vault file. */
    public VaultService(VaultFileStore store, Clock clock, Argon2Params kdf) {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(kdf, "kdf");
    }

    /** Creates a new vault; refuses if the file exists. */
    public CreatedVault create(SecretChars passphrase) throws VaultException {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Unlocks through the passphrase slot. */
    public Vault unlockWithPassphrase(SecretChars passphrase) throws VaultException {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Unlocks through the recovery-key slot. */
    public Vault unlockWithRecoveryKey(SecretChars recoveryKey) throws VaultException {
        throw new UnsupportedOperationException("M1 stub");
    }
}
