package pm.vault;

import java.util.Objects;
import pm.crypto.SecretChars;

/**
 * Result of {@link VaultService#create}: the unlocked vault plus the recovery key
 * (ADR 0004). The caller shows the recovery key once and then closes it. Closing this
 * record closes both.
 *
 * @param vault       the new, unlocked vault
 * @param recoveryKey formatted recovery key, 8 groups of 7 base32 characters
 */
public record CreatedVault(Vault vault, SecretChars recoveryKey) implements AutoCloseable {

    /** Rejects null components (EXP01-J). */
    public CreatedVault {
        Objects.requireNonNull(vault, "vault");
        Objects.requireNonNull(recoveryKey, "rk");
    }

    /** Zeroes the recovery key and locks the vault. */
    @Override
    public void close() {
        try (vault) {
            recoveryKey.close();
        }
    }
}
