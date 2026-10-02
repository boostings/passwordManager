package pm.vault;

import pm.crypto.SecretChars;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane C/D replace this file.
 *
 * <p>Result of {@link VaultService#create}: the unlocked vault and its recovery key (ADR 0004). The
 * recovery key is shown once, then closed by the caller.
 */
public record CreatedVault(Vault vault, SecretChars recoveryKey) {
}
