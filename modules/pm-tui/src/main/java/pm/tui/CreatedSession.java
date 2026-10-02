package pm.tui;

import pm.crypto.SecretChars;

/**
 * Lane E port twin of {@code pm.vault.CreatedVault}: the new session and its recovery key
 * (ADR 0004). The recovery key is shown once, then closed by the caller.
 */
public record CreatedSession(Session session, SecretChars recoveryKey) {
}
