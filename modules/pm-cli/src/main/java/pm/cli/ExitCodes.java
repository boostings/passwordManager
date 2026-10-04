package pm.cli;

import pm.storage.StorageException;
import pm.vault.VaultException;

/**
 * Process exit codes (plan.md §5 E, SR-501): 0 ok, 1 wrong credential, 2 usage, 3 corrupt or
 * unsupported, 4 storage, 5 internal error, 6 recovery key not shown, 7 not enough memory, 8 denied
 * ({@code env run}), 9 external service failed ({@code ssh-agent}, breach service). Both
 * mappings switch exhaustively over {@link VaultException.Code}, so a new code is a compile error
 * rather than a silent default.
 *
 * <p>{@code ALREADY_EXISTS} maps to 2 (usage): {@code init} was pointed at a path that already
 * holds a vault, and the fix is a different invocation ({@code --vault}), not repairing anything.
 * {@code LOCKED} maps to 4 (storage): another process holds the vault file lock, an environment
 * condition of the file system rather than bad input or a damaged file.
 *
 * <p>{@link #INTERNAL} (5) is an unexpected runtime failure (a bug); it has its own code so it can
 * never be mistaken for a wrong passphrase (1), and only the catalogue text "internal error" is
 * printed, never the exception or a stack trace (SR-501, ERR01-J). {@link #RECOVERY_NOT_SHOWN} (6)
 * means {@code init} created the vault but writing the recovery key to stdout failed (closed pipe,
 * full disk): the key is gone, so the user must delete the new, still empty vault and re-run
 * {@code init} (ADR 0004). {@link #INSUFFICIENT_MEMORY} (7) means the Java heap is too small for
 * the Argon2id memory the vault header asks for (ADR 0007): the vault is intact and the passphrase
 * was never tested, so it must not look like a corrupt vault (3) or a wrong passphrase (1).
 */
final class ExitCodes {
    static final int OK = 0;
    static final int WRONG_CREDENTIAL = 1;
    static final int USAGE = 2;
    static final int CORRUPT = 3;
    static final int STORAGE = 4;
    static final int INTERNAL = 5;
    static final int RECOVERY_NOT_SHOWN = 6;
    static final int INSUFFICIENT_MEMORY = 7;
    /** {@code env run}: the approval was denied, timed out or the vault was locked; nothing ran. */
    static final int DENIED = 8;
    /**
     * A service outside pm failed: {@code ssh-agent} (absent, whether {@code SSH_AUTH_SOCK} is unset
     * or nothing listens on it; unsafe socket; refused; bad reply; no answer within the deadline) or
     * the opt-in breach service (network, timeout, invalid reply). Nothing in the vault changed.
     */
    static final int EXTERNAL = 9;

    private ExitCodes() {
    }

    /** Exit code for a vault failure. */
    static int of(VaultException.Code code) {
        return switch (code) {
            case WRONG_CREDENTIAL -> WRONG_CREDENTIAL;
            case CORRUPT, UNSUPPORTED_VERSION -> CORRUPT;
            case ALREADY_EXISTS -> USAGE;
            case LOCKED, STORAGE -> STORAGE;
            case INSUFFICIENT_MEMORY -> INSUFFICIENT_MEMORY;
        };
    }

    /** Catalogue message for a vault failure; never the exception's own message (SR-501). */
    static Messages messageFor(VaultException e) {
        return switch (e.code()) {
            case WRONG_CREDENTIAL -> Messages.ERR_WRONG_CREDENTIAL;
            case CORRUPT -> Messages.ERR_CORRUPT;
            case UNSUPPORTED_VERSION -> Messages.ERR_UNSUPPORTED_VERSION;
            case ALREADY_EXISTS -> Messages.ERR_ALREADY_EXISTS;
            case LOCKED -> Messages.ERR_LOCKED;
            case STORAGE -> isNotFound(e.getCause()) ? Messages.ERR_NOT_FOUND : Messages.ERR_STORAGE;
            case INSUFFICIENT_MEMORY -> Messages.ERR_INSUFFICIENT_MEMORY;
        };
    }

    private static boolean isNotFound(Throwable cause) {
        return cause instanceof StorageException se && se.code() == StorageException.Code.NOT_FOUND;
    }
}
