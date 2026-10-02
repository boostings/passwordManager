package pm.cli;

import pm.storage.StorageException;
import pm.vault.VaultException;

/**
 * Process exit codes (plan.md §5 E, SR-501): 0 ok, 1 wrong credential, 2 usage, 3 corrupt or
 * unsupported, 4 storage. Both mappings switch exhaustively over {@link VaultException.Code}, so a
 * new code is a compile error rather than a silent default.
 *
 * <p>{@code ALREADY_EXISTS} maps to 2 (usage): {@code init} was pointed at a path that already
 * holds a vault, and the fix is a different invocation ({@code --vault}), not repairing anything.
 * {@code LOCKED} maps to 4 (storage): another process holds the vault file lock, an environment
 * condition of the file system rather than bad input or a damaged file.
 */
final class ExitCodes {
    static final int OK = 0;
    static final int WRONG_CREDENTIAL = 1;
    static final int USAGE = 2;
    static final int CORRUPT = 3;
    static final int STORAGE = 4;

    private ExitCodes() {
    }

    /** Exit code for a vault failure. */
    static int of(VaultException.Code code) {
        return switch (code) {
            case WRONG_CREDENTIAL -> WRONG_CREDENTIAL;
            case CORRUPT, UNSUPPORTED_VERSION -> CORRUPT;
            case ALREADY_EXISTS -> USAGE;
            case LOCKED, STORAGE -> STORAGE;
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
        };
    }

    private static boolean isNotFound(Throwable cause) {
        return cause instanceof StorageException se && se.code() == StorageException.Code.NOT_FOUND;
    }
}
