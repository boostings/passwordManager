package pm.vault;

import java.util.Objects;

/**
 * Every failure a vault operation reports. The message is the code name only, never a
 * path, a key, or text from the underlying cause (SR-501, ERR01-J).
 */
public final class VaultException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Failure classes the CLI and TUI map to exit codes and fixed messages. */
    public enum Code {
        /** The passphrase or recovery key does not open any slot. */
        WRONG_CREDENTIAL,
        /** The file is malformed or failed authentication. */
        CORRUPT,
        /** The file was written by a newer format version. */
        UNSUPPORTED_VERSION,
        /** {@code create} was called but a vault file already exists. */
        ALREADY_EXISTS,
        /** The vault was used after it was locked. */
        LOCKED,
        /** The storage layer failed; the cause carries the storage code. */
        STORAGE,
        /**
         * The JVM heap cannot hold the Argon2id memory this vault's header asks for (ADR 0007).
         * The vault and the credential may both be fine; the fix is a larger {@code -Xmx}, so
         * this is never reported as {@link #CORRUPT}.
         */
        INSUFFICIENT_MEMORY,
        /**
         * A save, or a passphrase change, was refused and nothing was written: the vault file is
         * not the one this vault last read or wrote (another vault over the same file saved since,
         * or the file is no longer a vault this build reads), and writing would silently undo that
         * other save (SR-151). Lock this vault and unlock again to work on the file as it is now.
         */
        CONFLICT,
        /**
         * A passphrase change failed, but the file on disk holds the new passphrase slot: the new
         * passphrase and the recovery key open it, the old passphrase does not. The write could not
         * be confirmed; the cause is the failure. The vault stays open and holds the header that is
         * on disk, so its later saves keep the new passphrase (SR-152).
         */
        PASSPHRASE_CHANGED_UNCONFIRMED,
        /**
         * A passphrase change failed, and the file could not be read back or holds neither the old
         * nor the new passphrase slot, so which passphrase opens it is unknown; the cause is the
         * failure. A change never alters the recovery slot, so the recovery key opens the file as
         * long as it is a file this vault wrote (SR-152).
         */
        PASSPHRASE_CHANGE_UNKNOWN
    }

    private final Code failure;

    /**
     * Creates an exception for {@code code}.
     *
     * @param code  failure class, never null
     * @param cause underlying exception, or null
     */
    public VaultException(Code code, Throwable cause) {
        super(Objects.requireNonNull(code, "code").name(), cause);
        this.failure = code;
    }

    /** Returns the failure class. */
    public Code code() {
        return failure;
    }
}
