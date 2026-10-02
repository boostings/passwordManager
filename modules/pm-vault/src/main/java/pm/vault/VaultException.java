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
        STORAGE
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
