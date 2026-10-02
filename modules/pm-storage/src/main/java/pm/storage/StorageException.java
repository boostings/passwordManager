package pm.storage;

import java.util.Objects;

/** A code-only storage failure; implements SR-501 and CERT ERR01-J. */
public final class StorageException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Stable errors which callers may translate into user-facing messages. */
    public enum Code {
        NOT_FOUND, TOO_LARGE, SYMLINK_REFUSED, LOCKED_BY_OTHER, PERMISSIONS, IO
    }

    private final Code errorCode;

    /**
     * Creates an error without retaining a potentially sensitive cause or suppressed errors.
     *
     * @param code the safe error category
     * @param cause the original failure, deliberately discarded because it can contain paths
     */
    public StorageException(Code code, Throwable cause) {
        super(Objects.requireNonNull(code, "CODE").name(), null, false, true);
        errorCode = code;
    }

    /**
     * Returns the safe error category without filesystem details.
     * @return the error code
     */
    public Code code() {
        return errorCode;
    }
}
