package pm.vault.record;

import java.util.Objects;

/**
 * Record payload failure (ADR 0006). The message is the code name only, never record content
 * (SR-501, ERR01-J).
 */
public final class RecordException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Failure classes. */
    public enum Code {
        /** Payload violates the record schema (ADR 0006). */
        SCHEMA,
        /** A record or payload bound was exceeded. */
        LIMIT,
        /** Payload is not well-formed. */
        MALFORMED
    }

    private final Code failure;

    /**
     * Creates an exception whose message is {@code code.name()}.
     *
     * @param code failure class, never null
     */
    public RecordException(Code code) {
        this(code, null);
    }

    /**
     * Creates an exception whose message is {@code code.name()}.
     *
     * @param code  failure class, never null
     * @param cause underlying failure, may be null
     */
    public RecordException(Code code, Throwable cause) {
        super(Objects.requireNonNull(code, "code").name(), cause);
        this.failure = code;
    }

    /**
     * Returns the failure class.
     *
     * @return the code
     */
    public Code code() {
        return failure;
    }
}
