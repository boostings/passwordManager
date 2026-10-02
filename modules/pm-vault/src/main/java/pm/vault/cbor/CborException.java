package pm.vault.cbor;

import java.util.Objects;

/**
 * CBOR decode failure (ADR 0006 amendment). The message is the code name only, never input
 * content (SR-501, ERR01-J).
 */
public final class CborException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Failure classes. */
    public enum Code {
        /** Input is not well-formed CBOR of the accepted subset. */
        MALFORMED,
        /** A {@link CborLimits} bound was exceeded. */
        LIMIT,
        /** Input is well-formed but not in deterministic form (RFC 8949 §4.2.1). */
        NON_CANONICAL
    }

    private final Code failure;

    /**
     * Creates an exception whose message is {@code code.name()}.
     *
     * @param code failure class, never null
     */
    public CborException(Code code) {
        this(code, null);
    }

    /**
     * Creates an exception whose message is {@code code.name()}.
     *
     * @param code  failure class, never null
     * @param cause underlying failure, may be null
     */
    public CborException(Code code, Throwable cause) {
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
