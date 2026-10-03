package pm.vault.cbor;

import java.util.Objects;

/**
 * Rejection of an encoded item by {@link CborReader} (ADR 0006 Amendment 1, SR-021).
 *
 * <p>The message is fixed text chosen by the reader. It never contains bytes or text taken from the
 * input, so it can be chained into other exceptions without leaking vault content (SR-501,
 * ERR01-J). Callers branch on {@link #code()}, never on the message.
 */
public final class CborException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Why the input was rejected. */
    public enum Code {
        /** Not well-formed, or outside the supported subset (tags, floats, negative integers, ...). */
        MALFORMED,
        /** A {@link CborLimits} bound was exceeded, or a number does not fit the supported range. */
        LIMIT,
        /** Well-formed, but not the RFC 8949 section 4.2.1 deterministic encoding. */
        NON_CANONICAL
    }

    private final Code reason;

    /**
     * Creates a rejection.
     *
     * @param code why the input was rejected
     * @param message fixed text, never input data
     */
    public CborException(Code code, String message) {
        super(message);
        this.reason = Objects.requireNonNull(code, "code");
    }

    /**
     * Creates a rejection with the underlying cause.
     *
     * @param code why the input was rejected
     * @param message fixed text, never input data
     * @param cause the failure that led to the rejection
     */
    public CborException(Code code, String message, Throwable cause) {
        super(message, cause);
        this.reason = Objects.requireNonNull(code, "code");
    }

    /** Returns why the input was rejected. */
    public Code code() {
        return reason;
    }
}
