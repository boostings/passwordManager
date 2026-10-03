package pm.vault.record;

import java.util.Objects;

/**
 * Rejection of a payload by {@link RecordCodec#decodePayload} (ADR 0006, SR-021).
 *
 * <p>The message is fixed text. It never contains record content, so it is safe to chain into
 * other exceptions (SR-501, ERR01-J). Callers branch on {@link #code()}, never on the message.
 */
public final class RecordException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Why the payload was rejected. */
    public enum Code {
        /** Valid CBOR that does not match {@code docs/schemas/records.cddl}. */
        SCHEMA,
        /** A size, count or range bound was exceeded. */
        LIMIT,
        /** Not a deterministic encoding of the supported CBOR subset. */
        MALFORMED
    }

    private final Code reason;

    /**
     * Creates a rejection.
     *
     * @param code why the payload was rejected
     * @param message fixed text, never record content
     */
    public RecordException(Code code, String message) {
        super(message);
        this.reason = Objects.requireNonNull(code, "code");
    }

    /**
     * Creates a rejection with the underlying cause.
     *
     * @param code why the payload was rejected
     * @param message fixed text, never record content
     * @param cause the failure that led to the rejection
     */
    public RecordException(Code code, String message, Throwable cause) {
        super(message, cause);
        this.reason = Objects.requireNonNull(code, "code");
    }

    /** Returns why the payload was rejected. */
    public Code code() {
        return reason;
    }
}
