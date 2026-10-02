package pm.vault.record;

import java.util.Objects;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane D replaces this file.
 *
 * <p>Record payload failure. The message is the code name only (SR-501, ERR01-J).
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
        super(Objects.requireNonNull(code, "code").name());
        this.failure = code;
    }

    /** Returns the failure class. */
    public Code code() {
        return failure;
    }
}
