package pm.vault.cbor;

import java.util.Objects;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane D replaces this file.
 *
 * <p>CBOR decode failure. The message is the code name only (SR-501, ERR01-J).
 */
public final class CborException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Failure classes. */
    public enum Code {
        /** Input is not well-formed CBOR of the accepted subset. */
        MALFORMED,
        /** A {@link CborLimits} bound was exceeded. */
        LIMIT,
        /** Input is well-formed but not in deterministic form. */
        NON_CANONICAL
    }

    private final Code failure;

    /**
     * Creates an exception whose message is {@code code.name()}.
     *
     * @param code failure class, never null
     */
    public CborException(Code code) {
        super(Objects.requireNonNull(code, "code").name());
        this.failure = code;
    }

    /** Returns the failure class. */
    public Code code() {
        return failure;
    }
}
