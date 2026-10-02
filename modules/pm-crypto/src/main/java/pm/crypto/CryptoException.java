package pm.crypto;

/** Checked crypto failure carrying only an error code; the message is the code name (SR-501, ERR01-J). */
public final class CryptoException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Fixed error catalogue. */
    public enum Code {
        /** Authentication tag, key unwrap, or checksum verification failed. */
        AUTH_FAILED,
        /** Malformed caller input (length, encoding). */
        BAD_INPUT,
        /** Parameters outside the allowed range. */
        BAD_PARAMS,
        /** Unexpected provider failure. */
        INTERNAL
    }

    private final Code code;

    /** Creates an exception whose message is {@code code.name()}. */
    public CryptoException(Code code) {
        super(code.name());
        this.code = code;
    }

    /** The error code. */
    public Code code() {
        return code;
    }
}
