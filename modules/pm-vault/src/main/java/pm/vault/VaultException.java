package pm.vault;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane C/D replace this file.
 *
 * <p>Checked vault failure carrying only an error code; the message is the code name (SR-501,
 * ERR01-J).
 */
public final class VaultException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Fixed error catalogue. */
    public enum Code {
        /** Passphrase or recovery key did not unwrap any slot. */
        WRONG_CREDENTIAL,
        /** The vault file failed to parse or authenticate. */
        CORRUPT,
        /** The vault format version is not supported. */
        UNSUPPORTED_VERSION,
        /** {@code create} found an existing vault file. */
        ALREADY_EXISTS,
        /** The vault is locked or held by another process. */
        LOCKED,
        /** Underlying storage failure. */
        STORAGE
    }

    private final Code errorCode;

    /** Creates an exception whose message is {@code code.name()}. */
    public VaultException(Code code, Throwable cause) {
        super(code.name(), cause);
        this.errorCode = code;
    }

    /** The error code. */
    public Code code() {
        return errorCode;
    }
}
