package pm.vault.cbor;

public class CborException extends Exception {
    private static final long serialVersionUID = 1L;

    public enum Code { MALFORMED, LIMIT, NON_CANONICAL }

    private final Code code;

    public CborException(Code code, String message) {
        super(message);
        this.code = code;
    }

    public CborException(Code code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public Code code() {
        return code;
    }
}
