package pm.vault.record;

public class RecordException extends Exception {
    private static final long serialVersionUID = 1L;

    public enum Code { SCHEMA, LIMIT, MALFORMED }

    private final Code code;

    public RecordException(Code code, String message) {
        super(message);
        this.code = code;
    }

    public RecordException(Code code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public Code code() {
        return code;
    }
}
