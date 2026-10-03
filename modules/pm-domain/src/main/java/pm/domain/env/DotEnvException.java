package pm.domain.env;

import java.util.Objects;

/**
 * A {@code .env} file was rejected. Carries a code and a line number only: never any text from
 * the file, which may hold secrets (SR-501, FIO13-J).
 */
public final class DotEnvException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Why the file was rejected. */
    public enum Code {
        /** The file is larger than {@link DotEnv#MAX_INPUT_BYTES}. */
        TOO_LARGE,
        /** The file is not valid UTF-8. */
        BAD_ENCODING,
        /** A control character other than tab appears outside a double-quoted value. */
        CONTROL_CHARACTER,
        /** A variable name is empty, too long, or uses characters other than letters, digits and _. */
        BAD_NAME,
        /** A line holds a name but no {@code =}. */
        MISSING_EQUALS,
        /** A quoted value is not closed. */
        UNTERMINATED_QUOTE,
        /** A backslash escape other than \n \r \t \" \\ \$ in a double-quoted value. */
        BAD_ESCAPE,
        /** Text follows a closing quote. */
        TRAILING_TEXT,
        /** A value is longer than {@link DotEnv#MAX_VALUE_BYTES}. */
        VALUE_TOO_LARGE,
        /** More than {@link DotEnv#MAX_ENTRIES} variables. */
        TOO_MANY_ENTRIES,
        /** The same name appears twice. */
        DUPLICATE_NAME
    }

    private final Code reason;
    private final int lineNumber;

    DotEnvException(Code code, int line) {
        super(Objects.requireNonNull(code, "code").name() + " at line " + line);
        this.reason = code;
        this.lineNumber = line;
    }

    /** Why the file was rejected. */
    public Code code() {
        return reason;
    }

    /** The 1-based line where the problem starts; 0 for whole-file problems. */
    public int line() {
        return lineNumber;
    }
}
