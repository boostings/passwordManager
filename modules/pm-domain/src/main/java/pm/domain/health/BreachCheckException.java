package pm.domain.health;

import java.util.Objects;

/**
 * A breach lookup did not complete. Carries a code only: never the password, its hash, the prefix
 * sent or the response body (SR-501).
 */
public final class BreachCheckException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Why the lookup failed. */
    public enum Code {
        /** The connection failed or was reset. */
        NETWORK,
        /** The whole exchange (connect, headers and body) did not finish within the client's timeout. */
        TIMEOUT,
        /** The service answered with a status other than 200. */
        HTTP_STATUS,
        /** The response body exceeded {@link BreachClient#MAX_BODY_BYTES}. */
        TOO_LARGE,
        /** The body was empty or a line was not {@code <35 uppercase hex>:<count>}. */
        MALFORMED,
        /** The calling thread was interrupted; its interrupt flag is set again. */
        INTERRUPTED,
        /** The local SHA-1 computation failed. */
        INTERNAL
    }

    private final Code reason;

    BreachCheckException(Code code) {
        super(Objects.requireNonNull(code, "code").name());
        this.reason = code;
    }

    /** Why the lookup failed. */
    public Code code() {
        return reason;
    }
}
