package pm.browser.host;

import java.util.Objects;

/**
 * A message the host refuses. The message is the code name, never browser data (SR-501), and the
 * code is what the extension receives in an {@code error} reply.
 */
public final class HostException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Why the input was refused. */
    public enum Code {
        /** The browser closed stdin at a frame boundary: a normal end. */
        CLOSED,
        /** Stdin ended inside a frame. Closes the host. */
        TRUNCATED,
        /** A frame length of zero or above the limit. Closes the host. */
        FRAME_SIZE,
        /** The frame is not well-formed UTF-8. */
        BAD_UTF8,
        /** The frame is not one JSON value within the depth, size and member limits. */
        MALFORMED,
        /** The {@code type} field names no known request. */
        UNKNOWN_TYPE,
        /** A field is missing, extra, of the wrong type or out of range. */
        BAD_FIELD,
        /** A {@code hello} with a protocol version other than {@link Request.Hello#VERSION}. */
        VERSION,
        /** Answering failed unexpectedly; nothing was released and the session continues. */
        INTERNAL
    }

    private final Code reason;

    /** Creates a refusal whose message is {@code code.name()}. */
    public HostException(Code code) {
        super(Objects.requireNonNull(code, "code").name());
        this.reason = code;
    }

    /** Why the input was refused. */
    public Code code() {
        return reason;
    }
}
