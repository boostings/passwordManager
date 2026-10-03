package pm.browser.host;

import java.util.Objects;
import pm.approval.Decision;

/**
 * A message the host refuses. The message is the code name (or, for a broker refusal, the
 * {@link Decision} name), never browser data (SR-501), and it is what the extension receives in
 * an {@code error} reply.
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
        /** The origin is not a canonical {@code http}/{@code https} origin (ADR 0014 §5). */
        BAD_ORIGIN,
        /** No login with that id is registered for exactly that origin. */
        NOT_FOUND,
        /** The approval broker refused; the message is the broker's {@link Decision} name. */
        DENIED,
        /** A port broke its contract (for example, did not consume its grant); nothing was released. */
        INTERNAL
    }

    private final Code reason;

    /** Creates a refusal whose message is {@code code.name()}. */
    public HostException(Code code) {
        this(code, Objects.requireNonNull(code, "code").name());
    }

    private HostException(Code code, String message) {
        super(message);
        this.reason = code;
    }

    /**
     * A broker refusal with code {@link Code#DENIED} whose message, and so reply code, is
     * {@code decision.name()}.
     *
     * @throws IllegalArgumentException {@code NOT_A_DENIAL} if {@code decision} allows
     */
    public static HostException denied(Decision decision) {
        if (decision.allowed()) {
            throw new IllegalArgumentException("NOT_A_DENIAL");
        }
        return new HostException(Code.DENIED, decision.name());
    }

    /** Why the input was refused. */
    public Code code() {
        return reason;
    }
}
