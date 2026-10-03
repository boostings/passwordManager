package pm.sharing.wire;

import java.util.Objects;

/** A frame or message the protocol refuses. The message is the code name, never peer data (SR-501). */
public final class WireException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Why the input was refused. Every code closes the session (lan-share.md §4). */
    public enum Code {
        /** The stream ended cleanly at a frame boundary. */
        CLOSED,
        /** The stream ended inside a frame. */
        TRUNCATED,
        /** A frame length of zero or above {@link Frames#MAX_BODY}. */
        FRAME_SIZE,
        /** The body is not one deterministic CBOR map within the limits. */
        MALFORMED,
        /** The {@code t} field names no known message. */
        UNKNOWN_TYPE,
        /** A field is missing, extra, of the wrong type or out of range. */
        BAD_FIELD,
        /** A HELLO with a protocol version other than {@link Message.Hello#VERSION}. */
        VERSION,
        /** A {@code seq} that is not exactly one more than the previous one. */
        BAD_SEQUENCE
    }

    private final Code reason;

    /** Creates a refusal whose message is {@code code.name()}. */
    public WireException(Code code) {
        super(Objects.requireNonNull(code, "code").name());
        this.reason = code;
    }

    /** Why the input was refused. */
    public Code code() {
        return reason;
    }
}
