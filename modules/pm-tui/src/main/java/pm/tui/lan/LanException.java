package pm.tui.lan;

import java.util.Objects;

/**
 * A devices or sharing step the user asked for cannot go ahead. The code is the whole message:
 * front ends map it to fixed catalogue text and never show a value (SR-501, ERR01-J).
 */
public final class LanException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Why. */
    public enum Code {
        /** No paired device has that name or fingerprint. */
        NO_SUCH_DEVICE,
        /** More than one paired device has that name; use the fingerprint. */
        AMBIGUOUS_DEVICE,
        /** No item has that title, or it is internal sharing state. */
        NO_SUCH_ITEM,
        /** More than one item has that title. */
        AMBIGUOUS_ITEM,
        /** This item cannot go this way (a project to a browser, an oversized item). */
        NOT_SHAREABLE,
        /** The address is not {@code IP:port}. */
        BAD_ADDRESS,
        /** The window length is not between 1 s and 24 h. */
        BAD_TTL,
        /** The share id is not 32 hex digits. */
        BAD_SHARE_ID,
        /** No open share window has that id. */
        NO_SUCH_SHARE,
        /** The network or TLS layer failed. */
        NETWORK
    }

    private final Code failure;

    /** A failure with {@code code}. */
    public LanException(Code code) {
        super(Objects.requireNonNull(code, "code").name());
        this.failure = code;
    }

    /** A failure with {@code code} caused by {@code cause}; the cause is never shown. */
    public LanException(Code code, Throwable cause) {
        super(Objects.requireNonNull(code, "code").name(), cause);
        this.failure = code;
    }

    /** The reason. */
    public Code code() {
        return failure;
    }
}
