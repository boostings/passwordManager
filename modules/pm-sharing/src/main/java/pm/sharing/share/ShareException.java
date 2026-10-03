package pm.sharing.share;

import java.util.Objects;

/** A share that did not complete. Every case fails closed: nothing is sent or applied. */
public final class ShareException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Why; the codes with a wire number travel in an ERROR message. */
    public enum Code {
        /** Out-of-order message, sequence gap, unreadable frame, or wrong device id. */
        PROTOCOL(1),
        /** The share window has closed. */
        EXPIRED(2),
        /** A one-use share was already sent. */
        USED(3),
        /** The share, or the device, was revoked. */
        REVOKED(4),
        /** No such share for this device. */
        UNKNOWN(5),
        /** The receiver could not validate or apply the payload; nothing was applied. */
        NOT_APPLIED(6),
        /** The receiver already applied this share id. */
        REPLAY(7),
        /** The receiving user declined the offer. */
        DECLINED(0),
        /** The sender had nothing to offer this device. */
        NOTHING_OFFERED(0),
        /** The peer ended the session without saying why. */
        PEER_ABORTED(0);

        private final int wireCode;

        Code(int wireCode) {
            this.wireCode = wireCode;
        }

        /** The ERROR code for this reason; 0 for reasons that are never sent. */
        public int wire() {
            return wireCode;
        }

        /** The reason an ERROR code names; {@code PEER_ABORTED} for an unknown code. */
        public static Code fromWire(long code) {
            for (Code c : values()) {
                if (c.wireCode != 0 && c.wireCode == code) {
                    return c;
                }
            }
            return PEER_ABORTED;
        }
    }

    private final Code reason;

    /** A failure whose message is {@code code.name()}. */
    public ShareException(Code code) {
        super(Objects.requireNonNull(code, "code").name());
        this.reason = code;
    }

    /** Why the share did not complete. */
    public Code code() {
        return reason;
    }
}
