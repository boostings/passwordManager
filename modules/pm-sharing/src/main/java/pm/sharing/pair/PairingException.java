package pm.sharing.pair;

import java.util.Objects;

/** A failed pairing ceremony. Every code except {@code LOCKED} counts toward the lockout (SR-203). */
public final class PairingException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Why the ceremony failed. */
    public enum Code {
        /** A message out of order, a sequence gap or an unreadable frame. */
        PROTOCOL,
        /** The HELLO's device id is not the id of the key the peer proved in TLS. */
        IDENTITY,
        /** The initiator's revealed nonce does not open its commitment. */
        COMMITMENT,
        /** The peer's confirmation MAC does not verify: the two sides derived different SAS keys. */
        CONFIRMATION,
        /** The local user said the digits differ, or cancelled. */
        REJECTED,
        /** The peer sent BYE or ERROR. */
        PEER_ABORTED,
        /** Pairing is locked out after repeated failures. */
        LOCKED
    }

    private final Code reason;

    /** Creates a failure whose message is {@code code.name()}. */
    public PairingException(Code code) {
        super(Objects.requireNonNull(code, "code").name());
        this.reason = code;
    }

    /** Why the ceremony failed. */
    public Code code() {
        return reason;
    }
}
