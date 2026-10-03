package pm.sharing.share;

import java.time.Clock;
import java.util.List;
import java.util.Objects;
import pm.crypto.ConstantTime;
import pm.crypto.DeviceIdentity;
import pm.sharing.wire.Message;
import pm.sharing.wire.Octets;
import pm.sharing.wire.Sequence;
import pm.sharing.wire.WireException;

/**
 * What both ends of a share session have in common: HELLO first, its device id bound to the key
 * TLS proved, strict sequence numbers, and ERROR ending the session. Not thread-safe.
 */
final class SessionCore {
    /** Capability advertised in HELLO. */
    static final String CAPABILITY = "share";

    final byte[] peerKey;
    final Clock clock;
    private final byte[] ownKey;
    private final String ownName;
    private final Sequence outgoing = new Sequence();
    private final Sequence incoming = new Sequence();
    private boolean helloSeen;
    private boolean ended;

    SessionCore(byte[] ownKey, byte[] peerKey, String ownName, Clock clock) {
        this.ownKey = key(ownKey);
        this.peerKey = key(peerKey);
        this.ownName = Objects.requireNonNull(ownName, "ownName");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    private static byte[] key(byte[] k) {
        if (Objects.requireNonNull(k, "key").length != DeviceIdentity.PUBLIC_KEY_BYTES) {
            throw new IllegalArgumentException("BAD_KEY");
        }
        return k.clone();
    }

    long nextSeq() {
        return outgoing.next();
    }

    Message hello() {
        return new Message.Hello(nextSeq(), Octets.copyOf(DeviceIdentity.deviceId(ownKey)), ownName,
                List.of(CAPABILITY));
    }

    boolean failed() {
        return ended;
    }

    /**
     * Checks the envelope of {@code m}: not failed, in sequence, HELLO first and bound to the TLS
     * key, ERROR ends the session.
     *
     * @return false if {@code m} was the HELLO and is fully handled
     */
    boolean admit(Message m) throws ShareException {
        Objects.requireNonNull(m, "m");
        if (ended) {
            throw fail(ShareException.Code.PROTOCOL);
        }
        try {
            incoming.accept(m.seq());
        } catch (WireException e) {
            throw fail(ShareException.Code.PROTOCOL);
        }
        if (m instanceof Message.ErrorReport e) {
            throw fail(ShareException.Code.fromWire(e.code()));
        }
        if (helloSeen) {
            return true;
        }
        if (!(m instanceof Message.Hello h)
                || !ConstantTime.equals(h.deviceId().toByteArray(), DeviceIdentity.deviceId(peerKey))) {
            throw fail(ShareException.Code.PROTOCOL);
        }
        helloSeen = true;
        return false;
    }

    ShareException fail(ShareException.Code code) {
        ended = true;
        return new ShareException(code);
    }

    List<Message> abort(ShareException.Code code) {
        ended = true;
        long seq = nextSeq();
        return List.of(code.wire() == 0 ? new Message.Bye(seq) : new Message.ErrorReport(seq, code.wire()));
    }
}
