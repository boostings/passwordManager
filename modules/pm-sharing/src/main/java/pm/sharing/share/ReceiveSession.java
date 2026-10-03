package pm.sharing.share;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import pm.sharing.wire.Message;
import pm.sharing.wire.Octets;

/**
 * The receiver's side of one share connection (lan-share.md §6 steps 2–5, §9), with no I/O:
 *
 * <pre>
 * start → HELLO                                    [WAIT_HELLO]
 * HELLO                                            [WAIT_OFFER]
 * SHARE_OFFER (open, not seen before)              [OFFERED]   user decides:
 *   accept → SHARE_ACCEPT                          [WAIT_DATA]
 *   decline → BYE                                  [DECLINED]
 * SHARE_DATA(id)                                   [VALIDATING] caller validates and applies:
 *   applied(true) → SHARE_ACK(true)                [WAIT_BYE]
 *   applied(false) → SHARE_ACK(false), ERROR       [FAILED]
 * BYE                                              [DONE]
 * </pre>
 *
 * An offer whose window has closed, or whose id was applied before, is refused. Not thread-safe.
 */
public final class ReceiveSession {
    /** Where the session is. */
    public enum State {
        /** {@link #start()} not yet called. */
        NEW,
        /** Waiting for the sender's HELLO. */
        WAIT_HELLO,
        /** Waiting for SHARE_OFFER. */
        WAIT_OFFER,
        /** Offer shown; waiting for the user. */
        OFFERED,
        /** Accepted; waiting for SHARE_DATA. */
        WAIT_DATA,
        /** Data received; the caller validates and applies it. */
        VALIDATING,
        /** Acknowledged; waiting for the sender's BYE. */
        WAIT_BYE,
        /** Finished and applied. */
        DONE,
        /** The user declined, or applying failed. */
        ENDED
    }

    private final SessionCore core;
    private final ReceivedShares seen;
    private State current = State.NEW;
    private Message.ShareOffer shown;
    private Octets data;

    /**
     * A receiver session.
     *
     * @param peerKey the sender's key, as TLS proved it
     */
    public ReceiveSession(byte[] ownKey, byte[] peerKey, String ownName, ReceivedShares received, Clock clock) {
        this.core = new SessionCore(ownKey, peerKey, ownName, clock);
        this.seen = Objects.requireNonNull(received, "received");
    }

    /** The current state. */
    public State state() {
        return current;
    }

    /** The offer to show the user: names and counts, never values. From {@code OFFERED} on. */
    public Message.ShareOffer offer() {
        require(shown != null);
        return shown;
    }

    /** The received record set; only in {@code VALIDATING}. */
    public Octets payload() {
        require(current == State.VALIDATING);
        return data;
    }

    /** Whether the session has ended in failure. */
    public boolean failed() {
        return core.failed();
    }

    /**
     * Ends the session after a local failure.
     *
     * @return ERROR with the reason's wire code, or BYE for a reason that has none
     */
    public List<Message> abort(ShareException.Code code) {
        return core.abort(code);
    }

    ShareException fail(ShareException.Code code) {
        return core.fail(code);
    }

    /** HELLO. */
    public List<Message> start() {
        require(current == State.NEW && !core.failed());
        current = State.WAIT_HELLO;
        return List.of(core.hello());
    }

    /**
     * Handles one message from the sender.
     *
     * @throws ShareException the session failed; send {@link #abort} to tell the sender
     */
    public List<Message> receive(Message m) throws ShareException {
        if (current == State.NEW || current == State.OFFERED || current == State.VALIDATING
                || current == State.DONE || current == State.ENDED) {
            throw core.fail(ShareException.Code.PROTOCOL);
        }
        if (!core.admit(m)) {
            current = State.WAIT_OFFER;
            return List.of();
        }
        return switch (m) {
            case Message.ShareOffer o when current == State.WAIT_OFFER -> {
                if (!Instant.ofEpochSecond(o.expires()).isAfter(core.clock.instant())) {
                    throw core.fail(ShareException.Code.EXPIRED);
                }
                if (seen.contains(o.shareId())) {
                    throw core.fail(ShareException.Code.REPLAY);
                }
                shown = o;
                current = State.OFFERED;
                yield List.of();
            }
            case Message.Bye b when current == State.WAIT_OFFER -> throw core.fail(ShareException.Code.NOTHING_OFFERED);
            case Message.ShareData d when current == State.WAIT_DATA && d.shareId().equals(shown.shareId()) -> {
                data = d.payload();
                current = State.VALIDATING;
                yield List.of();
            }
            case Message.Bye b when current == State.WAIT_BYE -> {
                current = State.DONE;
                yield List.of();
            }
            default -> throw core.fail(ShareException.Code.PROTOCOL);
        };
    }

    /** The user accepted the offer. */
    public List<Message> accept() {
        require(current == State.OFFERED);
        current = State.WAIT_DATA;
        return List.of(new Message.ShareAccept(core.nextSeq(), shown.shareId()));
    }

    /** The user declined the offer. */
    public List<Message> decline() {
        require(current == State.OFFERED);
        current = State.ENDED;
        return List.of(new Message.Bye(core.nextSeq()));
    }

    /**
     * Reports whether the payload was validated and applied atomically. On {@code false} nothing
     * may have been applied.
     */
    public List<Message> applied(boolean ok) {
        require(current == State.VALIDATING);
        data.wipe();
        Message ack = new Message.ShareAck(core.nextSeq(), shown.shareId(), ok);
        if (ok) {
            seen.add(shown.shareId());
            current = State.WAIT_BYE;
            return List.of(ack);
        }
        current = State.ENDED;
        return List.of(ack, new Message.ErrorReport(core.nextSeq(), ShareException.Code.NOT_APPLIED.wire()));
    }

    private void require(boolean ok) {
        if (!ok) {
            throw new IllegalStateException(current.name());
        }
    }
}
