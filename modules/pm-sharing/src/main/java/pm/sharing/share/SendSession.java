package pm.sharing.share;

import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import pm.sharing.wire.Message;

/**
 * The sender's side of one share connection (lan-share.md §6 steps 2–6), with no I/O:
 *
 * <pre>
 * start → HELLO                                     [WAIT_HELLO]
 * HELLO → SHARE_OFFER (oldest open window)          [WAIT_ACCEPT]
 *       → BYE (nothing for this device)             [DONE, nothing sent]
 * SHARE_ACCEPT(id) → claim → SHARE_DATA             [WAIT_ACK]
 * SHARE_ACK(id) → BYE                               [DONE]
 * </pre>
 *
 * BYE while waiting for the accept means the receiver declined. Any other message fails.
 */
public final class SendSession {
    /** Where the session is. */
    public enum State {
        /** {@link #start()} not yet called. */
        NEW,
        /** Waiting for the receiver's HELLO. */
        WAIT_HELLO,
        /** Offer sent. */
        WAIT_ACCEPT,
        /** Data sent. */
        WAIT_ACK,
        /** Finished; see {@link #delivered()}. */
        DONE
    }

    private final SessionCore core;
    private final Shares shares;
    private State current = State.NEW;
    private Share chosen;
    private boolean applied;

    /**
     * A sender session.
     *
     * @param peerKey the receiver's key, as TLS proved it
     */
    public SendSession(byte[] ownKey, byte[] peerKey, String ownName, Shares shares, Clock clock) {
        this.core = new SessionCore(ownKey, peerKey, ownName, clock);
        this.shares = Objects.requireNonNull(shares, "shares");
    }

    /** The current state. */
    public State state() {
        return current;
    }

    /** The share offered on this connection, once offered. */
    public Optional<Share> offered() {
        return Optional.ofNullable(chosen);
    }

    /** Whether the receiver acknowledged applying the data. */
    public boolean delivered() {
        return applied;
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

    /** HELLO. */
    public List<Message> start() {
        if (current != State.NEW || core.failed()) {
            throw new IllegalStateException(current.name());
        }
        current = State.WAIT_HELLO;
        return List.of(core.hello());
    }

    /**
     * Handles one message from the receiver.
     *
     * @throws ShareException the session failed; send {@link #abort} to tell the receiver
     */
    public List<Message> receive(Message m) throws ShareException {
        if (current == State.NEW || current == State.DONE) {
            throw core.fail(ShareException.Code.PROTOCOL);
        }
        if (!core.admit(m)) {
            return offer();
        }
        return switch (m) {
            case Message.ShareAccept a when current == State.WAIT_ACCEPT && a.shareId().equals(chosen.id()) -> {
                Share share = claim();
                current = State.WAIT_ACK;
                yield List.of(new Message.ShareData(core.nextSeq(), share.id(), share.payload()));
            }
            case Message.Bye b when current == State.WAIT_ACCEPT -> throw core.fail(ShareException.Code.DECLINED);
            case Message.ShareAck a when current == State.WAIT_ACK && a.shareId().equals(chosen.id()) -> {
                if (!a.applied()) {
                    throw core.fail(ShareException.Code.NOT_APPLIED);
                }
                applied = true;
                current = State.DONE;
                yield List.of(new Message.Bye(core.nextSeq()));
            }
            default -> throw core.fail(ShareException.Code.PROTOCOL);
        };
    }

    private Share claim() throws ShareException {
        try {
            return shares.claim(chosen.id(), core.peerKey, core.clock.instant());
        } catch (ShareException e) {
            throw core.fail(e.code());
        }
    }

    private List<Message> offer() {
        Optional<Share> share = shares.offerFor(core.peerKey, core.clock.instant());
        if (share.isEmpty()) {
            current = State.DONE;
            return List.of(new Message.Bye(core.nextSeq()));
        }
        chosen = share.get();
        current = State.WAIT_ACCEPT;
        return List.of(chosen.offer(core.nextSeq()));
    }
}
