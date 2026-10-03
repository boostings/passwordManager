package pm.sharing.pair;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;
import pm.crypto.DeviceIdentity;
import pm.crypto.Pairing;
import pm.crypto.SecretBytes;
import pm.sharing.wire.Message;
import pm.sharing.wire.Octets;
import pm.sharing.wire.Sequence;
import pm.sharing.wire.WireException;

/**
 * One side of the pairing ceremony (lan-share.md §5, ADR 0010 Amendment 1) as a state machine with
 * no I/O: {@link #start()}, {@link #receive}, {@link #confirm()} and {@link #reject()} return the
 * messages to send. The peer key is the one TLS authenticated, never anything a message says.
 *
 * <pre>
 * initiator: start → HELLO, PAIR_REQ, PAIR_COMMIT          [WAIT_NONCE]
 *            PAIR_NONCE → PAIR_REVEAL                       [CONFIRM]
 * responder: start → HELLO                                  [WAIT_REQ]
 *            PAIR_REQ                                       [WAIT_COMMIT]
 *            PAIR_COMMIT → PAIR_NONCE                       [WAIT_REVEAL]
 *            PAIR_REVEAL (must open the commitment)         [CONFIRM]
 * both:      user confirms → PAIR_SAS_OK; peer's PAIR_SAS_OK verified;
 *            when both → PAIR_DONE                          [WAIT_DONE]
 *            PAIR_DONE                                      [DONE]
 * </pre>
 *
 * Each side needs the peer's HELLO before any other message, and the HELLO's device id must be the
 * id of the TLS key. Anything else (a message the state does not expect, a sequence gap, BYE or
 * ERROR) ends the session in {@code FAILED}; a failed session refuses every further call. The
 * initiator reveals its nonce only after it holds the responder's, and the responder sends its
 * nonce only after it holds the commitment: that ordering is the defence against SAS grinding.
 * Not thread-safe.
 */
public final class PairingSession implements AutoCloseable {
    /** Which end of the TCP connection this side is. */
    public enum Role {
        /** Connected out and sends the commitment. */
        INITIATOR,
        /** Accepted the connection and sends its nonce in the clear. */
        RESPONDER
    }

    /** Where the ceremony is. */
    public enum State {
        /** {@link #start()} not yet called. */
        NEW,
        /** Responder: waiting for PAIR_REQ. */
        WAIT_REQ,
        /** Responder: waiting for PAIR_COMMIT. */
        WAIT_COMMIT,
        /** Initiator: waiting for PAIR_NONCE. */
        WAIT_NONCE,
        /** Responder: waiting for PAIR_REVEAL. */
        WAIT_REVEAL,
        /** The SAS is ready; waiting for the local user and the peer's confirmation. */
        CONFIRM,
        /** Both confirmations done; waiting for the peer's PAIR_DONE. */
        WAIT_DONE,
        /** Paired; {@link #result()} is available. */
        DONE,
        /** Ended; every further call is refused. */
        FAILED
    }

    private final Role role;
    private final byte[] ownKey;
    private final byte[] peerKey;
    private final String ownName;
    private final Supplier<byte[]> nonces;
    private final Sequence outgoing = new Sequence();
    private final Sequence incoming = new Sequence();
    private State current = State.NEW;
    private String peerLabel;
    private byte[] ownNonce;
    private byte[] peerCommit;
    private SecretBytes sasKey;
    private boolean localConfirmed;
    private boolean peerConfirmed;

    PairingSession(Role role, byte[] ownKey, byte[] peerKey, String ownName, Supplier<byte[]> nonces) {
        this.role = Objects.requireNonNull(role, "role");
        this.ownKey = key(ownKey);
        this.peerKey = key(peerKey);
        this.ownName = Objects.requireNonNull(ownName, "ownName");
        this.nonces = Objects.requireNonNull(nonces, "nonces");
    }

    /**
     * A session for this device in {@code role}.
     *
     * @param ownKey this device's raw public key
     * @param peerKey the peer's raw public key, from {@code Tls.peerPublicKey} of the handshake
     * @param ownName this device's name, sent in HELLO
     */
    public static PairingSession of(Role role, byte[] ownKey, byte[] peerKey, String ownName) {
        return new PairingSession(role, ownKey, peerKey, ownName, Pairing::nonce);
    }

    private static byte[] key(byte[] k) {
        if (Objects.requireNonNull(k, "key").length != DeviceIdentity.PUBLIC_KEY_BYTES) {
            throw new IllegalArgumentException("BAD_KEY");
        }
        return k.clone();
    }

    /** The current state. */
    public State state() {
        return current;
    }

    /** The first messages this side sends. */
    public List<Message> start() {
        require(State.NEW);
        List<Message> out = new ArrayList<>();
        out.add(new Message.Hello(outgoing.next(), Octets.copyOf(DeviceIdentity.deviceId(ownKey)), ownName,
                List.of("pair")));
        if (role == Role.INITIATOR) {
            ownNonce = nonces.get();
            out.add(new Message.PairReq(outgoing.next()));
            out.add(new Message.PairCommit(outgoing.next(), Octets.copyOf(Pairing.commitment(ownKey, ownNonce))));
            current = State.WAIT_NONCE;
        } else {
            current = State.WAIT_REQ;
        }
        return out;
    }

    /**
     * Handles one message from the peer and returns the replies.
     *
     * @throws PairingException the session is now {@code FAILED}
     */
    public List<Message> receive(Message m) throws PairingException {
        Objects.requireNonNull(m, "m");
        if (current == State.NEW || current == State.DONE || current == State.FAILED) {
            throw fail(PairingException.Code.PROTOCOL);
        }
        try {
            incoming.accept(m.seq());
        } catch (WireException e) {
            throw fail(PairingException.Code.PROTOCOL);
        }
        if (m instanceof Message.Bye || m instanceof Message.ErrorReport) {
            throw fail(PairingException.Code.PEER_ABORTED);
        }
        if (peerLabel == null) {
            return hello(m);
        }
        return switch (m) {
            case Message.PairReq r when current == State.WAIT_REQ -> {
                current = State.WAIT_COMMIT;
                yield List.of();
            }
            case Message.PairCommit c when current == State.WAIT_COMMIT -> {
                peerCommit = c.commit().toByteArray();
                ownNonce = nonces.get();
                current = State.WAIT_REVEAL;
                yield List.of(new Message.PairNonce(outgoing.next(), Octets.copyOf(ownNonce)));
            }
            case Message.PairNonce n when current == State.WAIT_NONCE -> {
                deriveSas(ownNonce, n.nonce().toByteArray());
                yield List.of(new Message.PairReveal(outgoing.next(), Octets.copyOf(ownNonce)));
            }
            case Message.PairReveal r when current == State.WAIT_REVEAL -> {
                byte[] revealed = r.nonce().toByteArray();
                if (!Pairing.opens(peerCommit, peerKey, revealed)) {
                    throw fail(PairingException.Code.COMMITMENT);
                }
                deriveSas(revealed, ownNonce);
                yield List.of();
            }
            case Message.PairSasOk s when current == State.CONFIRM && !peerConfirmed -> peerConfirmation(s);
            case Message.PairDone d when current == State.WAIT_DONE -> {
                current = State.DONE;
                yield List.of();
            }
            default -> throw fail(PairingException.Code.PROTOCOL);
        };
    }

    private List<Message> hello(Message m) throws PairingException {
        if (!(m instanceof Message.Hello h)) {
            throw fail(PairingException.Code.PROTOCOL);
        }
        if (!ConstantTime.equals(h.deviceId().toByteArray(), DeviceIdentity.deviceId(peerKey))) {
            throw fail(PairingException.Code.IDENTITY);
        }
        peerLabel = h.name();
        return List.of();
    }

    private void deriveSas(byte[] initiatorNonce, byte[] responderNonce) throws PairingException {
        try {
            sasKey = Pairing.sasKey(ownKey, peerKey, initiatorNonce, responderNonce);
        } catch (CryptoException e) {
            throw fail(PairingException.Code.PROTOCOL);
        }
        current = State.CONFIRM;
    }

    private List<Message> peerConfirmation(Message.PairSasOk s) throws PairingException {
        if (!verify(s.mac())) {
            throw fail(PairingException.Code.CONFIRMATION);
        }
        peerConfirmed = true;
        return finishIfBoth(new ArrayList<>());
    }

    private boolean verify(Octets mac) throws PairingException {
        try {
            return Pairing.confirms(sasKey, peerKey, mac.toByteArray());
        } catch (CryptoException e) {
            throw fail(PairingException.Code.PROTOCOL);
        }
    }

    private List<Message> finishIfBoth(List<Message> out) {
        if (localConfirmed && peerConfirmed) {
            out.add(new Message.PairDone(outgoing.next()));
            current = State.WAIT_DONE;
        }
        return out;
    }

    /** The six digits to show; available from {@code CONFIRM} on. */
    public String sas() {
        if (sasKey == null || current == State.FAILED) {
            throw new IllegalStateException(current.name());
        }
        return Pairing.sas(sasKey);
    }

    /** The peer's name from its HELLO, for display next to the SAS; null before HELLO. */
    public String peerName() {
        return peerLabel;
    }

    /** The peer's fingerprint, for display next to the SAS. */
    public String peerFingerprint() {
        return DeviceIdentity.fingerprint(peerKey);
    }

    /** Whether the local user has confirmed the digits. */
    public boolean userConfirmed() {
        return localConfirmed;
    }

    /**
     * The local user saw the same digits on both screens.
     *
     * @return PAIR_SAS_OK, and PAIR_DONE if the peer's confirmation already verified
     */
    public List<Message> confirm() throws PairingException {
        if (current != State.CONFIRM || localConfirmed) {
            throw fail(PairingException.Code.PROTOCOL);
        }
        localConfirmed = true;
        byte[] mac;
        try {
            mac = Pairing.confirmation(sasKey, ownKey);
        } catch (CryptoException e) {
            throw fail(PairingException.Code.PROTOCOL);
        }
        List<Message> out = new ArrayList<>();
        out.add(new Message.PairSasOk(outgoing.next(), Octets.copyOf(mac)));
        return finishIfBoth(out);
    }

    /**
     * The local user said the digits differ, or cancelled.
     *
     * @return BYE for the peer; the session is {@code FAILED}
     */
    public List<Message> reject() {
        Message bye = new Message.Bye(outgoing.next());
        fail(PairingException.Code.REJECTED);
        return List.of(bye);
    }

    /** The paired device; only in {@code DONE}. */
    public PairedDevice result() {
        require(State.DONE);
        return new PairedDevice(Octets.copyOf(peerKey), peerLabel);
    }

    private void require(State expected) {
        if (current != expected) {
            throw new IllegalStateException(current.name());
        }
    }

    private PairingException fail(PairingException.Code code) {
        current = State.FAILED;
        close();
        return new PairingException(code);
    }

    /** Wipes the SAS key. */
    @Override
    public void close() {
        if (sasKey != null) {
            sasKey.close();
        }
    }
}
