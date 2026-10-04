package pm.sharing.pair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.crypto.CryptoException;
import pm.crypto.DeviceIdentity;
import pm.crypto.Pairing;
import pm.crypto.SecretBytes;
import pm.fuzz.Script;
import pm.fuzz.Seeds;
import pm.sharing.pair.PairingSession.Role;
import pm.sharing.pair.PairingSession.State;
import pm.sharing.wire.Message;
import pm.sharing.wire.Octets;

/**
 * Fuzz harness for the pairing ceremony state machine (SR-201, SR-203, T-FUZZ-LAN). The input is a
 * script: which role the session under test plays, its nonce, then up to {@link #MAX_STEPS} steps,
 * each either a message from the peer's side of the TLS session (built from the peer key and a
 * nonce the script chose, or garbage, or a reflected or mis-bound value, under a correct or wrong
 * sequence number) or a local user action (confirm, reject).
 *
 * <p>The oracle: {@code receive} and {@code confirm} throw only {@link PairingException}, after
 * which the session is {@code FAILED} for good. The responder sends its nonce only after it holds
 * a commitment, the initiator reveals only after it holds the responder's nonce. And the session
 * reaches {@code DONE} only if the local user confirmed, the revealed nonce opens the accepted
 * commitment under the peer key (responder), and the accepted PAIR_SAS_OK is exactly the peer's
 * confirmation MAC under the SAS key of the nonces actually exchanged. That last check is
 * independent of the session: it recomputes the key with {@link Pairing}.
 *
 * <p>Lives in {@code pm.sharing.pair} so it can give the session a scripted nonce. Without
 * {@code JAZZER_FUZZ=1} the seeds in {@code PairingSessionFuzzTestInputs} are replayed.
 */
@Tag("T-FUZZ-LAN")
@Tag("T-LAN-02")
@Tag("T-LAN-03")
class PairingSessionFuzzTest {
    static final int MAX_STEPS = 48;
    private static final byte[] OWN = key(1);
    private static final byte[] PEER = key(2);
    private static final byte[] OTHER = key(3);
    private static final int STEP_KINDS = 4;
    private static final int MESSAGE_KINDS = 11;
    private static final int MAC_KINDS = 4;

    @FuzzTest
    void fuzz(byte[] in) {
        new Run(new Script(in)).play();
    }

    private static byte[] key(int fill) {
        byte[] k = new byte[DeviceIdentity.PUBLIC_KEY_BYTES];
        Arrays.fill(k, (byte) fill);
        return k;
    }

    /** One scripted ceremony and what the session accepted along the way. */
    static final class Run {
        private final Script s;
        private final Role role;
        private final byte[] ownNonce;
        private final PairingSession session;
        private byte[] peerNonce;
        private byte[] commit;
        private byte[] acceptedNonce;
        private byte[] acceptedMac;
        private boolean nonceSent;
        private boolean revealSent;
        private long nextIn;

        Run(Script s) {
            this.s = s;
            this.role = s.bit() ? Role.INITIATOR : Role.RESPONDER;
            this.ownNonce = s.filled(Pairing.NONCE_BYTES);
            this.peerNonce = s.filled(Pairing.NONCE_BYTES);
            this.session = new PairingSession(role, OWN, PEER, "own", ownNonce::clone);
        }

        State play() {
            try (session) {
                sent(session.start());
                for (int i = 0; i < MAX_STEPS && !s.done(); i++) {
                    if (!step()) {
                        break;
                    }
                    check();
                }
                if (session.state() == State.FAILED) {
                    assertThrows(PairingException.class, () -> session.receive(new Message.Bye(nextIn)));
                    assertThrows(PairingException.class, session::confirm);
                }
                return session.state();
            }
        }

        /** One scripted step; false once the session has failed. */
        private boolean step() {
            boolean wasFailed = session.state() == State.FAILED;
            try {
                switch (s.pick(STEP_KINDS)) {
                    case 0, 1 -> deliver(message());
                    case 2 -> sent(session.confirm());
                    default -> {
                        if (s.bit()) {
                            session.reject();
                        } else {
                            peerNonce = s.filled(Pairing.NONCE_BYTES);
                        }
                    }
                }
            } catch (PairingException e) {
                assertEquals(State.FAILED, session.state(), e.code().name());
            }
            assertTrue(!wasFailed || session.state() == State.FAILED, "left FAILED");
            return session.state() != State.FAILED;
        }

        private void deliver(Message m) throws PairingException {
            List<Message> replies = session.receive(m);
            nextIn++;
            switch (m) {
                case Message.PairCommit c -> commit = c.commit().toByteArray();
                case Message.PairNonce n -> acceptedNonce = n.nonce().toByteArray();
                case Message.PairReveal r -> acceptedNonce = r.nonce().toByteArray();
                case Message.PairSasOk ok -> acceptedMac = ok.mac().toByteArray();
                default -> {
                    // HELLO, PAIR_REQ and PAIR_DONE carry nothing the oracle needs
                }
            }
            sent(replies);
        }

        private void sent(List<Message> out) {
            for (Message m : out) {
                if (m instanceof Message.PairNonce) {
                    assertEquals(Role.RESPONDER, role);
                    assertNotNull(commit, "responder nonce before the commitment");
                    nonceSent = true;
                } else if (m instanceof Message.PairReveal) {
                    assertEquals(Role.INITIATOR, role);
                    assertNotNull(acceptedNonce, "initiator reveal before the responder nonce");
                    revealSent = true;
                }
            }
        }

        /** The next peer-side message, as the script describes it. */
        private Message message() {
            long seq = s.bit() ? nextIn : s.u8();
            return switch (s.pick(MESSAGE_KINDS)) {
                case 0 -> new Message.Hello(seq, Octets.copyOf(DeviceIdentity.deviceId(s.bit() ? PEER : OTHER)), "peer",
                        List.of("pair"));
                case 1 -> new Message.PairReq(seq);
                case 2 -> new Message.PairCommit(seq, Octets.copyOf(s.bit()
                        ? Pairing.commitment(s.bit() ? PEER : OTHER, peerNonce) : s.filled(Pairing.NONCE_BYTES)));
                case 3 -> new Message.PairNonce(seq, Octets.copyOf(peerNonce));
                case 4 -> new Message.PairReveal(seq, Octets.copyOf(peerNonce));
                case 5 -> new Message.PairSasOk(seq, Octets.copyOf(mac()));
                case 6 -> new Message.PairDone(seq);
                case 7 -> new Message.Bye(seq);
                case 8 -> new Message.ErrorReport(seq, s.u8());
                case 9 -> new Message.ShareAccept(seq, Octets.copyOf(s.filled(Message.SHARE_ID_BYTES)));
                default -> new Message.Revoke(seq, Octets.copyOf(s.filled(Message.DEVICE_ID_BYTES)));
            };
        }

        /** The peer's MAC from the peer's view of the nonces, a reflected or mis-keyed one, or garbage. */
        private byte[] mac() {
            int kind = s.pick(MAC_KINDS);
            if (kind == MAC_KINDS - 1) {
                return s.filled(Pairing.NONCE_BYTES);
            }
            byte[][] nonces = role == Role.INITIATOR ? new byte[][] {ownNonce, peerNonce}
                    : new byte[][] {peerNonce, ownNonce};
            byte[] signer = kind == 0 ? PEER : kind == 1 ? OWN : OTHER;
            return confirmation(nonces[0], nonces[1], signer);
        }

        private static byte[] confirmation(byte[] initiatorNonce, byte[] responderNonce, byte[] signer) {
            try (SecretBytes key = Pairing.sasKey(PEER, OWN, initiatorNonce, responderNonce)) {
                return Pairing.confirmation(key, signer);
            } catch (CryptoException e) {
                throw new AssertionError(e.code().name(), e);
            }
        }

        private void check() {
            if (session.state() != State.DONE) {
                assertThrows(IllegalStateException.class, session::result);
                return;
            }
            assertTrue(session.userConfirmed(), "DONE without the local user's confirmation");
            assertTrue(role == Role.INITIATOR ? revealSent : nonceSent, "DONE without the commit-reveal exchange");
            assertNotNull(acceptedNonce, "DONE without the peer's nonce");
            byte[] initiatorNonce = role == Role.INITIATOR ? ownNonce : acceptedNonce;
            byte[] responderNonce = role == Role.INITIATOR ? acceptedNonce : ownNonce;
            if (role == Role.RESPONDER) {
                assertTrue(Pairing.opens(commit, PEER, acceptedNonce), "DONE but the reveal does not open the commitment");
            }
            assertArrayEquals(confirmation(initiatorNonce, responderNonce, PEER), acceptedMac,
                    "DONE without the peer's confirmation MAC");
            try (SecretBytes key = Pairing.sasKey(OWN, PEER, initiatorNonce, responderNonce)) {
                assertEquals(Pairing.sas(key), session.sas());
            } catch (CryptoException e) {
                throw new AssertionError(e.code().name(), e);
            }
            assertArrayEquals(PEER, session.result().publicKey().toByteArray());
        }
    }

    /** What each seed does, and the state it must end in. */
    static Map<String, State> seedOutcomes() {
        return Map.of(
                "initiator-honest.bin", State.DONE,
                "responder-honest.bin", State.DONE,
                "responder-bad-reveal.bin", State.FAILED,
                "initiator-reflected-mac.bin", State.FAILED,
                "initiator-wrong-hello.bin", State.FAILED,
                "responder-sequence-gap.bin", State.FAILED);
    }

    /** The seeds reach the states their names say, so the DONE oracle is exercised, not vacuous. */
    @Test
    void seedsEndAsLabelled() throws IOException {
        for (Map.Entry<String, State> seed : seedOutcomes().entrySet()) {
            byte[] script = Seeds.read(PairingSessionFuzzTest.class, seed.getKey());
            assertEquals(seed.getValue(), new Run(new Script(script)).play(), seed.getKey());
        }
    }

    /** An empty script is a started session that is never answered. */
    @Test
    void emptyScriptLeavesTheResponderWaiting() {
        assertEquals(State.WAIT_REQ, new Run(new Script(new byte[0])).play());
    }
}
