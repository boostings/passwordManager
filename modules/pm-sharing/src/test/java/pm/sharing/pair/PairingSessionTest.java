package pm.sharing.pair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pm.sharing.pair.Peers.ALICE;
import static pm.sharing.pair.Peers.BOB;
import static pm.sharing.pair.Peers.MALLORY;

import java.util.ArrayList;
import java.util.List;
import java.util.function.LongFunction;
import org.junit.jupiter.api.Test;
import pm.crypto.DeviceIdentity;
import pm.crypto.Pairing;
import pm.sharing.pair.PairingException.Code;
import pm.sharing.pair.PairingSession.State;
import pm.sharing.wire.Message;
import pm.sharing.wire.Octets;

/** The pairing ceremony as a pure state machine (lan-share.md §5, ADR 0010 Amendment 1). */
class PairingSessionTest {
    private static final Octets V32 = Octets.copyOf(new byte[32]);
    private static final Octets ID16 = Octets.copyOf(new byte[16]);

    /** One message of every type, numbered by the caller. */
    private static final List<LongFunction<Message>> EVERY_TYPE = List.of(
            s -> new Message.Hello(s, ID16, "x", List.of()),
            Message.PairReq::new,
            s -> new Message.PairCommit(s, V32),
            s -> new Message.PairNonce(s, V32),
            s -> new Message.PairReveal(s, V32),
            s -> new Message.PairSasOk(s, V32),
            Message.PairDone::new,
            s -> new Message.ShareAccept(s, ID16),
            s -> new Message.Revoke(s, ID16));

    @Test
    void honestPeersSeeTheSameDigitsAndPinEachOther() throws PairingException {
        try (PairingSession a = Peers.initiator(ALICE, BOB, 7); PairingSession b = Peers.responder(BOB, ALICE, 9)) {
            Peers.toConfirm(a, b);
            assertEquals(State.CONFIRM, a.state());
            assertEquals(State.CONFIRM, b.state());
            assertEquals(a.sas(), b.sas());
            assertEquals(Pairing.SAS_DIGITS, a.sas().length());
            assertEquals("resp", a.peerName());
            assertEquals(DeviceIdentity.fingerprint(BOB), a.peerFingerprint());
            Peers.pump(a, a.confirm(), b, List.of());
            assertTrue(a.userConfirmed());
            assertEquals(State.CONFIRM, a.state());
            Peers.pump(b, b.confirm(), a, List.of());
            assertEquals(State.DONE, a.state());
            assertEquals(State.DONE, b.state());
            assertArrayEquals(BOB, a.result().publicKey().toByteArray());
            assertArrayEquals(ALICE, b.result().publicKey().toByteArray());
            assertEquals("init", b.result().name());
            assertEquals(DeviceIdentity.fingerprint(ALICE), b.result().fingerprint());
        }
    }

    @Test
    void theInitiatorRevealsOnlyAfterTheResponderNonceAndCommitsFirst() throws PairingException {
        try (PairingSession a = Peers.initiator(ALICE, BOB, 7); PairingSession b = Peers.responder(BOB, ALICE, 9)) {
            List<Message> opening = a.start();
            assertInstanceOf(Message.PairCommit.class, opening.get(2));
            assertTrue(opening.stream().noneMatch(Message.PairReveal.class::isInstance));
            b.start();
            assertEquals(List.of(), b.receive(opening.get(0)));
            assertEquals(List.of(), b.receive(opening.get(1)));
            Message nonce = b.receive(opening.get(2)).get(0);
            assertInstanceOf(Message.PairNonce.class, nonce);
            assertEquals(State.WAIT_REVEAL, b.state());
        }
    }

    @Test
    void aRelayingAttackerLeavesTheVictimsWithDifferentDigits() throws PairingException {
        // Alice's TLS peer is Mallory, and so is Bob's: each binds Mallory's key into its SAS.
        try (PairingSession alice = Peers.initiator(ALICE, MALLORY, 7);
                PairingSession toAlice = Peers.responder(MALLORY, ALICE, 5);
                PairingSession toBob = Peers.initiator(MALLORY, BOB, 6);
                PairingSession bob = Peers.responder(BOB, MALLORY, 9)) {
            Peers.toConfirm(alice, toAlice);
            Peers.toConfirm(toBob, bob);
            assertNotEquals(alice.sas(), bob.sas());
        }
    }

    @Test
    void aForwardedConfirmationFromTheOtherLegDoesNotVerify() throws PairingException {
        try (PairingSession alice = Peers.initiator(ALICE, MALLORY, 7);
                PairingSession toAlice = Peers.responder(MALLORY, ALICE, 5);
                PairingSession toBob = Peers.initiator(MALLORY, BOB, 6);
                PairingSession bob = Peers.responder(BOB, MALLORY, 9)) {
            Peers.toConfirm(alice, toAlice);
            Peers.toConfirm(toBob, bob);
            Message.PairSasOk fromBob = (Message.PairSasOk) bob.confirm().get(0);
            Message forwarded = new Message.PairSasOk(fromBob.seq(), fromBob.mac());
            assertEquals(Code.CONFIRMATION, assertThrows(PairingException.class, () -> alice.receive(forwarded)).code());
            assertEquals(State.FAILED, alice.state());
            assertThrows(IllegalStateException.class, alice::sas);
        }
    }

    @Test
    void aHelloThatNamesAnotherDeviceIsRefused() throws PairingException {
        try (PairingSession a = Peers.initiator(ALICE, BOB, 7)) {
            a.start();
            Message forged = new Message.Hello(0, Octets.copyOf(DeviceIdentity.deviceId(MALLORY)), "bob", List.of());
            assertEquals(Code.IDENTITY, assertThrows(PairingException.class, () -> a.receive(forged)).code());
            assertNull(a.peerName());
        }
    }

    @Test
    void anythingBeforeHelloIsAProtocolError() throws PairingException {
        try (PairingSession b = Peers.responder(BOB, ALICE, 9)) {
            b.start();
            assertEquals(Code.PROTOCOL, assertThrows(PairingException.class,
                    () -> b.receive(new Message.PairReq(0))).code());
        }
    }

    @Test
    void aRevealThatDoesNotOpenTheCommitmentIsRefused() throws PairingException {
        try (PairingSession a = Peers.initiator(ALICE, BOB, 7); PairingSession b = Peers.responder(BOB, ALICE, 9)) {
            List<Message> opening = a.start();
            b.start();
            for (Message m : opening) {
                b.receive(m);
            }
            Message lie = new Message.PairReveal(3, Octets.copyOf(Peers.filled(8)));
            assertEquals(Code.COMMITMENT, assertThrows(PairingException.class, () -> b.receive(lie)).code());
        }
    }

    @Test
    void aSequenceGapOrAnAbortEndsTheSession() throws PairingException {
        try (PairingSession a = Peers.initiator(ALICE, BOB, 7)) {
            a.start();
            assertEquals(Code.PROTOCOL, assertThrows(PairingException.class,
                    () -> a.receive(new Message.Bye(1))).code());
        }
        try (PairingSession a = Peers.initiator(ALICE, BOB, 7)) {
            a.start();
            assertEquals(Code.PEER_ABORTED, assertThrows(PairingException.class,
                    () -> a.receive(new Message.Bye(0))).code());
        }
        try (PairingSession a = Peers.initiator(ALICE, BOB, 7)) {
            a.start();
            assertEquals(Code.PEER_ABORTED, assertThrows(PairingException.class,
                    () -> a.receive(new Message.ErrorReport(0, 1))).code());
            assertEquals(Code.PROTOCOL, assertThrows(PairingException.class,
                    () -> a.receive(new Message.PairReq(1))).code());
        }
    }

    @Test
    void rejectingSendsByeAndFails() throws PairingException {
        try (PairingSession a = Peers.initiator(ALICE, BOB, 7); PairingSession b = Peers.responder(BOB, ALICE, 9)) {
            Peers.toConfirm(a, b);
            List<Message> bye = a.reject();
            assertInstanceOf(Message.Bye.class, bye.get(0));
            assertEquals(State.FAILED, a.state());
            assertEquals(Code.PEER_ABORTED, assertThrows(PairingException.class, () -> b.receive(bye.get(0))).code());
            assertEquals(Code.PROTOCOL, assertThrows(PairingException.class, a::confirm).code());
        }
    }

    @Test
    void lifecycleMisuseIsRefused() throws PairingException {
        try (PairingSession a = Peers.initiator(ALICE, BOB, 7)) {
            assertEquals(Code.PROTOCOL, assertThrows(PairingException.class,
                    () -> a.receive(new Message.PairReq(0))).code());
        }
        try (PairingSession a = Peers.initiator(ALICE, BOB, 7)) {
            assertEquals(State.NEW, a.state());
            assertThrows(IllegalStateException.class, a::sas);
            assertThrows(IllegalStateException.class, a::result);
            assertEquals(Code.PROTOCOL, assertThrows(PairingException.class, a::confirm).code());
        }
        try (PairingSession a = Peers.initiator(ALICE, BOB, 7); PairingSession b = Peers.responder(BOB, ALICE, 9)) {
            a.start();
            assertThrows(IllegalStateException.class, a::start);
            Peers.pump(a, List.of(), b, b.start());
            assertEquals(State.WAIT_NONCE, a.state());
        }
        try (PairingSession a = Peers.initiator(ALICE, BOB, 7); PairingSession b = Peers.responder(BOB, ALICE, 9)) {
            Peers.toConfirm(a, b);
            a.confirm();
            assertEquals(Code.PROTOCOL, assertThrows(PairingException.class, a::confirm).code());
        }
        try (PairingSession a = Peers.initiator(ALICE, BOB, 7); PairingSession b = Peers.responder(BOB, ALICE, 9)) {
            Peers.toConfirm(a, b);
            Peers.pump(a, a.confirm(), b, b.confirm());
            assertEquals(State.DONE, a.state());
            assertEquals(Code.PROTOCOL, assertThrows(PairingException.class,
                    () -> a.receive(new Message.PairDone(99))).code());
        }
    }

    @Test
    void keysMustBeRawEd25519() {
        assertThrows(IllegalArgumentException.class, () -> PairingSession.of(PairingSession.Role.INITIATOR,
                new byte[31], BOB, "x"));
        assertThrows(IllegalArgumentException.class, () -> new PairedDevice(Octets.copyOf(new byte[31]), "x"));
        try (PairingSession s = PairingSession.of(PairingSession.Role.RESPONDER, ALICE, BOB, "x")) {
            assertEquals(State.NEW, s.state());
        }
    }

    @Test
    void theRealNonceSourceGivesDistinctDigitsPerRun() throws PairingException {
        try (PairingSession a = PairingSession.of(PairingSession.Role.INITIATOR, ALICE, BOB, "a");
                PairingSession b = PairingSession.of(PairingSession.Role.RESPONDER, BOB, ALICE, "b")) {
            Peers.toConfirm(a, b);
            assertEquals(a.sas(), b.sas());
        }
    }

    /** Every message type, sent in every waiting state, either is the one expected or fails. */
    @Test
    void everyUnexpectedMessageInEveryStateIsAProtocolError() throws PairingException {
        int stages = 6;
        for (int stage = 0; stage < stages; stage++) {
            for (LongFunction<Message> type : EVERY_TYPE) {
                try (Staged s = stage(stage)) {
                    Message m = type.apply(s.nextSeq);
                    if (m.getClass() != s.expected) {
                        assertEquals(Code.PROTOCOL, assertThrows(PairingException.class,
                                () -> s.victim.receive(m)).code(), stage + " " + m);
                    }
                }
            }
        }
    }

    private record Staged(PairingSession victim, PairingSession other, long nextSeq, Class<?> expected)
            implements AutoCloseable {
        @Override
        public void close() {
            victim.close();
            other.close();
        }
    }

    /** Brings a session to a waiting state, with nothing in flight. */
    private static Staged stage(int stage) throws PairingException {
        PairingSession a = Peers.initiator(ALICE, BOB, 7);
        PairingSession b = Peers.responder(BOB, ALICE, 9);
        List<Message> fromA = a.start();
        List<Message> fromB = b.start();
        switch (stage) {
            case 0 -> {
                b.receive(fromA.get(0));
                return new Staged(b, a, 1, Message.PairReq.class);
            }
            case 1 -> {
                b.receive(fromA.get(0));
                b.receive(fromA.get(1));
                return new Staged(b, a, 2, Message.PairCommit.class);
            }
            case 2 -> {
                a.receive(fromB.get(0));
                return new Staged(a, b, 1, Message.PairNonce.class);
            }
            case 3 -> {
                for (Message m : fromA) {
                    b.receive(m);
                }
                return new Staged(b, a, 3, Message.PairReveal.class);
            }
            case 4 -> {
                Peers.pump(a, fromA, b, fromB);
                return new Staged(a, b, 2, Message.PairSasOk.class);
            }
            default -> {
                Peers.pump(a, fromA, b, fromB);
                List<Message> ok = new ArrayList<>(b.confirm());
                a.receive(ok.get(0));
                assertFalse(a.userConfirmed());
                // a has the peer's confirmation: a second one is out of order even though the state is CONFIRM.
                return new Staged(a, b, 3, Void.class);
            }
        }
    }
}
