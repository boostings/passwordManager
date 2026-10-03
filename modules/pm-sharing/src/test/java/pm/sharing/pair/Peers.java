package pm.sharing.pair;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.function.Supplier;
import pm.sharing.wire.Message;

/** In-memory test fixtures: fixed keys, fixed nonces, and a message pump between two sessions. */
final class Peers {
    static final byte[] ALICE = filled(1);
    static final byte[] BOB = filled(2);
    static final byte[] MALLORY = filled(3);

    private Peers() {
    }

    static byte[] filled(int b) {
        byte[] k = new byte[32];
        Arrays.fill(k, (byte) b);
        return k;
    }

    static Supplier<byte[]> nonces(int b) {
        return () -> filled(b);
    }

    static PairingSession initiator(byte[] own, byte[] peer, int nonce) {
        return new PairingSession(PairingSession.Role.INITIATOR, own, peer, "init", nonces(nonce));
    }

    static PairingSession responder(byte[] own, byte[] peer, int nonce) {
        return new PairingSession(PairingSession.Role.RESPONDER, own, peer, "resp", nonces(nonce));
    }

    /** Delivers messages both ways until neither side has anything to send. */
    static void pump(PairingSession a, List<Message> fromA, PairingSession b, List<Message> fromB)
            throws PairingException {
        Deque<Message> toB = new ArrayDeque<>(fromA);
        Deque<Message> toA = new ArrayDeque<>(fromB);
        while (!toA.isEmpty() || !toB.isEmpty()) {
            if (!toB.isEmpty()) {
                toA.addAll(b.receive(toB.poll()));
            } else {
                toB.addAll(a.receive(toA.poll()));
            }
        }
    }

    /** Starts both sides and runs them to {@code CONFIRM}. */
    static void toConfirm(PairingSession initiator, PairingSession responder) throws PairingException {
        pump(initiator, initiator.start(), responder, responder.start());
    }
}
