package pm.sharing.pair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLServerSocket;
import org.junit.jupiter.api.Test;
import pm.crypto.CryptoException;
import pm.crypto.DeviceIdentity;
import pm.crypto.Tls;
import pm.sharing.net.Lan;
import pm.sharing.net.PeerLink;
import pm.sharing.pair.PairingException.Code;
import pm.sharing.wire.Message;
import pm.sharing.wire.WireException;

/** The ceremony end to end over real loopback TLS 1.3 sockets; Bob's side runs on a second thread. */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: one executor plays the peer device
class PairerTest {
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
    private static final long WAIT_SECONDS = 30;

    /** What Bob does with an accepted, authenticated link. */
    @FunctionalInterface
    private interface BobSide {
        Object run(DeviceIdentity bob, PeerLink link) throws IOException, PairingException, WireException;
    }

    /** What Alice does with her link; returns her outcome. */
    @FunctionalInterface
    private interface AliceSide<T> {
        T run(DeviceIdentity alice, PeerLink link) throws IOException, PairingException, WireException;
    }

    private record Outcome<T>(T alice, Object bob, Throwable bobFailure) {}

    /** Bob listens with a pairing-mode pin; Alice connects; both sides run; Bob's result is collected. */
    private static <T> Outcome<T> exchange(BobSide bob, AliceSide<T> alice)
            throws CryptoException, IOException, PairingException, WireException, InterruptedException,
            TimeoutException {
        try (DeviceIdentity a = DeviceIdentity.generate(NOW); DeviceIdentity b = DeviceIdentity.generate(NOW);
                SSLServerSocket server = Lan.listen(b, k -> true, CLOCK, LOOPBACK);
                ExecutorService pool = Executors.newSingleThreadExecutor()) {
            Callable<Object> bobTask = () -> {
                try (PeerLink link = Lan.accept(server)) {
                    return bob.run(b, link);
                }
            };
            Future<Object> bobResult = pool.submit(bobTask);
            T aliceResult;
            try (PeerLink link = Lan.connect(a, k -> true, CLOCK, address(server))) {
                aliceResult = alice.run(a, link);
            }
            try {
                return new Outcome<>(aliceResult, bobResult.get(WAIT_SECONDS, TimeUnit.SECONDS), null);
            } catch (ExecutionException e) {
                return new Outcome<>(aliceResult, null, e.getCause());
            }
        }
    }

    private static Object respond(DeviceIdentity bob, PeerLink link, Lockout lockout, SasPrompt prompt)
            throws IOException, PairingException {
        try (PairingSession s = PairingSession.of(PairingSession.Role.RESPONDER, bob.publicKey(), link.peerKey(),
                "bob")) {
            return new Pairer(lockout, CLOCK).run(link, s, prompt);
        }
    }

    private static PairedDevice initiate(DeviceIdentity alice, PeerLink link, Lockout lockout, SasPrompt prompt)
            throws IOException, PairingException {
        try (PairingSession s = PairingSession.of(PairingSession.Role.INITIATOR, alice.publicKey(), link.peerKey(),
                "alice")) {
            return new Pairer(lockout, CLOCK).run(link, s, prompt);
        }
    }

    @Test
    void twoDevicesPairOverLoopbackAndAgreeOnTheDigits() throws CryptoException, IOException, PairingException, WireException, InterruptedException,
            TimeoutException {
        AtomicReference<String> bobSaw = new AtomicReference<>();
        AtomicReference<String> aliceSaw = new AtomicReference<>();
        AtomicReference<byte[]> bobKey = new AtomicReference<>();
        AtomicReference<byte[]> aliceKey = new AtomicReference<>();
        Outcome<PairedDevice> o = exchange((b, link) -> {
            bobKey.set(b.publicKey());
            return respond(b, link, new Lockout(), (sas, name, fp) -> {
                bobSaw.set(sas);
                return "alice".equals(name);
            });
        }, (a, link) -> {
            aliceKey.set(a.publicKey());
            return initiate(a, link, new Lockout(), (sas, name, fp) -> {
                aliceSaw.set(sas);
                return "bob".equals(name) && fp.equals(DeviceIdentity.fingerprint(link.peerKey()));
            });
        });
        assertEquals(null, o.bobFailure());
        assertEquals(aliceSaw.get(), bobSaw.get());
        assertArrayEquals(bobKey.get(), o.alice().publicKey().toByteArray());
        PairedDevice alice = (PairedDevice) o.bob();
        assertArrayEquals(aliceKey.get(), alice.publicKey().toByteArray());
        assertEquals("alice", alice.name());
    }

    @Test
    void failuresAreCountedAndTheThirdLocksPairing() throws CryptoException, IOException, PairingException, WireException, InterruptedException,
            TimeoutException {
        Lockout lockout = new Lockout();
        // Alice says the digits match; Bob says they differ and hangs up with BYE.
        for (int i = 0; i < 3; i++) {
            assertEquals(Code.PEER_ABORTED, aliceFailure(lockout, false, true));
        }
        assertFalse(lockout.allows(NOW));
        assertEquals(Lockout.FIRST, lockout.remaining(NOW));
        assertEquals(Code.LOCKED, aliceFailure(lockout, true, true));
        assertEquals(Lockout.FIRST, lockout.remaining(NOW));
    }

    @Test
    void theLocalUserSayingNoIsRejected() throws CryptoException, IOException, PairingException, WireException, InterruptedException,
            TimeoutException {
        assertEquals(Code.REJECTED, aliceFailure(new Lockout(), true, false));
    }

    private static Code aliceFailure(Lockout lockout, boolean bobMatches, boolean aliceMatches) throws CryptoException, IOException, PairingException, WireException, InterruptedException,
            TimeoutException {
        return exchange((b, link) -> respond(b, link, new Lockout(), (sas, name, fp) -> bobMatches),
                (a, link) -> assertThrows(PairingException.class,
                        () -> initiate(a, link, lockout, (sas, name, fp) -> aliceMatches)).code()).alice();
    }

    @Test
    void anOutOfTurnMessageIsAProtocolFailureAndTheStreamThenEnds() throws CryptoException, IOException, PairingException, WireException, InterruptedException,
            TimeoutException {
        Lockout lockout = new Lockout();
        Outcome<Code> o = exchange((b, link) -> {
            readOpening(link);
            link.send(List.of(new Message.Bye(5)));
            return null;
        }, (a, link) -> {
            Code code = assertThrows(PairingException.class,
                    () -> initiate(a, link, lockout, (sas, name, fp) -> true)).code();
            assertThrows(WireException.class, link::receive);
            return code;
        });
        assertEquals(Code.PROTOCOL, o.alice());
        assertCountedOnce(lockout);
    }

    @Test
    void aConnectionClosedMidCeremonyIsCounted() throws CryptoException, IOException, PairingException, WireException, InterruptedException,
            TimeoutException {
        Lockout lockout = new Lockout();
        Outcome<Code> o = exchange((b, link) -> {
            readOpening(link);
            return null;
        },
                (a, link) -> assertThrows(PairingException.class,
                        () -> initiate(a, link, lockout, (sas, name, fp) -> true)).code());
        assertEquals(Code.PROTOCOL, o.alice());
        assertCountedOnce(lockout);
    }

    @Test
    void aLinkCanChangeItsReadTimeout() throws CryptoException, IOException, PairingException, WireException, InterruptedException,
            TimeoutException {
        Outcome<Message> o = exchange((b, link) -> {
            link.send(List.of(new Message.PairDone(0)));
            return null;
        }, (a, link) -> {
            link.readTimeout(Pairer.CONFIRM_TIMEOUT);
            return link.receive();
        });
        assertEquals(new Message.PairDone(0), o.alice());
    }

    @Test
    void anUnpinnedClientIsRefusedByTheListener() throws CryptoException, IOException, PairingException, WireException, InterruptedException,
            TimeoutException {
        try (DeviceIdentity a = DeviceIdentity.generate(NOW); DeviceIdentity b = DeviceIdentity.generate(NOW);
                DeviceIdentity mallory = DeviceIdentity.generate(NOW);
                SSLServerSocket server = Lan.listen(b, Tls.pinnedTo(a.publicKey()), CLOCK, LOOPBACK);
                ExecutorService pool = Executors.newSingleThreadExecutor()) {
            Callable<PeerLink> accept = () -> Lan.accept(server);
            Future<PeerLink> bobSide = pool.submit(accept);
            assertThrows(IOException.class, () -> {
                try (PeerLink link = Lan.connect(mallory, k -> true, CLOCK, address(server))) {
                    link.receive();
                }
            });
            ExecutionException refused = assertThrows(ExecutionException.class,
                    () -> bobSide.get(WAIT_SECONDS, TimeUnit.SECONDS));
            assertTrue(refused.getCause() instanceof IOException, refused.toString());
        }
    }

    @Test
    void aClientRefusesAServerItDoesNotPin() throws CryptoException, IOException, PairingException, WireException, InterruptedException,
            TimeoutException {
        try (DeviceIdentity a = DeviceIdentity.generate(NOW); DeviceIdentity b = DeviceIdentity.generate(NOW);
                SSLServerSocket server = Lan.listen(b, k -> true, CLOCK, LOOPBACK);
                ExecutorService pool = Executors.newSingleThreadExecutor()) {
            Callable<PeerLink> accept = () -> Lan.accept(server);
            Future<PeerLink> bobSide = pool.submit(accept);
            assertThrows(IOException.class, () -> Lan.connect(a, Tls.pinnedTo(a.publicKey()), CLOCK,
                    address(server)).close());
            assertThrows(ExecutionException.class, () -> bobSide.get(WAIT_SECONDS, TimeUnit.SECONDS));
        }
    }

    /** Reads the initiator's HELLO, PAIR_REQ and PAIR_COMMIT, so a hang-up cannot race its writes. */
    private static void readOpening(PeerLink link) throws IOException, WireException {
        for (int i = 0; i < 3; i++) {
            link.receive();
        }
    }

    /** Exactly one failure was counted: two more lock, one more would not have. */
    private static void assertCountedOnce(Lockout lockout) {
        assertTrue(lockout.allows(NOW));
        lockout.failed(NOW);
        assertTrue(lockout.allows(NOW));
        lockout.failed(NOW);
        assertFalse(lockout.allows(NOW));
    }

    private static InetSocketAddress address(SSLServerSocket server) {
        return new InetSocketAddress(LOOPBACK, server.getLocalPort());
    }
}
