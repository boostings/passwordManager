package pm.sharing.share;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Predicate;
import javax.net.ssl.SSLServerSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.crypto.CryptoException;
import pm.crypto.DeviceIdentity;
import pm.sharing.net.Lan;
import pm.sharing.net.PeerLink;
import pm.sharing.share.ShareException.Code;
import pm.sharing.wire.Message;
import pm.sharing.wire.Octets;
import pm.sharing.wire.WireException;

/** The sender's listener over real loopback TLS: lifetime, pinning, revocation (SR-205, SR-207). */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: one executor plays a misbehaving sender
@Tag("T-LAN-05")
@Tag("T-LAN-06")
@Tag("T-LAN-07")
class ShareServerTest {
    private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
    private static final Duration WAIT = Duration.ofSeconds(20);
    private static final byte[] RECORDS = {(byte) 0xa0};

    private final MutableClock clock = new MutableClock(SharesTest.T0);
    private final Shares shares = new Shares();
    private final BlockingQueue<String> events = new LinkedBlockingQueue<>();
    private DeviceIdentity alice;
    private DeviceIdentity bob;
    private DeviceIdentity carol;

    private final ShareEvents recorder = new ShareEvents() {
        @Override
        public void delivered(Share share) {
            events.add("delivered " + share.summary());
        }

        @Override
        public void failed(Share share, Code code) {
            events.add("failed " + (share == null ? "-" : share.summary()) + " " + code);
        }

        @Override
        public void refused() {
            events.add("refused");
        }

        @Override
        public void closed() {
            events.add("closed");
        }
    };

    @BeforeEach
    void identities() throws CryptoException {
        alice = DeviceIdentity.generate(SharesTest.T0);
        bob = DeviceIdentity.generate(SharesTest.T0);
        carol = DeviceIdentity.generate(SharesTest.T0);
    }

    @AfterEach
    void wipe() {
        alice.close();
        bob.close();
        carol.close();
    }

    private Share offerTo(DeviceIdentity target, boolean oneUse) {
        return shares.open(target.publicKey(), Message.Kind.SECRET, "1 secret: db", RECORDS, Shares.DEFAULT_TTL,
                oneUse, clock.instant());
    }

    private ShareServer listen(Predicate<byte[]> trusted) throws IOException, CryptoException {
        return ShareServer.open(alice, "alice", trusted, shares, clock, LOOPBACK, recorder);
    }

    private ShareServer listen() throws IOException, CryptoException {
        return listen(k -> true);
    }

    private PeerLink connect(DeviceIdentity who, ShareServer server) throws IOException, CryptoException {
        return Lan.connect(who, k -> true, clock, new InetSocketAddress(LOOPBACK, server.port()));
    }

    private Message.ShareOffer receive(DeviceIdentity who, ShareServer server, ReceivedShares seen, boolean accept,
            boolean apply) throws IOException, CryptoException, ShareException {
        try (PeerLink link = connect(who, server)) {
            ReceiveSession s = new ReceiveSession(who.publicKey(), link.peerKey(), "bob", seen, clock);
            return ShareClient.receive(link, s, (offer, fp) -> {
                assertEquals(DeviceIdentity.fingerprint(alice.publicKey()), fp);
                return accept;
            }, (kind, payload) -> {
                assertArrayEquals(RECORDS, payload);
                return apply;
            });
        }
    }

    private String nextEvent() throws InterruptedException {
        String e = events.poll(WAIT.toSeconds(), TimeUnit.SECONDS);
        assertTrue(e != null, "no event");
        return e;
    }

    private void assertPortClosed(int port) {
        assertThrows(ConnectException.class,
                () -> Lan.connect(bob, k -> true, clock, new InetSocketAddress(LOOPBACK, port)).close());
    }

    @Test
    void aOneUseShareIsDeliveredThenTheListenerClosesAndFreesThePort()
            throws IOException, CryptoException, ShareException, InterruptedException {
        offerTo(bob, true);
        try (ShareServer server = listen()) {
            assertTrue(server.isOpen());
            Message.ShareOffer got = receive(bob, server, new ReceivedShares(), true, true);
            assertEquals("1 secret: db", got.summary());
            assertEquals("delivered 1 secret: db", nextEvent());
            assertEquals("closed", nextEvent());
            assertTrue(server.awaitClosed(WAIT));
            assertFalse(server.isOpen());
            assertPortClosed(server.port());
        }
    }

    @Test
    void theListenerClosesWhenTheLastWindowExpires() throws IOException, CryptoException, InterruptedException {
        offerTo(bob, false);
        try (ShareServer server = listen()) {
            assertFalse(server.awaitClosed(ShareServer.POLL.multipliedBy(3)));
            clock.advance(Shares.DEFAULT_TTL);
            assertTrue(server.awaitClosed(WAIT));
            assertEquals("closed", nextEvent());
            assertPortClosed(server.port());
        }
    }

    @Test
    void aRevokedOrUntrustedOrUnofferedDeviceFailsTheHandshake()
            throws IOException, CryptoException, InterruptedException {
        offerTo(bob, false);
        offerTo(carol, false);
        byte[] carolKey = carol.publicKey();
        try (ShareServer server = listen(k -> !pm.crypto.ConstantTime.equals(k, carolKey))) {
            assertThrows(IOException.class, () -> receive(carol, server, new ReceivedShares(), true, true));
            assertEquals("refused", nextEvent());
            shares.revokeDevice(bob.publicKey());
            assertThrows(IOException.class, () -> receive(bob, server, new ReceivedShares(), true, true));
            assertEquals("refused", nextEvent());
            try (DeviceIdentity dave = DeviceIdentity.generate(SharesTest.T0)) {
                assertThrows(IOException.class, () -> receive(dave, server, new ReceivedShares(), true, true));
            }
            assertEquals("refused", nextEvent());
            assertTrue(server.isOpen());
        }
        assertEquals("closed", nextEvent());
    }

    @Test
    void decliningLeavesTheWindowOpenAndAFailedApplyConsumesIt()
            throws IOException, CryptoException, InterruptedException {
        offerTo(bob, true);
        try (ShareServer server = listen()) {
            assertEquals(Code.DECLINED, assertThrows(ShareException.class,
                    () -> receive(bob, server, new ReceivedShares(), false, true)).code());
            assertEquals("failed 1 secret: db DECLINED", nextEvent());
            assertTrue(server.isOpen());
            assertEquals(Code.NOT_APPLIED, assertThrows(ShareException.class,
                    () -> receive(bob, server, new ReceivedShares(), true, false)).code());
            assertEquals("failed 1 secret: db NOT_APPLIED", nextEvent());
            assertTrue(server.awaitClosed(WAIT));
        }
    }

    @Test
    void aReusableShareReceivedTwiceIsAReplayOnTheSecondTime()
            throws IOException, CryptoException, ShareException, InterruptedException {
        offerTo(bob, false);
        ReceivedShares seen = new ReceivedShares();
        ShareServer server = listen();
        try (server) {
            receive(bob, server, seen, true, true);
            assertEquals("delivered 1 secret: db", nextEvent());
            assertEquals(Code.REPLAY, assertThrows(ShareException.class,
                    () -> receive(bob, server, seen, true, true)).code());
            assertEquals("failed 1 secret: db REPLAY", nextEvent());
        }
        // Closing the listener early ends it even though the reusable window is still open.
        assertFalse(server.isOpen());
        assertTrue(shares.anyOpen(clock.instant()));
    }

    @Test
    void aWindowThatClosesAfterTheHandshakeGetsBye()
            throws IOException, CryptoException, ShareException, InterruptedException, WireException {
        offerTo(bob, true);
        try (ShareServer server = listen(); PeerLink link = connect(bob, server)) {
            ReceiveSession s = new ReceiveSession(bob.publicKey(), link.peerKey(), "bob", new ReceivedShares(), clock);
            // Under TLS 1.3 the client finishes its handshake before the server has checked the
            // client's certificate, so revoke only once the server's Hello proves it accepted us;
            // a revoke before that fails the handshake instead (the test above).
            Message hello = link.receive();
            assertInstanceOf(Message.Hello.class, hello);
            shares.revokeDevice(bob.publicKey());
            link.send(s.start());
            link.send(s.receive(hello));
            Message bye = link.receive();
            assertEquals(Code.NOTHING_OFFERED, assertThrows(ShareException.class, () -> s.receive(bye)).code());
            assertTrue(server.awaitClosed(WAIT));
        }
        assertEquals("closed", nextEvent());
    }

    @Test
    void aReceiverThatHangsUpIsAProtocolFailure()
            throws IOException, CryptoException, InterruptedException, WireException {
        offerTo(bob, false);
        try (ShareServer server = listen()) {
            try (PeerLink link = connect(bob, server)) {
                assertInstanceOf(Message.Hello.class, link.receive());
            }
            assertEquals("failed - PROTOCOL", nextEvent());
        }
    }

    @Test
    void aSenderThatHangsUpIsAProtocolFailureForTheReceiver()
            throws IOException, CryptoException, InterruptedException, ExecutionException, TimeoutException {
        try (SSLServerSocket raw = Lan.listen(alice, k -> true, clock, LOOPBACK);
                ExecutorService pool = Executors.newSingleThreadExecutor()) {
            Callable<Boolean> hangUp = () -> {
                Lan.accept(raw).close();
                return true;
            };
            Future<Boolean> sender = pool.submit(hangUp);
            try (PeerLink link = Lan.connect(bob, k -> true, clock, new InetSocketAddress(LOOPBACK,
                    raw.getLocalPort()))) {
                ReceiveSession s = new ReceiveSession(bob.publicKey(), link.peerKey(), "bob", new ReceivedShares(),
                        clock);
                assertEquals(Code.PROTOCOL, assertThrows(ShareException.class,
                        () -> ShareClient.receive(link, s, (o, fp) -> true, (k, p) -> true)).code());
            }
            assertTrue(sender.get(WAIT.toSeconds(), TimeUnit.SECONDS));
        }
    }

    @Test
    void aMalformedOfferIdIsStillRefused() {
        assertThrows(IllegalArgumentException.class, () -> new Message.ShareAccept(0, Octets.copyOf(new byte[3])));
        assertEquals(List.of(), List.copyOf(events));
    }
}
