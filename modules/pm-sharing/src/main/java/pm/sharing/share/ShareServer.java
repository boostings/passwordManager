package pm.sharing.share;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import javax.net.ssl.SSLServerSocket;
import pm.crypto.CryptoException;
import pm.crypto.DeviceIdentity;
import pm.sharing.net.Lan;
import pm.sharing.net.PeerLink;
import pm.sharing.wire.Message;
import pm.sharing.wire.WireException;

/**
 * The sender's listener (lan-share.md §6 step 2, step 7, SR-207). It accepts only a trusted device
 * that has an open window, serves one connection at a time, and closes itself, freeing the port, as
 * soon as no window is open: after the last one-use send, on expiry, or on revocation.
 */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: TPS00-J one-thread executor for the accept loop
public final class ShareServer implements AutoCloseable {
    /** How often the accept loop wakes to check for expiry. */
    static final Duration POLL = Duration.ofMillis(100);

    private final SSLServerSocket server;
    private final DeviceIdentity self;
    private final String name;
    private final Shares shares;
    private final Clock clock;
    private final ShareEvents events;
    private final ExecutorService loop = Executors.newSingleThreadExecutor();
    private final CountDownLatch done = new CountDownLatch(1);

    private ShareServer(SSLServerSocket server, DeviceIdentity self, String name, Shares shares, Clock clock,
            ShareEvents events) {
        this.server = server;
        this.self = self;
        this.name = name;
        this.shares = shares;
        this.clock = clock;
        this.events = events;
    }

    /**
     * Opens the listener on an ephemeral port of {@code address} and starts accepting.
     *
     * @param trusted the pinned devices; a peer must pass it and have an open window
     */
    public static ShareServer open(DeviceIdentity self, String name, Predicate<byte[]> trusted, Shares shares,
            Clock clock, InetAddress address, ShareEvents events) throws IOException, CryptoException {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(trusted, "trusted");
        Objects.requireNonNull(shares, "shares");
        Objects.requireNonNull(events, "events");
        Predicate<byte[]> pin = k -> trusted.test(k) && shares.offerFor(k, clock.instant()).isPresent();
        SSLServerSocket socket = Lan.listen(self, pin, clock, address);
        socket.setSoTimeout(Math.toIntExact(POLL.toMillis()));
        ShareServer s = new ShareServer(socket, self, name, shares, clock, events);
        s.loop.execute(s::acceptLoop);
        return s;
    }

    /** The port, for the address shown to the receiver. */
    public int port() {
        return server.getLocalPort();
    }

    /** Whether the listener is still accepting. */
    public boolean isOpen() {
        return done.getCount() > 0;
    }

    /** Waits up to {@code timeout} for the listener to close; true if it has. */
    public boolean awaitClosed(Duration timeout) throws InterruptedException {
        return done.await(timeout.toMillis(), TimeUnit.MILLISECONDS);
    }

    private void acceptLoop() {
        try {
            while (shares.anyOpen(clock.instant()) && !server.isClosed()) {
                serveOne();
            }
        } finally {
            release();
            done.countDown();
            events.closed();
        }
    }

    /** Waits up to one poll interval for a connection and serves it; returns whether one came. */
    private boolean serveOne() {
        try (PeerLink link = Lan.accept(server)) {
            serve(link);
            return true;
        } catch (SocketTimeoutException e) {
            return false;
        } catch (IOException | CryptoException e) {
            // close() wakes a blocked accept with an exception; that is not a refused peer
            if (!server.isClosed()) {
                events.refused();
            }
            return false;
        }
    }

    private void serve(PeerLink link) {
        SendSession s = new SendSession(self.publicKey(), link.peerKey(), name, shares, clock);
        try {
            link.send(s.start());
            while (s.state() != SendSession.State.DONE) {
                link.send(s.receive(link.receive()));
            }
            if (s.delivered()) {
                events.delivered(s.offered().orElseThrow());
            }
        } catch (ShareException e) {
            failed(link, s, e.code());
        } catch (WireException | IOException e) {
            failed(link, s, ShareException.Code.PROTOCOL);
        }
    }

    private void failed(PeerLink link, SendSession s, ShareException.Code code) {
        events.failed(s.offered().orElse(null), code);
        sendBestEffort(link, s.abort(code));
    }

    /** Sends {@code messages} if the peer is still there; returns whether they went. */
    static boolean sendBestEffort(PeerLink link, List<Message> messages) {
        try {
            link.send(messages);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Closes the listening socket, releasing the port; returns false if it was already broken. */
    private boolean release() {
        try {
            server.close();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Closes the listener now, whatever windows remain, and waits for the loop to end. */
    @Override
    public void close() {
        release();
        loop.shutdown();
        try {
            loop.awaitTermination(Lan.READ_TIMEOUT.toMillis() * 2, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
