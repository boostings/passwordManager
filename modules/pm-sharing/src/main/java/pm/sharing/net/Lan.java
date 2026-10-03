package pm.sharing.net;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.function.Predicate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import pm.crypto.CryptoException;
import pm.crypto.DeviceIdentity;
import pm.crypto.Tls;
import pm.crypto.WebIdentity;

/**
 * Opens LAN listeners and connections (lan-share.md §3). TLS 1.3 only, mutual authentication, and
 * the peer accepted only if its key passes {@code pin}: any key while pairing, otherwise a trusted
 * device's key.
 *
 * <p>The casts from the JSSE socket factories are safe by contract: an {@code SSLContext}'s
 * factories create only {@code SSLSocket}s and {@code SSLServerSocket}s (CE-012).
 */
public final class Lan {
    /** Pending connections a listener queues. */
    public static final int BACKLOG = 4;
    /** Per-read timeout while the protocol is running. */
    public static final Duration READ_TIMEOUT = Duration.ofSeconds(10);
    /** Connect timeout. */
    public static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);

    private Lan() {
    }

    /**
     * A listener on an ephemeral port of {@code address}, with {@code SO_REUSEADDR} off. Each
     * accepted socket requires a client certificate that passes {@code pin}.
     */
    public static SSLServerSocket listen(DeviceIdentity self, Predicate<byte[]> pin, Clock clock, InetAddress address)
            throws IOException, CryptoException {
        Objects.requireNonNull(address, "address");
        SSLContext context = Tls.context(self, pin, clock);
        SSLServerSocket server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket();
        try {
            server.setReuseAddress(false);
            server.setSSLParameters(Tls.parameters(true));
            server.bind(new InetSocketAddress(address, 0), BACKLOG);
            return server;
        } catch (IOException e) {
            server.close();
            throw e;
        }
    }

    /**
     * An HTTPS listener for browser-only receiving (lan-share.md §7) on an ephemeral port of
     * {@code address}: it presents {@code web}, asks for no client certificate, and has
     * {@code SO_REUSEADDR} off. {@code accept} waits at most {@code acceptTimeout}.
     */
    public static SSLServerSocket listenForBrowsers(WebIdentity web, InetAddress address, Duration acceptTimeout)
            throws IOException, CryptoException {
        Objects.requireNonNull(address, "address");
        SSLServerSocket server = (SSLServerSocket) Tls.browserContext(web).getServerSocketFactory()
                .createServerSocket();
        try {
            server.setReuseAddress(false);
            server.setSSLParameters(Tls.browserParameters());
            server.setSoTimeout(Math.toIntExact(acceptTimeout.toMillis()));
            server.bind(new InetSocketAddress(address, 0), BACKLOG);
            return server;
        } catch (IOException e) {
            server.close();
            throw e;
        }
    }

    /** Accepts one connection and completes its handshake. */
    public static PeerLink accept(SSLServerSocket server) throws IOException, CryptoException {
        return PeerLink.handshake((SSLSocket) server.accept());
    }

    /** Connects to {@code peer} and completes the handshake. */
    public static PeerLink connect(DeviceIdentity self, Predicate<byte[]> pin, Clock clock, InetSocketAddress peer)
            throws IOException, CryptoException {
        Objects.requireNonNull(peer, "peer");
        SSLSocket socket = (SSLSocket) Tls.context(self, pin, clock).getSocketFactory().createSocket();
        try {
            socket.setSSLParameters(Tls.parameters(false));
            socket.connect(peer, Math.toIntExact(CONNECT_TIMEOUT.toMillis()));
        } catch (IOException e) {
            socket.close();
            throw e;
        }
        return PeerLink.handshake(socket);
    }
}
