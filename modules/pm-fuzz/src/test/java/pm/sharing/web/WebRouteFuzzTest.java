package pm.sharing.web;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;
import pm.crypto.WebIdentity;
import pm.fuzz.FuzzClock;
import pm.fuzz.Script;
import pm.fuzz.Seeds;

/**
 * Fuzz harness for the browser-share listener's routing and request-head parsing (SR-209, SR-210,
 * T-FUZZ-LAN). Each input opens a {@link WebServer} on loopback with a clock the script moves (the
 * listener is needed for an instance; the fuzzer does not connect to it). It then feeds up to
 * {@link #MAX_STEPS} request heads straight into {@link WebServer#requestLine} and
 * {@link WebServer#route}: raw bytes, or a request line assembled from the script's choice of
 * method, path (the page, the ciphertext, near misses, junk), version and trailing headers. The
 * script can also move the clock and revoke the share ({@link WebServer#close()}).
 *
 * <p>The oracle: neither method throws. A request line never holds a line break and never exceeds
 * the head limit. Every answer is 200, 400, 404, 405 or 410; a 200 comes only before expiry and
 * before revocation; the ciphertext is served at most once, only after the page, and is exactly
 * the sealed bytes.
 *
 * <p>The accept loop, TLS, the connection watchdog and revocation of a connection in flight are not
 * fuzzed. {@link #seedsGiveTheSameOutcomeOverRealTls} replays every seed over real loopback TLS
 * connections to the listener under the same oracle, where a refused or cut connection counts only
 * once the share is delivered, expired or revoked. {@code WebServerTest} (pm-sharing) covers the
 * watchdog and the in-flight cut deterministically.
 *
 * <p>Lives in {@code pm.sharing.web} because {@code route} and {@code requestLine} are
 * package-private. Without {@code JAZZER_FUZZ=1} the seeds in {@code WebRouteFuzzTestInputs} are
 * replayed.
 */
@Tag("T-FUZZ-LAN")
@Tag("T-WEB-01")
class WebRouteFuzzTest {
    static final int MAX_STEPS = 32;
    private static final InetAddress HOST = InetAddress.getLoopbackAddress();
    private static final int OK = 200;
    private static final Set<Integer> STATUSES = Set.of(OK, 400, 404, 405, 410);
    private static final List<String> METHODS = List.of("GET", "GET", "POST", "HEAD", "get");
    private static final List<String> VERSIONS = List.of("HTTP/1.1", "HTTP/1.0", "HTTP/2", "HTTP/1.1 ", "");
    private static final int STEP_KINDS = 4;
    private static final int PATH_KINDS = 7;
    private static final int RAW_MAX = 24;
    private static final long MILLIS_PER_TICK = 100;
    private static final int CLIENT_TIMEOUT_MILLIS = 5000;
    private static final String DATA_TYPE = "application/octet-stream";
    private static final WebIdentity WEB = identity();

    private static WebIdentity identity() {
        try {
            return WebIdentity.generate(FuzzClock.T0, Duration.ofHours(1), HOST);
        } catch (CryptoException e) {
            throw new IllegalStateException(e.code().name(), e);
        }
    }

    @FuzzTest
    void fuzz(byte[] in) throws IOException, CryptoException {
        new Run(new Script(in), null).play();
    }

    /** What one script got from the listener, for the seed tests. */
    record Outcome(int pages, int deliveries, int refusals) {}

    /** One answer: status, whether it was the ciphertext, and the body. */
    private static final class Answer {
        final int status;
        final boolean data;
        final byte[] body;

        Answer(int status, boolean data, byte[] body) {
            this.status = status;
            this.data = data;
            this.body = body.clone();
        }
    }

    /** One scripted listener; requests go to {@code route} directly, or over TLS when a client is given. */
    static final class Run {
        private final Script s;
        private final SSLContext tls;
        private final FuzzClock clock = new FuzzClock();
        private boolean revoked;
        private boolean pageServed;
        private int pages;
        private int deliveries;
        private int refusals;

        Run(Script s, SSLContext tls) {
            this.s = s;
            this.tls = tls;
        }

        Outcome play() throws IOException, CryptoException {
            Duration ttl = Duration.ofSeconds(1L + s.u8());
            try (SecretBytes payload = SecretBytes.copyOf("shared text".getBytes(StandardCharsets.UTF_8));
                    WebShare share = WebShare.seal(payload, ttl, clock.instant());
                    WebServer server = WebServer.open(share, WEB, clock, HOST, new Quiet())) {
                for (int i = 0; i < MAX_STEPS && !s.done(); i++) {
                    switch (s.pick(STEP_KINDS)) {
                        case 0, 1 -> request(server, share);
                        case 2 -> clock.advance(s.bit() ? Duration.ofSeconds(s.u8())
                                : Duration.ofMillis(s.u8() * MILLIS_PER_TICK));
                        default -> revoke(server);
                    }
                }
            }
            return new Outcome(pages, deliveries, refusals);
        }

        /** Revokes the share the way the TUI does: closes the listener. */
        private void revoke(WebServer server) {
            server.close();
            revoked = true;
        }

        private void request(WebServer server, WebShare share) throws IOException {
            byte[] head = s.bit() ? s.bytes(s.u8()) : assembled(share);
            Answer a = tls == null ? direct(server, head) : overTls(server, head);
            if (a == null) {
                assertTrue(revoked || deliveries > 0 || !clock.instant().isBefore(share.expires()),
                        "the listener went away while the share was live");
                refusals++;
                return;
            }
            assertTrue(STATUSES.contains(a.status), "status " + a.status);
            if (a.status != OK) {
                refusals++;
                return;
            }
            assertFalse(revoked, "served after revocation");
            assertTrue(clock.instant().isBefore(share.expires()), "served after expiry");
            if (a.data) {
                assertTrue(pageServed, "ciphertext before the page");
                assertEquals(0, deliveries, "ciphertext served twice");
                assertArrayEquals(share.ciphertext(), a.body);
                deliveries++;
            } else {
                assertArrayEquals(WebPage.HTML.getBytes(StandardCharsets.UTF_8), a.body);
                pageServed = true;
                pages++;
            }
        }

        private static Answer direct(WebServer server, byte[] head) throws IOException {
            String line = WebServer.requestLine(new ByteArrayInputStream(head));
            if (line != null) {
                assertFalse(line.contains("\r\n"), "line break in the request line");
                assertTrue(line.length() <= WebServer.MAX_REQUEST, "request line over the head limit");
            }
            WebServer.Response r = server.route(line);
            return new Answer(r.status(), r.head().contains(DATA_TYPE), r.body());
        }

        /**
         * Sends {@code head} on a new TLS connection, half-closes, and reads the reply; null if the
         * connection was refused or cut, or nothing came back.
         */
        private Answer overTls(WebServer server, byte[] head) {
            try (Socket socket = tls.getSocketFactory().createSocket()) {
                socket.connect(new InetSocketAddress(HOST, server.port()), CLIENT_TIMEOUT_MILLIS);
                socket.setSoTimeout(CLIENT_TIMEOUT_MILLIS);
                String reply;
                try (OutputStream out = socket.getOutputStream(); InputStream in = socket.getInputStream()) {
                    out.write(head);
                    out.flush();
                    socket.shutdownOutput();
                    reply = new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
                }
                int split = reply.indexOf("\r\n\r\n");
                if (split < 0) {
                    return null;
                }
                String responseHead = reply.substring(0, split);
                byte[] body = reply.substring(split + 4).getBytes(StandardCharsets.ISO_8859_1);
                int status = Integer.parseInt(responseHead.substring("HTTP/1.1 ".length(), "HTTP/1.1 200".length()));
                return new Answer(status, responseHead.contains(DATA_TYPE), body);
            } catch (IOException e) {
                return null;
            }
        }

        /** A request head built from the script's choices around the real share id. */
        private byte[] assembled(WebShare share) {
            String id = share.id();
            String path = switch (s.pick(PATH_KINDS)) {
                case 0 -> WebServer.PAGE + id;
                case 1 -> WebServer.DATA + id;
                case 2 -> WebServer.PAGE + id + raw();
                case 3 -> WebServer.DATA + id.toUpperCase(java.util.Locale.ROOT);
                case 4 -> WebServer.DATA + id.substring(1);
                case 5 -> "/" + raw();
                default -> raw();
            };
            String method = METHODS.get(s.pick(METHODS.size()));
            String version = VERSIONS.get(s.pick(VERSIONS.size()));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            write(out, method + " " + path + " " + version + "\r\n");
            if (s.bit()) {
                write(out, "Host: 127.0.0.1\r\n" + raw() + "\r\n");
            }
            write(out, s.bit() ? "\r\n" : raw());
            return out.toByteArray();
        }

        private String raw() {
            return new String(s.bytes(s.pick(RAW_MAX)), StandardCharsets.ISO_8859_1);
        }

        private static void write(ByteArrayOutputStream out, String text) {
            try {
                out.write(text.getBytes(StandardCharsets.ISO_8859_1));
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    /** Events nobody listens to. */
    private static final class Quiet implements WebEvents {
        @Override
        public void opened() {
            // the harness checks responses, not events
        }

        @Override
        public void delivered() {
            // the harness checks responses, not events
        }

        @Override
        public void closed() {
            // the harness checks responses, not events
        }
    }

    /** A client context that trusts only the harness's certificate. */
    static SSLContext trustingTheListener() throws IOException, GeneralSecurityException {
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, null);
        store.setCertificateEntry("web", CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(WEB.certificate())));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(store);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), null);
        return context;
    }

    /** What each seed must get: pages, deliveries, refusals. */
    static Map<String, Outcome> seedOutcomes() {
        return Map.of(
                "page-then-data.bin", new Outcome(1, 1, 1),
                "data-before-page.bin", new Outcome(1, 1, 1),
                "page-then-expiry.bin", new Outcome(1, 0, 1),
                "page-then-revoke.bin", new Outcome(1, 0, 1),
                "raw-garbage.bin", new Outcome(0, 0, 1));
    }

    /** The seeds get what their names say, so the 200 branches of the oracle are exercised. */
    @Test
    void seedsEndAsLabelled() throws IOException, CryptoException {
        for (Map.Entry<String, Outcome> seed : seedOutcomes().entrySet()) {
            byte[] script = Seeds.read(WebRouteFuzzTest.class, seed.getKey());
            assertEquals(seed.getValue(), new Run(new Script(script), null).play(), seed.getKey());
        }
    }

    /**
     * The same seeds over real loopback TLS: the accept loop, the TLS handshake and the response
     * writer give the same outcome as {@code route}, and the oracle holds for every reply.
     */
    @Test
    void seedsGiveTheSameOutcomeOverRealTls() throws IOException, CryptoException, GeneralSecurityException {
        SSLContext tls = trustingTheListener();
        for (Map.Entry<String, Outcome> seed : seedOutcomes().entrySet()) {
            byte[] script = Seeds.read(WebRouteFuzzTest.class, seed.getKey());
            assertEquals(seed.getValue(), new Run(new Script(script), tls).play(), seed.getKey());
        }
    }
}
