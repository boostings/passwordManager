package pm.sharing.web;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;
import pm.crypto.WebIdentity;

/** The one-fetch HTTPS listener over real loopback TLS (SR-209, SR-210, SR-207). */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: a second client dribbles bytes while the first is served
@Tag("T-WEB-01")
@Tag("T-WEB-02")
@Tag("T-LAN-05")
@Tag("T-LAN-07")
class WebServerTest {
    private static final InetAddress HOST = InetAddress.getLoopbackAddress();
    private static final Duration WAIT = Duration.ofSeconds(10);

    /** Records events in order. */
    static final class Events implements WebEvents {
        final List<String> seen = new CopyOnWriteArrayList<>();

        @Override
        public void opened() {
            seen.add("opened");
        }

        @Override
        public void delivered() {
            seen.add("delivered");
        }

        @Override
        public void closed() {
            seen.add("closed");
        }
    }

    /** An HTTP response split into head and body. */
    record Reply(String head, String latin1Body) {
        byte[] body() {
            return latin1Body.getBytes(StandardCharsets.ISO_8859_1);
        }

        int status() {
            return Integer.parseInt(head.substring(9, 12));
        }

        String header(String name) {
            for (String line : head.split("\r\n", -1)) {
                if (line.startsWith(name + ": ")) {
                    return line.substring(name.length() + 2);
                }
            }
            return null;
        }
    }

    @Test
    void pageUntilTheDataIsFetchedOnceThenThePortIsClosed() throws IOException, GeneralSecurityException,
            CryptoException, InterruptedException {
        Events events = new Events();
        WebIdentity web = WebIdentity.generate(WebShareTest.T0, Duration.ofMinutes(10), HOST);
        try (WebShare share = share(Duration.ofMinutes(10)); WebServer server = WebServer.open(share, web, Clock.systemUTC(), HOST,
                        events)) {
            Reply early = get(web, server.port(), "GET /d/" + share.id() + " HTTP/1.1\r\nHost: x\r\n\r\n");
            assertEquals(410, early.status(), "no data before the page");
            Reply page = get(web, server.port(), "GET /s/" + share.id() + " HTTP/1.1\r\nHost: x\r\n\r\n");
            assertEquals(200, page.status());
            assertEquals("text/html; charset=utf-8", page.header("Content-Type"));
            assertEquals(WebPage.contentSecurityPolicy(), page.header("Content-Security-Policy"));
            assertEquals("no-store", page.header("Cache-Control"));
            assertEquals("no-referrer", page.header("Referrer-Policy"));
            assertEquals("nosniff", page.header("X-Content-Type-Options"));
            assertEquals("close", page.header("Connection"));
            assertEquals(WebPage.HTML, new String(page.body(), StandardCharsets.UTF_8));
            assertEquals(200, get(web, server.port(), "GET /s/" + share.id() + " HTTP/1.1\r\n\r\n").status(),
                    "a link preview fetching the page does not burn the share");
            assertEquals(404, get(web, server.port(), "GET /favicon.ico HTTP/1.1\r\n\r\n").status());
            Reply data = get(web, server.port(), "GET /d/" + share.id() + " HTTP/1.1\r\n\r\n");
            assertEquals(200, data.status());
            assertEquals(WebPage.contentSecurityPolicy(), data.header("Content-Security-Policy"));
            assertArrayEquals(share.ciphertext(), data.body());
            assertTrue(server.awaitClosed(WAIT));
            assertFalse(server.isOpen());
            assertEquals(List.of("opened", "delivered", "closed"), events.seen);
            int port = server.port();
            assertThrows(ConnectException.class, () -> get(web, port, "GET / HTTP/1.1\r\n\r\n"));
        }
    }

    @Test
    void theListenerClosesAtExpiryWithoutDelivering() throws IOException, CryptoException, InterruptedException {
        Events events = new Events();
        WebIdentity web = WebIdentity.generate(WebShareTest.T0, Duration.ofMinutes(10), HOST);
        try (WebShare share = share(Duration.ofSeconds(1)); WebServer server = WebServer.open(share, web, Clock.systemUTC(), HOST,
                        events)) {
            assertTrue(server.isOpen());
            assertTrue(server.awaitClosed(WAIT));
            assertEquals(List.of("closed"), events.seen);
            int port = server.port();
            assertThrows(ConnectException.class, () -> get(web, port, "GET / HTTP/1.1\r\n\r\n"));
        }
    }

    @Test
    void aClientThatRejectsTheCertificateDoesNotStopTheListener() throws IOException, GeneralSecurityException,
            CryptoException, InterruptedException {
        WebIdentity web = WebIdentity.generate(WebShareTest.T0, Duration.ofMinutes(10), HOST);
        WebIdentity other = WebIdentity.generate(WebShareTest.T0, Duration.ofMinutes(10), HOST);
        try (WebShare share = share(Duration.ofMinutes(10)); WebServer server = WebServer.open(share, web, Clock.systemUTC(), HOST,
                        new Events())) {
            int port = server.port();
            assertThrows(IOException.class, () -> get(other, port, "GET / HTTP/1.1\r\n\r\n"));
            assertEquals(200, get(web, port, "GET /s/" + share.id() + " HTTP/1.1\r\n\r\n").status());
            assertTrue(server.isOpen(), "still waiting for the data fetch");
        }
    }

    @Test
    void closeStopsTheListenerAndFreesThePort() throws IOException, CryptoException {
        Events events = new Events();
        WebIdentity web = WebIdentity.generate(WebShareTest.T0, Duration.ofMinutes(10), HOST);
        int port;
        try (WebShare share = share(Duration.ofMinutes(10)); WebServer server = WebServer.open(share, web,
                Clock.systemUTC(), HOST, events)) {
            port = server.port();
        }
        assertEquals(List.of("closed"), events.seen);
        assertThrows(ConnectException.class, () -> get(web, port, "GET / HTTP/1.1\r\n\r\n"));
    }

    @Test
    void afterExpiryOrCloseEverythingIsGone() throws IOException, CryptoException {
        WebIdentity web = WebIdentity.generate(WebShareTest.T0, Duration.ofMinutes(10), HOST);
        try (WebShare share = share(Duration.ofMinutes(10))) {
            String page = "GET /s/" + share.id() + " HTTP/1.1";
            try (WebServer expired = WebServer.open(share, web, Clock.fixed(share.expires(), ZoneOffset.UTC), HOST,
                    new Events())) {
                assertEquals(410, expired.route(page).status());
            }
            assertEquals(410, closedServer(share, web).route(page).status());
        }
    }

    private static WebServer closedServer(WebShare share, WebIdentity web) throws IOException, CryptoException {
        try (WebServer s = WebServer.open(share, web, Clock.systemUTC(), HOST, new Events())) {
            return s;
        }
    }

    /** Revocation cuts off a request already being read instead of answering it later. */
    @Test
    void closeCutsOffARequestInFlight() throws IOException, GeneralSecurityException, CryptoException,
            InterruptedException, ExecutionException {
        Events events = new Events();
        WebIdentity web = WebIdentity.generate(WebShareTest.T0, Duration.ofMinutes(10), HOST);
        try (WebShare share = share(Duration.ofMinutes(10)); ExecutorService slow = Executors.newSingleThreadExecutor();
                WebServer server = WebServer.open(share, web, Clock.systemUTC(), HOST, events)) {
            SSLContext context = trusting(web);
            Future<Long> dribble = slow.submit(() -> dribble(context, server.port()));
            Thread.sleep(1500);
            long took = millisToClose(server);
            assertTrue(took < 1000, "close took " + took + " ms");
            assertFalse(server.isOpen());
            assertTrue(dribble.get() < WebServer.CONNECTION_DEADLINE.toMillis(), "cut off by close");
            assertEquals(List.of("closed"), events.seen);
        }
    }

    private static long millisToClose(WebServer server) {
        long start = System.nanoTime();
        server.close();
        return (System.nanoTime() - start) / 1_000_000;
    }

    /** A client sending one byte per second never times out a read; the deadline still frees the listener. */
    @Test
    void aSlowClientIsCutOffAtTheConnectionDeadline() throws IOException, GeneralSecurityException, CryptoException,
            InterruptedException, ExecutionException {
        WebIdentity web = WebIdentity.generate(WebShareTest.T0, Duration.ofMinutes(10), HOST);
        try (WebShare share = share(Duration.ofMinutes(10)); WebServer server = WebServer.open(share, web,
                Clock.systemUTC(), HOST, new Events()); ExecutorService slow = Executors.newSingleThreadExecutor()) {
            SSLContext context = trusting(web);
            Future<Long> dribble = slow.submit(() -> dribble(context, server.port()));
            Thread.sleep(300);
            long start = System.nanoTime();
            assertEquals(200, get(web, server.port(), "GET /s/" + share.id() + " HTTP/1.1\r\n\r\n").status());
            long waited = (System.nanoTime() - start) / 1_000_000;
            assertTrue(waited < WebServer.CONNECTION_DEADLINE.toMillis() + 2000, "waited " + waited + " ms");
            long cutOff = dribble.get();
            assertTrue(cutOff > 0 && cutOff < WebServer.CONNECTION_DEADLINE.toMillis() + 3000, "cut off at " + cutOff);
        }
    }

    /** Sends one byte a second for 30 s; returns the milliseconds until the server cut it off, or -1. */
    private static long dribble(SSLContext context, int port) throws InterruptedException {
        long start = System.nanoTime();
        try (Socket s = context.getSocketFactory().createSocket(HOST, port); OutputStream out = s.getOutputStream()) {
            for (int i = 0; i < 30; i++) {
                out.write('G');
                out.flush();
                Thread.sleep(1000);
            }
            return -1L;
        } catch (IOException e) {
            return (System.nanoTime() - start) / 1_000_000;
        }
    }

    @Test
    void routeRefusesMalformedRequestsAndOtherMethods() throws IOException, CryptoException {
        WebIdentity web = WebIdentity.generate(WebShareTest.T0, Duration.ofMinutes(10), HOST);
        try (WebShare share = share(Duration.ofMinutes(10)); WebServer server = WebServer.open(share, web, Clock.systemUTC(), HOST,
                        new Events())) {
            String page = "/s/" + share.id();
            assertEquals(400, server.route(null).status());
            assertEquals(400, server.route("GET " + page).status());
            assertEquals(400, server.route("GET " + page + " HTTP/1.1 x").status());
            assertEquals(400, server.route("GET " + page + " HTTP/2").status());
            assertEquals(405, server.route("POST " + page + " HTTP/1.1").status());
            assertEquals(405, server.route("HEAD " + page + " HTTP/1.1").status());
            assertEquals(404, server.route("GET " + page + "/ HTTP/1.1").status());
            assertEquals(404, server.route("GET /s/" + "0".repeat(32) + " HTTP/1.1").status());
            assertEquals(200, server.route("GET " + page + " HTTP/1.0").status());
            assertEquals(200, server.route("GET /d/" + share.id() + " HTTP/1.1").status());
            assertEquals(410, server.route("GET /d/" + share.id() + " HTTP/1.1").status());
            assertEquals(400, server.route("GET " + page + " HTTP/1.1junk").status());
            WebServer.Response r = WebServer.Response.error(404, "Not Found");
            r.event().run();
            assertEquals("404 Not Found\n", new String(r.body(), StandardCharsets.UTF_8));
        }
    }

    @Test
    void requestHeadIsBoundedAndMustBeComplete() throws IOException {
        assertEquals("GET / HTTP/1.1", line("GET / HTTP/1.1\r\nHost: a\r\n\r\nignored"));
        assertEquals("A\r\rB", line("A\r\rB\r\n\r\n").substring(0, 4));
        assertEquals("x", line("x\r\n\r\r\n\r\n"));
        assertNull(line("GET / HTTP/1.1\r\n"), "stream ended before the head");
        byte[] huge = new byte[WebServer.MAX_REQUEST + 4];
        Arrays.fill(huge, (byte) 'a');
        assertNull(WebServer.requestLine(new ByteArrayInputStream(huge)));
        byte[] exact = new byte[WebServer.MAX_REQUEST];
        Arrays.fill(exact, (byte) 'a');
        System.arraycopy("\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1), 0, exact, exact.length - 4, 4);
        assertEquals(WebServer.MAX_REQUEST - 4, WebServer.requestLine(new ByteArrayInputStream(exact)).length());
    }

    static WebShare share(Duration ttl) throws CryptoException {
        try (SecretBytes p = SecretBytes.copyOf(WebShareTest.TEXT)) {
            return WebShare.seal(p, ttl, Clock.systemUTC().instant());
        }
    }

    private static String line(String head) throws IOException {
        return WebServer.requestLine(new ByteArrayInputStream(head.getBytes(StandardCharsets.ISO_8859_1)));
    }

    /** A client context that trusts only {@code trusted}'s certificate. */
    static SSLContext trusting(WebIdentity trusted) throws IOException, GeneralSecurityException {
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, null);
        store.setCertificateEntry("web", java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(trusted.certificate())));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(store);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), null);
        return context;
    }

    /** Sends {@code request} over TLS trusting only {@code trusted}'s certificate; reads to EOF. */
    static Reply get(WebIdentity trusted, int port, String request) throws IOException, GeneralSecurityException {
        SSLContext context = trusting(trusted);
        try (Socket s = context.getSocketFactory().createSocket()) {
            s.connect(new InetSocketAddress(HOST, port), 5000);
            s.setSoTimeout(5000);
            try (OutputStream out = s.getOutputStream(); InputStream in = s.getInputStream()) {
                out.write(request.getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
                String text = new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
                int split = text.indexOf("\r\n\r\n");
                return new Reply(text.substring(0, split), text.substring(split + 4));
            }
        }
    }
}
