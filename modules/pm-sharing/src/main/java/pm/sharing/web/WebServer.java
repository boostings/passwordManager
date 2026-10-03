package pm.sharing.web;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLServerSocket;
import pm.crypto.CryptoException;
import pm.crypto.WebIdentity;
import pm.sharing.net.Lan;

/**
 * The HTTPS listener for one browser share (lan-share.md §7 steps 2–4, SR-209, SR-210). It serves
 * the page {@code /s/<id>} (static, holds nothing secret, so a link preview fetching it costs
 * nothing) until the ciphertext {@code /d/<id>} has been fetched once, after the page. Everything
 * else gets an error. It closes itself, freeing the port, after the ciphertext is fetched or when the
 * window expires; {@link #close()} also cuts off a request in flight.
 * Connections are served one at a time. Each read waits at most {@link #READ_TIMEOUT}, and a
 * watchdog closes any connection still open after {@link #CONNECTION_DEADLINE}, so neither a stalled
 * TLS handshake nor a client sending one byte at a time can hold the listener.
 */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: TPS00-J one-thread executor for the accept loop
public final class WebServer implements AutoCloseable {
    /** Path prefix of the page. */
    static final String PAGE = "/s/";
    /** Path prefix of the ciphertext. */
    static final String DATA = "/d/";
    /** Longest request head accepted, request line and headers together. */
    static final int MAX_REQUEST = 8 * 1024;
    /** How long a connection may take to send its request head. */
    static final Duration READ_TIMEOUT = Duration.ofSeconds(2);
    /** Longest any one connection may last, handshake and response included. */
    static final Duration CONNECTION_DEADLINE = Duration.ofSeconds(5);
    /** How often the accept loop wakes to check for expiry. */
    static final Duration POLL = Duration.ofMillis(100);
    private static final byte[] HEAD_END = {'\r', '\n', '\r', '\n'};

    private final SSLServerSocket server;
    private final WebShare share;
    private final Clock clock;
    private final WebEvents events;
    private final ExecutorService loop = Executors.newSingleThreadExecutor();
    private final ScheduledExecutorService watchdog = Executors.newSingleThreadScheduledExecutor();
    private final CountDownLatch done = new CountDownLatch(1);
    /** Touched only by the loop thread. */
    private boolean pageServed;
    /** Set by {@link #close()}; from then on nothing is served. */
    private volatile boolean closing;
    /** The connection being served, so {@link #close()} can cut it off. */
    private volatile Socket current;
    /** Touched only by the loop thread. */
    private boolean dataServed;

    private WebServer(SSLServerSocket server, WebShare share, Clock clock, WebEvents events) {
        this.server = server;
        this.share = share;
        this.clock = clock;
        this.events = events;
    }

    /** Opens the listener on an ephemeral port of {@code address}, presenting {@code web}, and starts serving. */
    public static WebServer open(WebShare share, WebIdentity web, Clock clock, InetAddress address, WebEvents events)
            throws IOException, CryptoException {
        Objects.requireNonNull(share, "share");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(events, "events");
        WebServer s = new WebServer(Lan.listenForBrowsers(web, address, POLL), share, clock, events);
        s.loop.execute(s::acceptLoop);
        return s;
    }

    /** The port, for the link shown to the sender. */
    public int port() {
        return server.getLocalPort();
    }

    /** Whether the listener is still serving. */
    public boolean isOpen() {
        return done.getCount() > 0;
    }

    /** Waits up to {@code timeout} for the listener to close; true if it has. */
    public boolean awaitClosed(Duration timeout) throws InterruptedException {
        return done.await(timeout.toMillis(), TimeUnit.MILLISECONDS);
    }

    private void acceptLoop() {
        try {
            while (!dataServed && clock.instant().isBefore(share.expires()) && !server.isClosed()) {
                serveOne();
            }
        } finally {
            release();
            watchdog.shutdownNow();
            loop.shutdown();
            done.countDown();
            events.closed();
        }
    }

    /** Waits up to one poll interval for a connection and answers it; returns whether one came. */
    private boolean serveOne() {
        try (Socket client = server.accept()) {
            current = client; // anything accepted after close() is answered 410 by route()
            ScheduledFuture<?> deadline = watchdog.schedule(() -> closeQuietly(client),
                    CONNECTION_DEADLINE.toMillis(), TimeUnit.MILLISECONDS);
            try {
                client.setSoTimeout(Math.toIntExact(READ_TIMEOUT.toMillis()));
                Response r = route(requestLine(client.getInputStream()));
                r.write(client.getOutputStream());
                r.event().run();
                return true;
            } finally {
                deadline.cancel(false);
                current = null;
            }
        } catch (IOException e) {
            // accept timeout, a refused certificate, a slow or broken client, the watchdog, or close()
            return false;
        }
    }

    /** Closes {@code socket} if there is one; returns false if there was none or closing failed. */
    static boolean closeQuietly(Socket socket) {
        if (socket == null) {
            return false;
        }
        try {
            socket.close();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * The answer to {@code requestLine} (null when the head was too long or cut short). After expiry
     * or {@link #close()} everything is gone. Marks the page or the data as served.
     */
    Response route(String requestLine) {
        String[] parts = requestLine == null ? new String[0] : requestLine.split(" ", -1);
        if (parts.length != 3 || (!"HTTP/1.1".equals(parts[2]) && !"HTTP/1.0".equals(parts[2]))) {
            return Response.error(400, "Bad Request");
        }
        if (!"GET".equals(parts[0])) {
            return Response.error(405, "Method Not Allowed");
        }
        if (closing || !clock.instant().isBefore(share.expires())) {
            return Response.error(410, "Gone");
        }
        String target = parts[1];
        if (target.equals(PAGE + share.id())) {
            Runnable first = pageServed ? () -> { } : events::opened;
            pageServed = true;
            return new Response(200, "OK", "text/html; charset=utf-8",
                    WebPage.HTML.getBytes(StandardCharsets.UTF_8), first);
        }
        if (target.equals(DATA + share.id())) {
            if (!pageServed || dataServed) {
                return Response.error(410, "Gone");
            }
            dataServed = true;
            return new Response(200, "OK", "application/octet-stream", share.ciphertext(), events::delivered);
        }
        return Response.error(404, "Not Found");
    }

    /**
     * Reads the request head and returns its first line, or null if the head is longer than
     * {@link #MAX_REQUEST} or the stream ends first.
     */
    static String requestLine(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int matched = 0;
        while (matched < HEAD_END.length) {
            int b = in.read();
            if (b < 0 || head.size() == MAX_REQUEST) {
                return null;
            }
            head.write(b);
            matched = b == HEAD_END[matched] ? matched + 1 : b == HEAD_END[0] ? 1 : 0;
        }
        String text = head.toString(StandardCharsets.ISO_8859_1);
        return text.substring(0, text.indexOf("\r\n"));
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

    /** Closes the listener now and waits for the loop to end. */
    @Override
    public void close() {
        closing = true;
        release();
        closeQuietly(current);
        loop.shutdown();
        watchdog.shutdownNow();
        try {
            loop.awaitTermination(CONNECTION_DEADLINE.toMillis() * 2, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** One HTTP/1.1 response, always with the §7 security headers and {@code Connection: close}. */
    static final class Response {
        private final int code;
        private final String reason;
        private final String type;
        private final byte[] content;
        private final Runnable onSent;

        Response(int code, String reason, String type, byte[] content, Runnable onSent) {
            this.code = code;
            this.reason = reason;
            this.type = type;
            this.content = content.clone();
            this.onSent = onSent;
        }

        static Response error(int code, String reason) {
            return new Response(code, reason, "text/plain; charset=utf-8",
                    (code + " " + reason + "\n").getBytes(StandardCharsets.UTF_8), () -> { });
        }

        int status() {
            return code;
        }

        byte[] body() {
            return content.clone();
        }

        Runnable event() {
            return onSent;
        }

        String head() {
            return "HTTP/1.1 " + code + " " + reason + "\r\n"
                    + "Content-Type: " + type + "\r\n"
                    + "Content-Length: " + content.length + "\r\n"
                    + "Cache-Control: no-store\r\n"
                    + "Content-Security-Policy: " + WebPage.contentSecurityPolicy() + "\r\n"
                    + "Referrer-Policy: no-referrer\r\n"
                    + "X-Content-Type-Options: nosniff\r\n"
                    + "X-Frame-Options: DENY\r\n"
                    + "Cross-Origin-Opener-Policy: same-origin\r\n"
                    + "Cross-Origin-Resource-Policy: same-origin\r\n"
                    + "Connection: close\r\n\r\n";
        }

        void write(OutputStream out) throws IOException {
            out.write(head().getBytes(StandardCharsets.ISO_8859_1));
            out.write(content);
            out.flush();
        }
    }
}
