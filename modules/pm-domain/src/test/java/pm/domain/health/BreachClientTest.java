package pm.domain.health;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pm.crypto.CryptoException;
import pm.crypto.Hash;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.vault.record.LoginRecord;

/**
 * T-HEALTH-01 (TM-70, SR-074): a fake range server on loopback records every request byte the
 * client sends; the tests assert it only ever sees a five-character prefix.
 */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-016: fake server needs its own handler threads to drip and stall
class BreachClientTest {
    private static final String SAMPLE = "correct-horse-sample";
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final int DRIP_BYTES = 100;
    private static final long DRIP_GAP_MS = 100;
    private static final long STALL_LENGTH = 1000;
    private static final long STALL_MAX_S = 30;

    /** Everything the client sent in one request. */
    private record Seen(String method, String rawPath, String rawQuery, Map<String, List<String>> headers, String body) {
        String everything() {
            return method + " " + rawPath + "?" + rawQuery + " " + headers + " " + body;
        }
    }

    private final List<Seen> seen = new CopyOnWriteArrayList<>();
    private final Map<String, Function<String, Reply>> routes = new ConcurrentHashMap<>();
    private final CountDownLatch release = new CountDownLatch(1);
    private final ExecutorService handlers = Executors.newCachedThreadPool();
    private HttpServer server;
    private URI base;

    private record Reply(int status, String body, String location) {
        static Reply ok(String body) {
            return new Reply(200, body, null);
        }
    }

    @BeforeEach
    void startFakeRangeServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.createContext("/drip/", this::drip);
        server.createContext("/stall/", this::stall);
        server.setExecutor(handlers);
        server.start();
        base = URI.create("http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort() + "/");
    }

    @AfterEach
    void stop() {
        release.countDown();
        server.stop(0);
        handlers.shutdownNow();
    }

    /** Headers at once, then one body byte every 100 ms: never finishes inside a short deadline. */
    private void drip(HttpExchange ex) throws IOException {
        try (ex; OutputStream os = ex.getResponseBody()) {
            ex.sendResponseHeaders(200, 0);
            for (int i = 0; i < DRIP_BYTES; i++) {
                os.write('0');
                os.flush();
                if (release.await(DRIP_GAP_MS, TimeUnit.MILLISECONDS)) {
                    return;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Headers promising a body that never arrives until the test ends. */
    private void stall(HttpExchange ex) throws IOException {
        try (ex) {
            ex.sendResponseHeaders(200, STALL_LENGTH);
            if (!release.await(STALL_MAX_S, TimeUnit.SECONDS)) {
                return;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Test
    void oneDeadlineCoversHeadersAndTheWholeBody() {
        Duration deadline = Duration.ofSeconds(1);
        for (String path : new String[] {"/drip/", "/stall/"}) {
            try (BreachClient client = BreachClient.create(base.resolve(path), deadline);
                    SecretBytes pw = Records.secret(SAMPLE)) {
                long start = System.nanoTime();
                BreachCheckException e = assertThrows(BreachCheckException.class, () -> client.occurrences(pw), path);
                Duration took = Duration.ofNanos(System.nanoTime() - start);
                assertEquals(BreachCheckException.Code.TIMEOUT, e.code(), path);
                assertTrue(took.compareTo(Duration.ofSeconds(4)) < 0, () -> path + " took " + took);
            }
        }
    }

    private void handle(HttpExchange ex) throws IOException {
        try (ex; InputStream in = ex.getRequestBody()) {
            byte[] body = in.readAllBytes();
            Map<String, List<String>> headers = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            ex.getRequestHeaders().forEach((k, v) -> headers.put(k, List.copyOf(v)));
            URI uri = ex.getRequestURI();
            seen.add(new Seen(ex.getRequestMethod(), uri.getRawPath(), uri.getRawQuery(), headers,
                    new String(body, StandardCharsets.ISO_8859_1)));
            String path = uri.getRawPath();
            int slash = path.lastIndexOf('/');
            Function<String, Reply> route = routes.getOrDefault(path.substring(0, slash + 1), p -> new Reply(404, "", null));
            Reply reply = route.apply(path.substring(slash + 1));
            if (reply.location() != null) {
                ex.getResponseHeaders().add("Location", reply.location());
            }
            byte[] out = reply.body().getBytes(StandardCharsets.US_ASCII);
            ex.sendResponseHeaders(reply.status(), out.length == 0 ? -1 : out.length);
            if (out.length > 0) {
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(out);
                }
            }
        }
    }

    private static String sha1Hex(String password) throws CryptoException {
        try (SecretBytes pw = Records.secret(password); SecretBytes digest = Hash.sha1ForBreachRange(pw)) {
            return digest.apply(HexFormat.of().withUpperCase()::formatHex);
        }
    }

    /** A padded range response: {@code padding} count-0 lines plus the given real lines. */
    private static String rangeBody(int padding, String... lines) {
        List<String> out = new ArrayList<>(List.of(lines));
        for (int i = 0; i < padding; i++) {
            out.add(String.format(Locale.ROOT, "%035X:0", ((long) i * 0x9E3779B97F4A7C15L) >>> 1));
        }
        return String.join("\r\n", out);
    }

    private void assertOnlyPrefixLeft(String password, String fullHex) {
        String suffix = fullHex.substring(BreachClient.PREFIX_CHARS);
        for (Seen s : seen) {
            String all = s.everything().toUpperCase(Locale.ROOT);
            assertFalse(all.contains(fullHex), "full hash sent");
            assertFalse(all.contains(suffix), "hash suffix sent");
            assertFalse(all.contains(suffix.substring(0, 8)), "part of the suffix sent");
            assertEquals(List.of("pm-password-manager"), s.headers().get("User-Agent"));
            // The fixed product User-Agent is the only header text allowed to contain "password".
            String withoutAgent = all.replace("PM-PASSWORD-MANAGER", "");
            assertFalse(withoutAgent.contains(password.toUpperCase(Locale.ROOT)), "password sent");
            assertEquals("GET", s.method());
            assertEquals("/range/" + fullHex.substring(0, BreachClient.PREFIX_CHARS), s.rawPath());
            assertEquals(null, s.rawQuery());
            assertEquals("", s.body());
            assertEquals(List.of("true"), s.headers().get("Add-Padding"));
            assertEquals(null, s.headers().get("Cookie"));
            assertEquals(null, s.headers().get("Authorization"));
        }
    }

    @Test
    void serverSeesOnlyAFiveCharacterPrefixAndCountIsMatchedLocally() throws BreachCheckException, CryptoException {
        String hex = sha1Hex(SAMPLE);
        String prefix = hex.substring(0, 5);
        String suffix = hex.substring(5);
        routes.put("/range/", p -> p.equals(prefix) ? Reply.ok(rangeBody(800, suffix + ":42")) : Reply.ok(rangeBody(10)));
        try (BreachClient client = BreachClient.create(base, TIMEOUT); SecretBytes pw = Records.secret(SAMPLE)) {
            assertEquals(0, seen.size(), "constructing the client sends nothing");
            assertEquals(42, client.occurrences(pw));
            assertFalse(pw.isClosed());
        }
        assertEquals(1, seen.size());
        assertEquals(5, seen.get(0).rawPath().length() - "/range/".length());
        assertOnlyPrefixLeft(SAMPLE, hex);
    }

    @Test
    void knownVectorAndCharInput() throws BreachCheckException, CryptoException {
        // The full digest vector is pinned in HashTest; here it is computed so no hash literal is committed.
        String hex = sha1Hex("password");
        routes.put("/range/", p -> Reply.ok(rangeBody(5, hex.substring(5) + ":9545824", "")));
        try (BreachClient client = BreachClient.create(base, TIMEOUT);
                SecretChars pw = SecretChars.takeOwnership("password".toCharArray())) {
            assertEquals(9_545_824, client.occurrences(pw));
            assertFalse(pw.isClosed());
        }
        assertEquals("/range/5BAA6", seen.get(0).rawPath());
        assertOnlyPrefixLeft("password", hex);
    }

    @Test
    void absentOrPaddingOnlyMatchIsZero() throws BreachCheckException, CryptoException {
        String suffix = sha1Hex(SAMPLE).substring(5);
        routes.put("/range/", p -> Reply.ok(rangeBody(50)));
        try (BreachClient client = BreachClient.create(base, TIMEOUT); SecretBytes pw = Records.secret(SAMPLE)) {
            assertEquals(0, client.occurrences(pw));
            routes.put("/range/", p -> Reply.ok(rangeBody(50, suffix + ":0")));
            assertEquals(0, client.occurrences(pw), "a padding line is never a hit");
        }
    }

    @Test
    void basePathIsKeptAndSlashAdded() throws BreachCheckException, CryptoException {
        routes.put("/api/v3/range/", p -> Reply.ok(rangeBody(3)));
        try (BreachClient client = BreachClient.create(base.resolve("/api/v3"), TIMEOUT);
                SecretBytes pw = Records.secret(SAMPLE)) {
            assertEquals(base.resolve("/api/v3/"), client.base());
            assertEquals(0, client.occurrences(pw));
        }
        assertTrue(seen.get(0).rawPath().startsWith("/api/v3/range/"));
    }

    @Test
    void failuresCarryCodesOnly() throws BreachCheckException, CryptoException {
        try (BreachClient client = BreachClient.create(base, TIMEOUT); SecretBytes pw = Records.secret(SAMPLE)) {
            routes.put("/range/", p -> new Reply(500, "", null));
            assertEquals(BreachCheckException.Code.HTTP_STATUS, assertThrows(BreachCheckException.class, () -> client.occurrences(pw)).code());
            routes.put("/range/", p -> new Reply(302, "", base.resolve("/elsewhere/" + p).toString()));
            int before = seen.size();
            assertEquals(BreachCheckException.Code.HTTP_STATUS, assertThrows(BreachCheckException.class, () -> client.occurrences(pw)).code());
            assertEquals(before + 1, seen.size(), "redirects are not followed");
            routes.put("/range/", p -> Reply.ok("not a range line"));
            BreachCheckException malformed = assertThrows(BreachCheckException.class, () -> client.occurrences(pw));
            assertEquals(BreachCheckException.Code.MALFORMED, malformed.code());
            assertEquals("MALFORMED", malformed.getMessage());
            routes.put("/range/", p -> Reply.ok(""));
            assertEquals(BreachCheckException.Code.MALFORMED,
                    assertThrows(BreachCheckException.class, () -> client.occurrences(pw)).code(),
                    "an empty 200 must not read as 'not breached'");
            routes.put("/range/", p -> Reply.ok("\r\n\r\n"));
            assertEquals(BreachCheckException.Code.MALFORMED, assertThrows(BreachCheckException.class, () -> client.occurrences(pw)).code());
            routes.put("/range/", p -> new Reply(200, "0".repeat(BreachClient.MAX_BODY_BYTES), null));
            assertEquals(BreachCheckException.Code.MALFORMED, assertThrows(BreachCheckException.class, () -> client.occurrences(pw)).code(),
                    "exactly the limit is read, then parsed");
            routes.put("/range/", p -> new Reply(200, "0".repeat(BreachClient.MAX_BODY_BYTES + 1), null));
            assertEquals(BreachCheckException.Code.TOO_LARGE, assertThrows(BreachCheckException.class, () -> client.occurrences(pw)).code());
        }
        server.stop(0);
        try (BreachClient client = BreachClient.create(base, Duration.ofSeconds(2)); SecretBytes pw = Records.secret(SAMPLE)) {
            assertEquals(BreachCheckException.Code.NETWORK, assertThrows(BreachCheckException.class, () -> client.occurrences(pw)).code());
        }
    }

    @Test
    void offlineHealthCheckNeverTouchesTheNetwork() {
        routes.put("/range/", p -> Reply.ok(rangeBody(1)));
        Instant now = Instant.parse("2026-10-03T12:00:00Z");
        try (BreachClient unused = BreachClient.create(base, TIMEOUT);
                LoginRecord r = Records.login(1, "password", now)) {
            assertFalse(new HealthCheck(Clock.fixed(now, ZoneOffset.UTC)).run(List.of(r)).isClean());
            assertEquals(base, unused.base());
        }
        assertEquals(List.of(), seen, "no request without an explicit occurrences() call");
    }

    @Test
    void baseUriValidation() {
        for (String bad : new String[] {"http://example.com/", "ftp://127.0.0.1/", "https://u:p@example.com/",
                "https://example.com/?q=1", "https://example.com/#f", "/relative", "HTTPS://example.com/",
                "http://127.0.0.1.example.com/", "https:///nohost"}) {
            assertThrows(IllegalArgumentException.class, () -> BreachClient.create(URI.create(bad), TIMEOUT), bad);
        }
        assertThrows(IllegalArgumentException.class, () -> BreachClient.create(base, Duration.ZERO));
        assertThrows(NullPointerException.class, () -> BreachClient.create(null, TIMEOUT));
        for (String ok : new String[] {"https://example.com", "http://localhost:8080/x/", "http://[::1]:9/", "http://127.0.0.2/"}) {
            try (BreachClient c = BreachClient.create(URI.create(ok), TIMEOUT)) {
                assertTrue(c.base().getRawPath().endsWith("/"), ok);
            }
        }
        try (BreachClient real = BreachClient.pwnedPasswords()) {
            assertEquals(URI.create("https://api.pwnedpasswords.com/"), real.base());
        }
    }

    @Test
    void strictRangeParsing() throws BreachCheckException, CryptoException {
        byte[] suffix = "0123456789ABCDEF0123456789ABCDEF012".getBytes(StandardCharsets.US_ASCII);
        String body = String.join("\r\n", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3",
                "0123456789ABCDEF0123456789ABCDEF012:7", "", "");
        assertEquals(7, BreachClient.match(bytes(body), suffix.clone()));
        assertEquals(BreachCheckException.Code.MALFORMED,
                assertThrows(BreachCheckException.class, () -> BreachClient.match(new byte[0], suffix.clone())).code());
        assertEquals(BreachCheckException.Code.MALFORMED,
                assertThrows(BreachCheckException.class, () -> BreachClient.match(bytes("\n\r\n"), suffix.clone())).code());
        byte[] consumed = suffix.clone();
        BreachClient.match(bytes("0123456789ABCDEF0123456789ABCDEF012:1"), consumed);
        assertEquals(0, consumed[0], "the suffix buffer is zero-filled after matching");
        for (String bad : new String[] {
            "0123456789abcdef0123456789ABCDEF012:1",     // lowercase hex
            "0123456789ABCDEF0123456789ABCDEF012 1",     // no colon
            "0123456789ABCDEF0123456789ABCDEF012:",      // no count
            "0123456789ABCDEF0123456789ABCDEF012:1x",    // non-digit count
            "0123456789ABCDEF0123456789ABCDEF012:1234567890123456789", // 19 digits
            "0123456789ABCDEF:1",                        // short line
            "0123456789ABCDEF0123456789ABCDEF0123:1"     // 36 hex
        }) {
            BreachCheckException e = assertThrows(BreachCheckException.class, () -> BreachClient.match(bytes(bad), suffix.clone()), bad);
            assertEquals(BreachCheckException.Code.MALFORMED, e.code());
        }
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }
}
