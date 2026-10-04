package pm.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import pm.domain.health.BreachCheckException;
import pm.domain.health.BreachClient;

/**
 * plan.md §13 M4.4: {@code pm health} reports weak, reused and old passwords offline; {@code --breach}
 * is opt-in, asks first, and talks only to a loopback stand-in for the range API here. Without
 * {@code --breach} (or when the user declines) no client is built and the server sees no request.
 */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-045: the stalling handler restores the interrupt flag
class HealthCommandTest {
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final String UNLOCK_PHRASE = "correct horse";
    /** SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8. */
    private static final String WEAK_PREFIX = "5BAA6";
    private static final String WEAK_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
    private static final String STRONG = "vH7#qR2!mZ9$wK4&tL6^pN";

    private final FakeVaultPort port = new FakeVaultPort().withVault(UNLOCK_PHRASE);
    private final List<String> paths = new CopyOnWriteArrayList<>();
    private final AtomicInteger clientsBuilt = new AtomicInteger();
    private final CountDownLatch release = new CountDownLatch(1);
    private HttpServer server;
    private URI base;
    private volatile String reply = WEAK_SUFFIX + ":42\r\n" + "0".repeat(35) + ":0\r\n";

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.createContext("/stall/", this::stall);
        server.start();
        base = URI.create("http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort() + "/");
        port.stored.add(FakeVaultPort.login("Mail", "password", NOW));
        port.stored.add(FakeVaultPort.login("Bank", STRONG, NOW));
        port.stored.add(FakeVaultPort.login("Shop", STRONG, NOW));
        port.stored.add(FakeVaultPort.login("Forum", "Zq8#vT3!kL7$nB5&", NOW.minus(Duration.ofDays(400))));
    }

    @AfterEach
    void stop() {
        release.countDown();
        server.stop(0);
    }

    private void handle(HttpExchange ex) throws IOException {
        paths.add(ex.getRequestURI().getPath());
        byte[] body = reply.getBytes(StandardCharsets.US_ASCII);
        try (ex; OutputStream os = ex.getResponseBody()) {
            ex.sendResponseHeaders(200, body.length);
            os.write(body);
        }
    }

    private void stall(HttpExchange ex) throws IOException {
        paths.add(ex.getRequestURI().getPath());
        try (ex) {
            ex.sendResponseHeaders(200, 100);
            if (!release.await(10, TimeUnit.SECONDS)) {
                return;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private int run(FakeConsoleIo io, URI target, String... args) {
        Map<String, String> props = Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, "/nonexistent-home");
        Cli cli = new Cli(props::get, Clock.fixed(NOW, ZoneOffset.UTC), p -> { }).withBreachClients(() -> {
            clientsBuilt.incrementAndGet();
            return BreachClient.create(target, Duration.ofMillis(800));
        });
        return cli.run(args, io, (path, creating) -> port);
    }

    private int run(FakeConsoleIo io, String... args) {
        return run(io, base, args);
    }

    @Test
    void offlineReportNamesWeakReusedAndOldByTitleOnly() {
        FakeConsoleIo io = new FakeConsoleIo().secret(UNLOCK_PHRASE);
        assertEquals(ExitCodes.OK, run(io, "health"), io::errText);
        String out = io.outText();
        assertTrue(out.contains(Messages.HEALTH_CHECKED.text() + "4"), out);
        assertTrue(out.contains(Messages.HEALTH_WEAK.text() + "1"), out);
        assertTrue(out.contains("Mail"), out);
        assertTrue(out.contains(Messages.HEALTH_REUSED.text() + "1"), out);
        assertTrue(out.contains("Bank, Shop") || out.contains("Shop, Bank"), out);
        assertTrue(out.contains("365 days: 1") && out.contains("Forum  400 days"), out);
        assertFalse(out.contains("password\n") || out.contains(STRONG), "no password is printed");
        assertTrue(io.allSecretsZeroed());
    }

    @Test
    void withoutBreachNoClientIsBuiltAndNoRequestIsSent() {
        FakeConsoleIo io = new FakeConsoleIo().secret(UNLOCK_PHRASE);
        assertEquals(ExitCodes.OK, run(io, "health", "--max-age-days", "30"), io::errText);
        assertEquals(0, clientsBuilt.get(), "no HTTP client exists without --breach");
        assertEquals(List.of(), paths, "the network is never touched without --breach");
        assertFalse(io.outText().contains(Messages.BREACH_NOTICE.text()));
    }

    @Test
    void breachAsksFirstAndSendsNothingWhenDeclined() {
        FakeConsoleIo io = new FakeConsoleIo().secret(UNLOCK_PHRASE).line("n");
        assertEquals(ExitCodes.OK, run(io, "health", "--breach"), io::errText);
        String out = io.outText();
        assertTrue(out.contains("Only the first 5 hex characters"), out);
        assertTrue(out.contains(Messages.BREACH_SKIPPED.text()), out);
        assertEquals(0, clientsBuilt.get());
        assertEquals(List.of(), paths);
    }

    @Test
    void confirmedBreachSendsOnePrefixPerDistinctPassword() {
        FakeConsoleIo io = new FakeConsoleIo().secret(UNLOCK_PHRASE).line("y");
        assertEquals(ExitCodes.OK, run(io, "health", "--breach"), io::errText);
        assertEquals(3, paths.size(), () -> "reuse group looked up once: " + paths);
        for (String p : paths) {
            assertTrue(p.matches("/range/[0-9A-F]{5}"), p);
        }
        assertTrue(paths.contains("/range/" + WEAK_PREFIX), paths::toString);
        String out = io.outText();
        assertTrue(out.contains(Messages.BREACH_FOUND.text() + "Mail  42 times"), out);
        assertTrue(out.contains(Messages.BREACH_SUMMARY.text() + "1 of 3"), out);
    }

    @Test
    void malformedAndTimedOutRepliesMapToClearMessages() {
        reply = "this is not a range reply";
        FakeConsoleIo bad = new FakeConsoleIo().secret(UNLOCK_PHRASE).line("y");
        assertEquals(ExitCodes.EXTERNAL, run(bad, "health", "--breach"));
        assertTrue(bad.errText().contains(Messages.BREACH_MALFORMED.text()), bad::errText);

        FakeConsoleIo slow = new FakeConsoleIo().secret(UNLOCK_PHRASE).line("y");
        assertEquals(ExitCodes.EXTERNAL, run(slow, base.resolve("/stall/"), "health", "--breach"));
        assertTrue(slow.errText().contains(Messages.BREACH_TIMEOUT.text()), slow::errText);
        assertTrue(slow.outText().contains(Messages.HEALTH_CHECKED.text()), "the offline report still printed");
    }

    @Test
    void everyFailureCodeHasAMessage() {
        for (BreachCheckException.Code code : BreachCheckException.Code.values()) {
            assertFalse(HealthCommand.breachMessage(code).text().isEmpty(), code::name);
        }
        assertEquals(Messages.BREACH_NETWORK, HealthCommand.breachMessage(BreachCheckException.Code.NETWORK));
    }

    @Test
    void badOptionsAreUsageErrors() {
        for (String[] args : new String[][] {{"health", "--max-age-days", "0"}, {"health", "--max-age-days", "x"},
            {"health", "extra"}, {"health", "--breach", "--breach"}}) {
            FakeConsoleIo io = new FakeConsoleIo().secret(UNLOCK_PHRASE);
            assertEquals(ExitCodes.USAGE, run(io, args), String.join(" ", args));
        }
        assertEquals(0, clientsBuilt.get());
    }

    @Test
    void onlyAnExactYConfirms() {
        for (String answer : List.of(" y", "y ", "Y", "yes", "")) {
            FakeConsoleIo io = new FakeConsoleIo().secret(UNLOCK_PHRASE).line(answer);
            assertEquals(ExitCodes.OK, run(io, "health", "--breach"), io::errText);
            assertTrue(io.outText().contains(Messages.BREACH_SKIPPED.text()), () -> "[" + answer + "] " + io.outText());
        }
        assertEquals(0, clientsBuilt.get());
        assertEquals(List.of(), paths);
    }

    @Test
    void nothingToLookUpSkipsThePromptAndTheClient() {
        FakeVaultPort empty = new FakeVaultPort().withVault(UNLOCK_PHRASE);
        FakeConsoleIo io = new FakeConsoleIo().secret(UNLOCK_PHRASE).line("y");
        Map<String, String> props = Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, "/nonexistent-home");
        Cli cli = new Cli(props::get, Clock.fixed(NOW, ZoneOffset.UTC), p -> { }).withBreachClients(() -> {
            clientsBuilt.incrementAndGet();
            return BreachClient.create(base, Duration.ofMillis(800));
        });
        assertEquals(ExitCodes.OK, cli.run(new String[] {"health", "--breach"}, io, (path, creating) -> empty),
                io::errText);
        assertTrue(io.outText().contains(Messages.BREACH_NOTHING.text()), io::outText);
        assertFalse(io.outText().contains(Messages.BREACH_NOTICE.text()), "no prompt");
        assertFalse(io.outText().contains(Messages.BREACH_CONFIRM.text()), "the confirmation was never asked");
        assertEquals(0, clientsBuilt.get());
        assertEquals(List.of(), paths);
    }

    @Test
    void closedInputAtTheConfirmationSendsNothing() {
        FakeConsoleIo io = new FakeConsoleIo().secret(UNLOCK_PHRASE);
        assertEquals(ExitCodes.USAGE, run(io, "health", "--breach"));
        assertEquals(0, clientsBuilt.get());
        assertEquals(List.of(), paths);
    }
}
