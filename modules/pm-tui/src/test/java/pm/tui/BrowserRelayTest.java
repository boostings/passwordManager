package pm.tui;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.function.Predicate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.approval.ApprovalBroker;
import pm.approval.AuditEvent;
import pm.approval.Decision;
import pm.approval.Grant;
import pm.approval.PendingApproval;
import pm.approval.PolicyStore;
import pm.approval.ipc.RunDir;
import pm.browser.bridge.Bridge;
import pm.browser.bridge.Origin;
import pm.browser.bridge.VaultPort;
import pm.browser.host.ExtensionAllowlist;
import pm.browser.host.HostException;
import pm.browser.host.Json;
import pm.browser.host.JsonText;
import pm.browser.host.Messages;
import pm.browser.host.NativeFrames;
import pm.browser.host.Request;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.domain.env.Env;

/**
 * ADR 0014 §8, SR-113: the relay between the native host process and the TUI. No TUI means
 * {@code DENIED_LOCKED}; only allowlisted extensions from a live process of this user are served;
 * a relayed fill waits for the TUI's broker and releases once per approval; an approval never
 * covers another connection; lookups are rate-limited and audited; one waiting prompt per process;
 * silent or non-reading peers are cut off; a host that disconnects mid-approval gets its prompt
 * withdrawn and nothing released; the socket's place depends on the vault path only, and a live
 * socket is never taken over.
 */
@Tag("T-EXT-08")
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: the host side runs on its own thread, as in its own process
class BrowserRelayTest {
    private static final String EXTENSION = "abcdefghijklmnopabcdefghijklmnop";
    private static final String OTHER = "ponmlkjihgfedcbaponmlkjihgfedcba";
    private static final String ME = System.getProperty("user.name");
    private static final String OS = System.getProperty("os.name");
    private static final String RELAY_PW = "relay-SECRET-pw";
    private static final UUID LOGIN = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final long LIMIT_NANOS = Duration.ofSeconds(20).toNanos();
    private static final String LOOKUP = "{\"type\":\"lookup\",\"id\":\"l1\",\"origin\":\"https://example.org\"}";
    private static final String OTHER_LOOKUP = "{\"type\":\"lookup\",\"id\":\"l2\",\"origin\":\"https://other.example\"}";
    private static final String WEBAUTHN_GET = "{\"type\":\"webauthn.get\",\"id\":\"a\",\"origin\":\"https://example.org\","
            + "\"rpId\":\"example.org\",\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0\",\"allowCredentials\":[],"
            + "\"credential\":null,\"userVerification\":\"preferred\"}";
    private static final String WEBAUTHN_CREATE = "{\"type\":\"webauthn.create\",\"id\":\"c\",\"origin\":\"https://example.org\","
            + "\"rpId\":\"example.org\",\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0\","
            + "\"user\":{\"id\":\"AQID\",\"name\":\"alice\",\"displayName\":\"Alice\"},"
            + "\"algorithms\":[-7],\"excludeCredentials\":[],\"userVerification\":\"preferred\"}";
    /** Short deadlines so a test waits a fraction of a second, not five. */
    private static final BrowserRelay.Limits FAST =
            new BrowserRelay.Limits(Duration.ofMillis(300), Duration.ofMillis(300), 20, 10);

    @TempDir
    Path tmp;

    /** What the broker audits: the user's answers. */
    private final List<AuditEvent> brokerAudit = new CopyOnWriteArrayList<>();
    private final ApprovalBroker broker = new ApprovalBroker(Clock.systemUTC(), brokerAudit::add, PolicyStore.inMemory(),
            ME);
    private final AtomicInteger released = new AtomicInteger();
    /** When set, {@code password} counts it down and then waits for {@link #letGo}: a slow vault. */
    private volatile CountDownLatch inPassword;
    private final CountDownLatch letGo = new CountDownLatch(1);
    private final ExecutorService hostSide = Executors.newCachedThreadPool();
    private final List<AuditEvent> audited = new CopyOnWriteArrayList<>();
    private final List<VaultPort.Login> logins = new CopyOnWriteArrayList<>(
            List.of(new VaultPort.Login(LOGIN, "Example", "alice", List.of("https://example.org"))));

    /** An unlocked vault with the logins in {@link #logins}. */
    private final VaultPort vault = new VaultPort() {
        @Override
        public List<Login> logins() {
            return List.copyOf(logins);
        }

        @Override
        public SecretBytes password(Grant grant, UUID entry) {
            CountDownLatch in = inPassword;
            if (in != null) {
                in.countDown();
                try {
                    assertTrue(letGo.await(LIMIT_NANOS, TimeUnit.NANOSECONDS), "the test lets the vault go on");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            grant.consume();
            released.incrementAndGet();
            return SecretBytes.copyOf(RELAY_PW.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public UUID save(Grant grant, Origin origin, String username, SecretChars password) {
            throw new UnsupportedOperationException();
        }
    };

    @AfterEach
    void stop() {
        hostSide.shutdownNow();
    }

    /** A default vault path (short: socket paths are limited) with {@link #EXTENSION} allowlisted. */
    private Path vaultFile() throws IOException {
        Path allow = tmp.resolve(ExtensionAllowlist.FILE_NAME);
        if (!Files.exists(allow)) {
            Files.writeString(allow, EXTENSION + "\n", StandardCharsets.UTF_8);
        }
        return tmp.resolve("v.pmv");
    }

    private BrowserRelay relay(Path vaultFile) throws BrowserRelay.NotStarted {
        return relay(vaultFile, FAST, audited::add);
    }

    private BrowserRelay relay(Path vaultFile, BrowserRelay.Limits limits, Predicate<AuditEvent> audit)
            throws BrowserRelay.NotStarted {
        broker.unlock();
        return BrowserRelay.start(vaultFile, new BrowserRelay.Wiring(broker, () -> vault, audit, Clock.systemUTC(), ME,
                Duration.ofMinutes(5), limits), OS);
    }

    private static Request decode(String json) throws HostException {
        return Messages.decode(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String fillJson() {
        return "{\"type\":\"fill\",\"id\":\"f1\",\"origin\":\"https://example.org\",\"entry\":\"" + LOGIN + "\"}";
    }

    private CompletableFuture<Json.Obj> ask(Path vaultFile, String json) {
        return ask(vaultFile, EXTENSION, json);
    }

    private CompletableFuture<Json.Obj> ask(Path vaultFile, String extension, String json) {
        return CompletableFuture.supplyAsync(() -> {
            try (Request r = decode(json)) {
                return BrowserRelay.ask(vaultFile, extension, r);
            } catch (HostException e) {
                return Messages.error(null, e.getMessage());
            }
        }, hostSide);
    }

    /** Connects and sends {@code header} and {@code json} as the host would, without reading. */
    private static SocketChannel send(Path vaultFile, String header, String json) throws IOException, HostException {
        SocketChannel ch = SocketChannel.open(UnixDomainSocketAddress.of(BrowserRelay.socketPath(vaultFile)));
        try (SecretBytes caller = SecretBytes.copyOf(header.getBytes(StandardCharsets.US_ASCII));
                SecretBytes body = SecretBytes.copyOf(json.getBytes(StandardCharsets.UTF_8))) {
            NativeFrames.write(Channels.newOutputStream(ch), caller);
            NativeFrames.write(Channels.newOutputStream(ch), body);
        }
        return ch;
    }

    private static String header(String extension) {
        return extension + " " + BrowserRelay.HOST_INSTANCE; // the same host as ask(..)
    }

    private static Json.Obj replyOn(SocketChannel ch) throws IOException, HostException {
        byte[] frame = NativeFrames.read(Channels.newInputStream(ch));
        return (Json.Obj) JsonText.parse(new String(frame, StandardCharsets.UTF_8).toCharArray());
    }

    /** Connections a test holds open to fill the relay's slots; all closed at the end. */
    private static final class Held implements AutoCloseable {
        private final List<SocketChannel> channels = new ArrayList<>();

        void add(SocketChannel ch) {
            channels.add(ch);
        }

        /** Whether the relay closed every one: a read sees the end of the stream at once. */
        boolean allEnded() throws IOException {
            boolean ended = true;
            for (int i = 0; i < channels.size(); i++) {
                ended &= channels.get(i).read(ByteBuffer.allocate(1)) == -1;
            }
            return ended;
        }

        /** For each one, "cut" if no whole reply frame arrives, else the reply's type and code. */
        List<String> replies() {
            List<String> seen = new ArrayList<>();
            for (int i = 0; i < channels.size(); i++) {
                try {
                    Json.Obj reply = replyOn(channels.get(i));
                    seen.add(text(reply, "type") + " " + text(reply, "code"));
                } catch (IOException | HostException | RuntimeException e) {
                    seen.add("cut"); // truncated, or reset by the relay
                }
            }
            return seen;
        }

        @Override
        public void close() throws IOException {
            for (int i = 0; i < channels.size(); i++) {
                channels.get(i).close();
            }
        }
    }

    private static void waitFor(BooleanSupplier done) {
        long start = System.nanoTime();
        while (!done.getAsBoolean()) {
            if (System.nanoTime() - start > LIMIT_NANOS) {
                throw new AssertionError("timed out waiting");
            }
            Thread.onSpinWait();
        }
    }

    private static String text(Json.Obj reply, String member) {
        return ((Json.Str) reply.get(member)).text();
    }

    // ---- where the socket lives ------------------------------------------------------------

    @Test
    void withNoTuiTheHostIsToldPmIsLocked() throws HostException {
        try (Request r = decode(fillJson())) {
            HostException e = assertThrows(HostException.class,
                    () -> BrowserRelay.ask(tmp.resolve("none.pmv"), EXTENSION, r));
            assertEquals(Decision.DENIED_LOCKED.name(), e.getMessage());
        }
    }

    @Test
    void theSocketDependsOnTheVaultPathOnly() throws IOException {
        Path vault = tmp.resolve("v.pmv");
        assertEquals(tmp.resolve("v.pmv" + BrowserRelay.DIR_SUFFIX).resolve(BrowserRelay.SOCKET),
                BrowserRelay.socketPath(vault));
        assertEquals(BrowserRelay.socketPath(vault), BrowserRelay.socketPath(tmp.resolve("x").resolve("..").resolve("v.pmv")));
        // Too long for an AF_UNIX address: refused with a clear reason, not a bind error.
        Path deep = tmp.resolve("d".repeat(100)).resolve("v.pmv");
        assertFalse(BrowserRelay.fitsSocketPath(BrowserRelay.socketPath(deep), "Mac OS X"));
        BrowserRelay.NotStarted e = assertThrows(BrowserRelay.NotStarted.class, () -> relay(deep));
        assertEquals(BrowserRelay.Unavailable.PATH_TOO_LONG, e.reason());
        assertFalse(Files.exists(BrowserRelay.socketDir(deep)), "nothing created");
    }

    /**
     * The length limit is the one the JDK enforces (sun_path less two bytes: 102 on macOS, 106 on
     * Linux), checked against the real bind on this OS: a socket path of limit-1 and limit bytes
     * is served, limit+1 is refused before anything is created, and the JDK itself refuses it.
     */
    @Test
    void theSocketPathLimitIsTheOneTheJdkBinds() throws IOException, BrowserRelay.NotStarted {
        assertEquals(102, BrowserRelay.maxSocketPathBytes("Mac OS X"));
        assertEquals(102, BrowserRelay.maxSocketPathBytes("FreeBSD"));
        assertEquals(106, BrowserRelay.maxSocketPathBytes("Linux"));
        int limit = BrowserRelay.maxSocketPathBytes(OS);
        for (int bytes : new int[] {limit - 1, limit}) {
            Path v = vaultWithSocketOf(bytes);
            try (BrowserRelay relay = relay(v)) {
                assertEquals(bytes, relay.socketPath().toString().getBytes(StandardCharsets.UTF_8).length);
                assertTrue(BrowserRelay.isLive(relay.socketPath()), bytes + " bytes are served");
            }
        }
        Path over = vaultWithSocketOf(limit + 1);
        BrowserRelay.NotStarted e = assertThrows(BrowserRelay.NotStarted.class, () -> relay(over));
        assertEquals(BrowserRelay.Unavailable.PATH_TOO_LONG, e.reason());
        assertFalse(Files.exists(BrowserRelay.socketDir(over)), "nothing created");
        Files.createDirectories(BrowserRelay.socketDir(over));
        try (ServerSocketChannel ch = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            IOException refused = assertThrows(IOException.class,
                    () -> ch.bind(UnixDomainSocketAddress.of(BrowserRelay.socketPath(over))));
            assertEquals("Unix domain path too long", refused.getMessage(), "the JDK's own limit is limit+1");
        }
    }

    /**
     * A bind that fails is reported for what it is: a path too long for this OS is
     * {@code PATH_TOO_LONG}, a live socket {@code IN_USE}, anything else {@code UNSAFE}, never
     * {@code IN_USE} without a live socket.
     */
    @Test
    void aFailedBindIsReportedForWhatItIs() throws IOException, BrowserRelay.NotStarted {
        int limit = BrowserRelay.maxSocketPathBytes(OS);
        Path over = BrowserRelay.socketPath(vaultWithSocketOf(limit + 1));
        assertEquals(BrowserRelay.Unavailable.PATH_TOO_LONG, BrowserRelay.bindFailure(over, OS));
        Path v = vaultFile();
        Path quiet = BrowserRelay.socketPath(v);
        assertEquals(BrowserRelay.Unavailable.UNSAFE, BrowserRelay.bindFailure(quiet, OS), "nothing listens");
        try (BrowserRelay relay = relay(v)) {
            assertEquals(BrowserRelay.Unavailable.IN_USE, BrowserRelay.bindFailure(relay.socketPath(), OS));
        }
    }

    /**
     * Where the claimed OS allows a longer path than the real one (a macOS JVM told it runs on
     * Linux), the JDK's refusal at bind is still {@code PATH_TOO_LONG}, not {@code IN_USE}.
     */
    @Test
    void aBindRefusedForLengthIsPathTooLong() throws IOException {
        int limit = BrowserRelay.maxSocketPathBytes(OS);
        assumeTrue(limit < BrowserRelay.LINUX_SOCKET_PATH_BYTES, "only where another OS allows longer paths");
        for (int bytes = limit + 1; bytes <= BrowserRelay.LINUX_SOCKET_PATH_BYTES; bytes++) {
            Path v = vaultWithSocketOf(bytes);
            BrowserRelay.NotStarted e = assertThrows(BrowserRelay.NotStarted.class,
                    () -> BrowserRelay.start(v, new BrowserRelay.Wiring(broker, () -> vault, audited::add,
                            Clock.systemUTC(), ME, Duration.ofMinutes(5), FAST), "Linux"));
            assertEquals(BrowserRelay.Unavailable.PATH_TOO_LONG, e.reason(), bytes + " bytes");
            assertFalse(Files.exists(BrowserRelay.socketPath(v)), "no socket left behind");
        }
    }

    /** A vault file in {@code tmp} whose relay socket path is {@code bytes} bytes long. */
    private Path vaultWithSocketOf(int bytes) throws IOException {
        vaultFile(); // the allowlist
        int overhead = tmp.toString().getBytes(StandardCharsets.UTF_8).length + 1 + BrowserRelay.DIR_SUFFIX.length()
                + 1 + BrowserRelay.SOCKET.length();
        assertTrue(bytes - overhead >= 1, "the temporary folder is short enough: " + tmp);
        Path v = tmp.resolve("v".repeat(bytes - overhead));
        assertEquals(bytes, BrowserRelay.socketPath(v).toString().getBytes(StandardCharsets.UTF_8).length);
        return v;
    }

    @Test
    void aStoppedTuiLeavesNoSocketBehind() throws IOException, HostException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        relay(v).close();
        assertFalse(Files.exists(BrowserRelay.socketPath(v)));
        try (Request r = decode(fillJson())) {
            HostException e = assertThrows(HostException.class, () -> BrowserRelay.ask(v, EXTENSION, r));
            assertEquals(Decision.DENIED_LOCKED.name(), e.getMessage());
        }
    }

    @Test
    void aSecondTuiDoesNotStealALiveSocket() throws IOException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        try (BrowserRelay first = relay(v)) {
            assertTrue(Files.exists(first.socketPath()));
            BrowserRelay.NotStarted e = assertThrows(BrowserRelay.NotStarted.class, () -> relay(v));
            assertEquals(BrowserRelay.Unavailable.IN_USE, e.reason());
            assertTrue(BrowserRelay.isLive(first.socketPath()), "the first relay still serves");
            assertEquals("lookup", text(ask(v, LOOKUP).join(), "type"));
        }
    }

    @Test
    void aLiveSocketWithoutTheLockIsNotStolenEither() throws IOException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        try (BrowserRelay first = relay(v)) {
            assertTrue(Files.exists(first.socketPath()));
            // Another process's relay: its lock is not visible here, only its live socket.
            Files.delete(BrowserRelay.socketDir(v).resolve(BrowserRelay.LOCK_FILE));
            BrowserRelay.NotStarted e = assertThrows(BrowserRelay.NotStarted.class, () -> relay(v));
            assertEquals(BrowserRelay.Unavailable.IN_USE, e.reason());
            assertTrue(Files.exists(first.socketPath()));
        }
    }

    @Test
    void aStaleSocketIsReplaced() throws IOException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        Path socket = BrowserRelay.socketPath(v);
        try (BrowserRelay crashed = relay(v)) {
            assertTrue(Files.exists(crashed.socketPath()));
            assertTrue(Files.exists(socket));
        }
        // A crashed TUI leaves its socket file: bind one that nobody accepts on.
        try (ServerSocketChannel dead =
                ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            dead.bind(UnixDomainSocketAddress.of(socket));
        }
        assertTrue(Files.exists(socket));
        assertFalse(BrowserRelay.isLive(socket));
        try (BrowserRelay next = relay(v)) {
            assertTrue(Files.exists(next.socketPath()));
            assertEquals("lookup", text(ask(v, LOOKUP).join(), "type"));
        }
    }

    @Test
    void theTuiServesTheRelayOnlyOnTheDefaultVaultAndOnlyWhileRunning() throws IOException {
        Path v = vaultFile();
        Path socket = BrowserRelay.socketPath(v);
        // The TUI's environment is irrelevant: the host (with none) finds the socket by the vault path.
        Env env = Env.of(Map.of("XDG_RUNTIME_DIR", tmp.resolve("xdg").toString()));
        Files.createDirectories(tmp.resolve("xdg"));
        try (ApprovalHost other = ApprovalHost.socketFor(v, env, Clock.systemUTC(), ME, false)) {
            other.unlocked(grant -> new TreeMap<>());
            assertFalse(Files.exists(socket), "not the default vault: no relay");
            assertEquals(Optional.of(pm.tui.Messages.BROWSER_NOT_DEFAULT), other.browserNote());
        }
        try (ApprovalHost host = ApprovalHost.socketFor(v, env, Clock.systemUTC(), ME, true)) {
            assertEquals(Optional.empty(), host.browserNote());
            host.unlocked(grant -> new TreeMap<>());
            assertTrue(Files.exists(socket));
            Json.Obj reply = ask(v, LOOKUP).join();
            assertEquals("error", text(reply, "type"));
            assertEquals(Decision.DENIED_LOCKED.name(), text(reply, "code"), "no browser port was handed over yet");
            // A second window with its own run folder: its broker starts, the browser relay does not.
            Env elsewhere = Env.of(Map.of("XDG_RUNTIME_DIR", tmp.resolve("xdg2").toString()));
            Files.createDirectories(tmp.resolve("xdg2"));
            try (ApprovalHost second = ApprovalHost.socketFor(v, elsewhere, Clock.systemUTC(), ME, true)) {
                second.unlocked(grant -> new TreeMap<>());
                assertTrue(second.broker().isPresent());
                assertEquals(Optional.of(pm.tui.Messages.browserOff(BrowserRelay.Unavailable.IN_USE)),
                        second.browserNote(), "a second window says why it does not serve the browser");
            }
            // A second window on the same run folder: the live broker socket is not taken either.
            try (ApprovalHost third = ApprovalHost.socketFor(v, env, Clock.systemUTC(), ME, true)) {
                third.unlocked(grant -> new TreeMap<>());
                assertEquals(Optional.empty(), third.broker());
                assertEquals(Optional.of(pm.tui.Messages.browserOff(BrowserRelay.Unavailable.IN_USE)),
                        third.browserNote());
            }
            assertTrue(BrowserRelay.isLive(socket), "closing the other windows left the first one's relay");
            assertTrue(host.broker().isPresent());
            assertTrue(Files.exists(tmp.resolve("xdg").resolve("pm").resolve(RunDir.SOCKET)),
                    "and its broker socket");
        }
        assertFalse(Files.exists(socket));
    }

    // ---- who may ask -----------------------------------------------------------------------

    @Test
    void lookupNeedsNoPromptAndFillReleasesOncePerApproval() throws IOException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        try (BrowserRelay relay = relay(v)) {
            assertTrue(Files.exists(relay.socketPath()));
            Json.Obj lookup = ask(v, LOOKUP).join();
            assertEquals("lookup", text(lookup, "type"), lookup.toString());
            assertEquals(0, released.get());

            CompletableFuture<Json.Obj> fill = ask(v, fillJson());
            waitFor(() -> !broker.pending().isEmpty());
            PendingApproval prompt = broker.pending().get(0);
            assertTrue(prompt.request().requester().label().startsWith(EXTENSION + " #"),
                    "the label names the connection: " + prompt.request().requester().label());
            assertEquals("https://example.org", prompt.request().scope().project());
            String peer = relay.peerOf(prompt.request().requestId()).orElseThrow();
            assertEquals("browser host " + BrowserRelay.HOST_INSTANCE.substring(0, 8) + " (unverified)", peer);
            assertEquals(0, released.get(), "nothing before the user answers");
            prompt.approveOnce();
            Json.Obj reply = fill.join();
            assertEquals("fill", text(reply, "type"), reply.toString());
            assertEquals(RELAY_PW, text(reply, "password"));
            assertEquals(1, released.get());
            assertEquals(Optional.empty(), relay.peerOf(prompt.request().requestId()), "forgotten once answered");

            CompletableFuture<Json.Obj> denied = ask(v, fillJson());
            waitFor(() -> !broker.pending().isEmpty());
            broker.pending().get(0).deny();
            assertEquals(Decision.DENIED.name(), text(denied.join(), "code"));
            assertEquals(1, released.get(), "a denial releases nothing");
        }
    }

    @Test
    void aWellFormedButNotAllowlistedExtensionIsDeniedWithoutAPrompt() throws IOException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        try (BrowserRelay relay = relay(v)) {
            assertTrue(Files.exists(relay.socketPath()));
            Json.Obj reply = ask(v, OTHER, fillJson()).join();
            assertEquals(Decision.DENIED_AUTH.name(), text(reply, "code"), reply.toString());
            Json.Obj lookup = ask(v, OTHER, LOOKUP).join();
            assertEquals(Decision.DENIED_AUTH.name(), text(lookup, "code"));
            assertTrue(broker.pending().isEmpty(), "never prompted");
            assertTrue(audited.isEmpty(), "nothing served, nothing to audit");
            // Taken off the allowlist while the TUI runs: refused from the next request on.
            assertEquals("lookup", text(ask(v, LOOKUP).join(), "type"));
            Files.writeString(tmp.resolve(ExtensionAllowlist.FILE_NAME), OTHER + "\n", StandardCharsets.UTF_8);
            assertEquals(Decision.DENIED_AUTH.name(), text(ask(v, LOOKUP).join(), "code"));
        }
    }

    /**
     * Taken off the allowlist while its prompt waits: the TUI would deny the prompt unseen, and an
     * approval that arrives anyway gets {@code DENIED_AUTH} with nothing released.
     */
    @Test
    void anExtensionTakenOffTheAllowlistWhileItsPromptWaitsGetsNothing() throws IOException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        try (BrowserRelay relay = relay(v)) {
            CompletableFuture<Json.Obj> fill = ask(v, fillJson());
            waitFor(() -> !broker.pending().isEmpty());
            PendingApproval prompt = broker.pending().get(0);
            UUID id = prompt.request().requestId();
            assertTrue(relay.stillAllowed(id));
            Files.writeString(tmp.resolve(ExtensionAllowlist.FILE_NAME), OTHER + "\n", StandardCharsets.UTF_8);
            assertFalse(relay.stillAllowed(id), "read again: the dialog denies it unseen");
            prompt.approveOnce(); // approved anyway
            Json.Obj reply = fill.join();
            assertEquals(Decision.DENIED_AUTH.name(), text(reply, "code"), reply.toString());
            assertEquals(0, released.get(), "nothing released");
            assertTrue(relay.stillAllowed(LOGIN), "a prompt the relay did not ask is not its to drop");
            // m54c-002: the broker audited the user's approval; the refusal is audited after it.
            assertEquals(List.of(Optional.of(Decision.ALLOWED_ONCE.name())),
                    brokerAudit.stream().filter(e -> e.requestId().equals(Optional.of(id)) && e.decision().isPresent())
                            .map(AuditEvent::decision).toList());
            assertOverruled(id, prompt.request().scope().profile(), Decision.DENIED_AUTH);
        }
    }

    /** The one relay audit entry: {@code request}'s approval overruled with {@code refusal}. */
    private void assertOverruled(UUID request, String profile, Decision refusal) {
        assertEquals(1, audited.size(), audited::toString);
        AuditEvent e = audited.get(0);
        assertEquals("approval", e.kind());
        assertEquals(Optional.of(request), e.requestId());
        assertEquals(Optional.of(refusal.name()), e.decision());
        assertEquals(Optional.of("https://example.org"), e.project());
        assertEquals(Optional.of(profile), e.profile());
        assertEquals(Optional.of(ME), e.osUser());
        assertEquals(Optional.of("EXTENSION"), e.requesterKind());
    }

    /**
     * Taken off the allowlist after the user approved, while the vault reads the password (a slow
     * vault): the allowlist is read again once the secret is in hand, just before the reply is
     * written, so the password is read but never sent, and the refusal is audited after the
     * approval.
     */
    @Test
    void aPasswordReadWhileTheExtensionIsTakenOffTheAllowlistIsNeverSent() throws IOException, InterruptedException,
            BrowserRelay.NotStarted {
        Path v = vaultFile();
        try (BrowserRelay relay = relay(v)) {
            CountDownLatch reading = new CountDownLatch(1);
            inPassword = reading;
            CompletableFuture<Json.Obj> fill = ask(v, fillJson());
            waitFor(() -> !broker.pending().isEmpty());
            PendingApproval prompt = broker.pending().get(0);
            prompt.approveOnce();
            assertTrue(reading.await(LIMIT_NANOS, TimeUnit.NANOSECONDS), "the vault is reading the password");
            Files.writeString(tmp.resolve(ExtensionAllowlist.FILE_NAME), OTHER + "\n", StandardCharsets.UTF_8);
            letGo.countDown();
            Json.Obj reply = fill.join();
            assertEquals(Decision.DENIED_AUTH.name(), text(reply, "code"), reply.toString());
            assertNull(reply.get("password"), "the password never leaves the TUI");
            assertEquals(1, released.get(), "read from the vault, then withheld");
            assertEquals(Optional.empty(), relay.peerOf(prompt.request().requestId()), "forgotten once answered");
            assertOverruled(prompt.request().requestId(), prompt.request().scope().profile(), Decision.DENIED_AUTH);
        } finally {
            inPassword = null;
        }
    }

    @Test
    void aHeaderWithoutAHostInstanceIsClosedUnanswered() throws IOException, HostException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        assertTrue(BrowserRelay.HOST_INSTANCE.matches("[0-9a-f]{32}"), BrowserRelay.HOST_INSTANCE);
        try (BrowserRelay relay = relay(v)) {
            assertTrue(Files.exists(relay.socketPath()));
            String hex = "0123456789abcdef0123456789abcdef";
            // a process ID (the old form), upper case, one short, one long, two spaces
            for (String host : List.of("4242", hex.toUpperCase(Locale.ROOT), hex.substring(1), hex + "0", " " + hex)) {
                try (SocketChannel ch = send(v, EXTENSION + " " + host, fillJson())) {
                    assertEquals(-1, ch.read(ByteBuffer.allocate(1)), host);
                }
            }
            assertTrue(broker.pending().isEmpty());
            try (SocketChannel ch = send(v, EXTENSION + " " + hex, LOOKUP)) { // any well-formed instance
                assertEquals("lookup", text(replyOn(ch), "type"));
            }
        }
    }

    @Test
    void aMalformedCallerIsDropped() throws IOException, HostException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        try (BrowserRelay relay = relay(v)) {
            assertTrue(Files.exists(relay.socketPath()));
            for (String header : List.of("not-an-extension-id 1", EXTENSION, EXTENSION + " 0", EXTENSION + " -1",
                    EXTENSION + "  1", EXTENSION + " 1 2")) {
                try (SocketChannel ch = send(v, header, fillJson())) {
                    assertThrows(HostException.class, () -> NativeFrames.read(Channels.newInputStream(ch)),
                            "closed without a reply: " + header);
                }
            }
            assertTrue(Files.exists(relay.socketPath()), "the relay serves on");
            assertTrue(broker.pending().isEmpty());
        }
    }

    @Test
    void anApprovalForTheSessionNeverCoversAnotherConnection() throws IOException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        try (BrowserRelay relay = relay(v)) {
            assertTrue(Files.exists(relay.socketPath()));
            CompletableFuture<Json.Obj> first = ask(v, fillJson());
            waitFor(() -> !broker.pending().isEmpty());
            PendingApproval once = broker.pending().get(0);
            once.approveForSession(); // the broker's session policy for this requester
            assertEquals("fill", text(first.join(), "type"));

            CompletableFuture<Json.Obj> second = ask(v, fillJson()); // a new host process or connection
            waitFor(() -> !broker.pending().isEmpty());
            PendingApproval again = broker.pending().get(0);
            assertNotEquals(once.request().requester().label(), again.request().requester().label());
            assertEquals(1, released.get(), "the second request waits for its own approval");
            again.deny();
            assertEquals(Decision.DENIED.name(), text(second.join(), "code"));
            assertEquals(1, released.get());
        }
    }

    @Test
    void aProcessGetsOneWaitingPromptAtATime() throws IOException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        try (BrowserRelay relay = relay(v)) {
            assertTrue(Files.exists(relay.socketPath()));
            CompletableFuture<Json.Obj> first = ask(v, fillJson());
            waitFor(() -> !broker.pending().isEmpty());
            Json.Obj busy = ask(v, fillJson()).join(); // same process, while the first prompt waits
            assertEquals(Decision.DENIED_BUSY.name(), text(busy, "code"), busy.toString());
            assertEquals(1, broker.pending().size());
            broker.pending().get(0).deny();
            assertEquals(Decision.DENIED.name(), text(first.join(), "code"));
            CompletableFuture<Json.Obj> next = ask(v, fillJson());
            waitFor(() -> !broker.pending().isEmpty());
            broker.pending().get(0).deny();
            assertEquals(Decision.DENIED.name(), text(next.join(), "code"), "a new prompt once the first is answered");
        }
    }

    // ---- lookups: rate limit and audit -----------------------------------------------------

    @Test
    void lookupsAreAuditedWithOriginAndCountOnly() throws IOException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        try (BrowserRelay relay = relay(v)) {
            assertTrue(Files.exists(relay.socketPath()));
            assertEquals("lookup", text(ask(v, LOOKUP).join(), "type"));
            assertEquals(1, audited.size());
            AuditEvent e = audited.get(0);
            assertEquals("approval", e.kind());
            assertEquals(Optional.of("EXTENSION"), e.requesterKind());
            assertEquals(Optional.of(ME), e.osUser());
            assertEquals(Optional.of("https://example.org"), e.project());
            assertEquals(Optional.of(BrowserRelay.LOOKUP_PROFILE), e.profile());
            assertEquals(1, e.varCount(), "the number of logins found");
            assertEquals(Optional.of(Decision.ALLOWED_ONCE.name()), e.decision());
            assertFalse(e.toString().contains("Example") || e.toString().contains("alice"),
                    "no title or username: " + e);
        }
    }

    @Test
    void noAuditEntryMeansNoLookupAnswer() throws IOException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        BrowserRelay.Limits one = new BrowserRelay.Limits(Duration.ofMillis(300), Duration.ofMillis(300), 20, 1);
        try (BrowserRelay relay = relay(v, one, e -> false)) {
            assertTrue(Files.exists(relay.socketPath()));
            Json.Obj reply = ask(v, LOOKUP).join();
            assertEquals(HostException.Code.INTERNAL.name(), text(reply, "code"), reply.toString());
            assertFalse(reply.toString().contains("alice"));
            assertEquals(HostException.Code.INTERNAL.name(), text(ask(v, LOOKUP).join(), "code"),
                    "the refusal could not be audited either");
            assertEquals(Decision.DENIED_BUSY.name(), text(ask(v, LOOKUP).join(), "code"));
        }
    }

    @Test
    void aBurstOfLookupsIsRefusedAndAuditedOnce() throws IOException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        BrowserRelay.Limits two = new BrowserRelay.Limits(Duration.ofMillis(300), Duration.ofMillis(300), 20, 2);
        try (BrowserRelay relay = relay(v, two, audited::add)) {
            assertTrue(Files.exists(relay.socketPath()));
            assertEquals("lookup", text(ask(v, LOOKUP).join(), "type"));
            assertEquals("lookup", text(ask(v, LOOKUP).join(), "type"));
            for (int i = 0; i < 5; i++) {
                assertEquals(Decision.DENIED_BUSY.name(), text(ask(v, LOOKUP).join(), "code"));
            }
            assertEquals(3, audited.size(), "two lookups and one refusal: " + audited);
            assertEquals(Optional.of(Decision.DENIED_BUSY.name()), audited.get(2).decision());
        }
    }

    @Test
    void theLookupBucketsLimitEachProcessAndAllTogetherAndRefill() {
        BrowserRelay.LookupLimiter limiter = new BrowserRelay.LookupLimiter(
                new BrowserRelay.Limits(Duration.ofSeconds(5), Duration.ofSeconds(5), 4, 2));
        Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
        assertEquals(BrowserRelay.LookupLimiter.Verdict.SERVE, limiter.take("a", t0));
        assertEquals(BrowserRelay.LookupLimiter.Verdict.SERVE, limiter.take("a", t0));
        assertEquals(BrowserRelay.LookupLimiter.Verdict.BUSY_FIRST, limiter.take("a", t0), "per process");
        assertEquals(BrowserRelay.LookupLimiter.Verdict.SERVE, limiter.take("b", t0));
        assertEquals(BrowserRelay.LookupLimiter.Verdict.SERVE, limiter.take("b", t0));
        assertEquals(BrowserRelay.LookupLimiter.Verdict.BUSY, limiter.take("c", t0), "in all; audited once a minute");
        Instant later = t0.plusSeconds(30); // half a minute refills half of each bucket
        assertEquals(BrowserRelay.LookupLimiter.Verdict.SERVE, limiter.take("c", later));
        assertEquals(BrowserRelay.LookupLimiter.Verdict.SERVE, limiter.take("a", later));
        assertEquals(BrowserRelay.LookupLimiter.Verdict.BUSY, limiter.take("b", later), "global bucket empty again");
        Instant minuteOn = t0.plusSeconds(61);
        assertEquals(BrowserRelay.LookupLimiter.Verdict.SERVE, limiter.take("b", minuteOn), "refilled");
        assertEquals(BrowserRelay.LookupLimiter.Verdict.SERVE, limiter.take("d", minuteOn));
        assertEquals(BrowserRelay.LookupLimiter.Verdict.BUSY_FIRST, limiter.take("e", minuteOn),
                "a minute after the last audited refusal, the next one is audited again");
        assertEquals(BrowserRelay.LookupLimiter.Verdict.BUSY, limiter.take("e", t0), "a clock going back refills nothing");
    }

    @Test
    void theLimiterForgetsTheOldestProcessesBeyondItsBound() {
        BrowserRelay.LookupLimiter limiter = new BrowserRelay.LookupLimiter(
                new BrowserRelay.Limits(Duration.ofSeconds(5), Duration.ofSeconds(5), 1000, 1));
        Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
        assertEquals(BrowserRelay.LookupLimiter.Verdict.SERVE, limiter.take("p0", t0));
        assertEquals(BrowserRelay.LookupLimiter.Verdict.BUSY_FIRST, limiter.take("p0", t0), "one a minute each");
        for (int i = 1; i <= 64; i++) {
            assertEquals(BrowserRelay.LookupLimiter.Verdict.SERVE, limiter.take("p" + i, t0));
        }
        assertEquals(BrowserRelay.LookupLimiter.Verdict.SERVE, limiter.take("p0", t0),
                "p0 was forgotten after 64 newer processes; memory stays bounded");
    }

    // ---- slots: silent and non-reading peers -----------------------------------------------

    @Test
    void silentPeersAreCutOffAtTheHeaderDeadline() throws IOException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        try (BrowserRelay relay = relay(v)) {
            assertTrue(Files.exists(relay.socketPath()));
            try (Held silent = new Held()) {
                for (int i = 0; i < BrowserRelay.MAX_CONNECTIONS; i++) {
                    silent.add(SocketChannel.open(UnixDomainSocketAddress.of(relay.socketPath())));
                }
                long start = System.nanoTime();
                Json.Obj reply = ask(v, LOOKUP).join();
                while (!"lookup".equals(text(reply, "type")) && System.nanoTime() - start < LIMIT_NANOS) {
                    assertEquals(Decision.DENIED_BUSY.name(), text(reply, "code"), "only busy while the slots are held");
                    reply = ask(v, LOOKUP).join();
                }
                assertEquals("lookup", text(reply, "type"), reply.toString());
                assertTrue(System.nanoTime() - start < Duration.ofSeconds(5).toNanos(), "within the deadline");
                assertTrue(silent.allEnded(), "every silent peer was disconnected");
            }
        }
    }

    @Test
    void peersThatDoNotReadTheirReplyAreCutOffAtTheWriteDeadline() throws IOException, HostException,
            BrowserRelay.NotStarted {
        Path v = vaultFile();
        // A lookup reply (about 770 KiB, under the 1 MiB frame limit) far larger than any socket
        // buffer: its write blocks until the peer reads.
        logins.clear();
        for (int i = 0; i < Bridge.MAX_LOOKUP; i++) {
            logins.add(new VaultPort.Login(new UUID(0, i + 1L), "t".repeat(12_000), "u", List.of("https://example.org")));
        }
        assertTrue(logins.stream().mapToInt(l -> l.title().length()).sum() > 512 * 1024,
                "each stuck reply is far larger than an AF_UNIX socket buffer (8 KiB by default on macOS)");
        try (BrowserRelay relay = relay(v)) {
            assertTrue(Files.exists(relay.socketPath()));
            try (Held stuck = new Held()) {
                for (int i = 0; i < BrowserRelay.MAX_CONNECTIONS; i++) {
                    stuck.add(send(v, header(EXTENSION), LOOKUP));
                }
                // The probe asks for a site with no logins: its small reply is never itself cut off
                // by the write deadline, whatever the load on the machine.
                long start = System.nanoTime();
                Json.Obj reply = ask(v, OTHER_LOOKUP).join();
                while (!"lookup".equals(text(reply, "type")) && System.nanoTime() - start < LIMIT_NANOS) {
                    assertEquals(Decision.DENIED_BUSY.name(), text(reply, "code"), "only busy while the slots are held");
                    reply = ask(v, OTHER_LOOKUP).join();
                }
                assertEquals("lookup", text(reply, "type"), "a real lookup is served");
                assertTrue(System.nanoTime() - start < Duration.ofSeconds(5).toNanos(), "within the deadline");
                // A stuck peer's slot is freed only when its reply is written in full or the peer is
                // cut off. Its reply is far larger than any socket buffer and it never reads, so once
                // the relay is idle every one was cut off; reading earlier would drain a peer whose
                // deadline has not yet passed and let its write finish.
                waitFor(() -> relay.busy() == 0);
                assertEquals(Collections.nCopies(BrowserRelay.MAX_CONNECTIONS, "cut"), stuck.replies(),
                        "each was cut off before its whole reply was written");
            }
        }
    }

    // ---- the host going away, and the wire format ------------------------------------------

    @Test
    void aHostThatDisconnectsMidApprovalGetsItsPromptWithdrawn() throws IOException, HostException,
            BrowserRelay.NotStarted {
        Path v = vaultFile();
        try (BrowserRelay relay = relay(v); SocketChannel ch = send(v, header(EXTENSION), fillJson())) {
            assertTrue(Files.exists(relay.socketPath()));
            waitFor(() -> !broker.pending().isEmpty());
            assertTrue(Files.exists(relay.socketPath()));
            PendingApproval prompt = broker.pending().get(0);
            ch.shutdownOutput(); // the service worker stopped; Chrome ended the host process
            waitFor(prompt::isDone);
            assertTrue(broker.pending().isEmpty());
            prompt.approveOnce(); // too late: the prompt was already answered for the user
            assertEquals(0, released.get(), "nothing is released for a host that is gone");
        }
    }

    @Test
    void passkeyRequestsAreNeitherRelayedNorServed() throws IOException, HostException, BrowserRelay.NotStarted {
        Path v = vaultFile();
        assertEquals(HostException.Code.UNKNOWN_TYPE.name(), text(ask(v, WEBAUTHN_GET).join(), "code"),
                "refused by the host before it looks for a TUI (no TUI would be DENIED_LOCKED)");
        try (BrowserRelay relay = relay(v)) {
            assertTrue(BrowserRelay.isLive(relay.socketPath()));
            assertEquals(HostException.Code.UNKNOWN_TYPE.name(), text(ask(v, WEBAUTHN_CREATE).join(), "code"));
            // Sent straight to the relay: the reply is decided from the type member alone, byte for
            // byte the reply to a type nobody knows, whether the rest is valid, partial or missing.
            byte[] unknown;
            try (SocketChannel ch = send(v, header(EXTENSION), "{\"type\":\"nosuch\"}")) {
                unknown = NativeFrames.read(Channels.newInputStream(ch));
            }
            assertEquals("{\"type\":\"error\",\"id\":null,\"code\":\"UNKNOWN_TYPE\"}",
                    new String(unknown, StandardCharsets.UTF_8));
            for (String json : List.of(WEBAUTHN_GET, WEBAUTHN_CREATE, "{\"type\":\"webauthn.get\",\"id\":\"a2\"}",
                    "{\"type\":\"webauthn.create\",\"id\":\"c2\"}", "{\"type\":\"webauthn.get\"}",
                    "{\"type\":\"webauthn.create\"}")) {
                try (SocketChannel ch = send(v, header(EXTENSION), json)) {
                    assertArrayEquals(unknown, NativeFrames.read(Channels.newInputStream(ch)), json);
                }
            }
            assertTrue(broker.pending().isEmpty(), "no prompt");
            assertTrue(audited.isEmpty(), "nothing served");
        }
    }

    @Test
    void theRelayEncodesEveryRequestTypeSoItDecodesUnchanged() throws HostException {
        // Each request is written member for member in the order the relay encodes it, so the
        // relay's encoding must reproduce it byte for byte, and decode to the same request.
        List<String> requests = List.of(
                "{\"type\":\"hello\",\"id\":\"h\",\"version\":1}",
                LOOKUP,
                fillJson(),
                "{\"type\":\"save\",\"id\":\"s\",\"origin\":\"https://example.org\",\"username\":\"u\",\"password\":\"p w\"}",
                "{\"type\":\"generate\",\"id\":\"g\",\"origin\":\"https://example.org\",\"username\":\"u\","
                        + "\"policy\":{\"length\":20,\"lower\":true,\"upper\":true,\"digits\":true,\"symbols\":false}}");
        for (String json : requests) {
            try (Request r = decode(json); SecretBytes again = JsonText.toUtf8(BrowserRelay.encode(r))) {
                byte[] copy = again.apply(byte[]::clone);
                assertEquals(json, new String(copy, StandardCharsets.UTF_8), "member for member");
                try (Request back = Messages.decode(copy)) {
                    assertEquals(r.getClass(), back.getClass(), json);
                    assertEquals(r.id(), back.id());
                }
            }
        }
        for (String json : List.of(WEBAUTHN_GET, WEBAUTHN_CREATE)) {
            try (Request r = decode(json)) {
                assertThrows(IllegalArgumentException.class, () -> BrowserRelay.encode(r), "never relayed");
            }
        }
    }
}
