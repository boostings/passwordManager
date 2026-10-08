package pm.tui;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import jdk.net.ExtendedSocketOptions;
import pm.approval.ApprovalBroker;
import pm.approval.ApprovalRequest;
import pm.approval.AuditEvent;
import pm.approval.Decision;
import pm.approval.ipc.IpcException;
import pm.approval.ipc.RunDir;
import pm.browser.bridge.Bridge;
import pm.browser.bridge.PasskeyPort;
import pm.browser.bridge.PasswordGenerator;
import pm.browser.bridge.VaultPort;
import pm.browser.host.ExtensionAllowlist;
import pm.browser.host.HostException;
import pm.browser.host.Json;
import pm.browser.host.JsonText;
import pm.browser.host.Messages;
import pm.browser.host.NativeFrames;
import pm.browser.host.Request;
import pm.crypto.Csprng;
import pm.crypto.SecretBytes;
import pm.storage.OwnerOnly;
import pm.storage.StorageException;

/**
 * The browser relay (ADR 0014 §8): Chrome starts {@code pm} as the native host in its own process,
 * which holds neither the vault nor a grant. That process forwards each decoded request over the
 * Unix socket {@value #SOCKET} in {@code <default vault>}{@value #DIR_SUFFIX} (an owner-only
 * folder whose place depends on the default vault path only, never on the environment) to the
 * TUI, where {@link Bridge} runs against the TUI's broker and open session. Only a TUI on the
 * default vault serves it, and only one at a time: a second TUI finds the socket live and leaves
 * it alone. With no TUI running there is no socket and the host answers {@code DENIED_LOCKED}.
 * Nothing is ever approved automatically.
 *
 * <p>Wire format, both directions in the native-messaging framing ({@link NativeFrames}: u32
 * little-endian length, at most 1 MiB): the host sends one frame {@code "<extension id> <host>"}
 * (ASCII; {@code <host>} is {@link #HOST_INSTANCE}, 128 random bits the host process draws once)
 * and one frame with the request JSON; the TUI answers with one frame of reply JSON and closes.
 *
 * <p>What the socket peer is trusted with: nothing beyond being the same OS user. The owner-only
 * folder (and, where the platform reports it, the peer's user) keeps other users out, but any
 * process of the same user can connect and claim to be the host, with any allowlisted extension
 * ID and any host instance. The relay therefore checks the extension ID against the allowlist on
 * every request, decodes the request again with the host's own schema
 * ({@link Messages#decodeWithoutPasskeys}),
 * binds every approval to the one connection it was asked on (a later connection, even from the
 * same program, never inherits it), shows the claimed host instance in the prompt, allows one
 * waiting prompt per host instance, and rate-limits and audits {@code lookup}, which needs no
 * prompt. The process behind the socket is not inspected (no process ID or program is read):
 * process APIs are confined to the env runner and the platform adapters (SR-100), and a process
 * ID would be the peer's claim anyway (SR-101).
 *
 * <p>If the host goes away while its request waits for approval (Chrome stopped the extension's
 * service worker and with it the native host), the waiting prompt is denied and no grant is used:
 * nothing is released for an answer nobody would receive. A peer that sends nothing within
 * {@link Limits#header} or does not read its reply within {@link Limits#write} is disconnected, so
 * it cannot hold one of the {@value #MAX_CONNECTIONS} connection slots for long.
 */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-065: TPS00-J bounded, named daemon executors, as BrokerServer (CE-002)
public final class BrowserRelay implements AutoCloseable {
    /** Socket file name in the relay folder. */
    public static final String SOCKET = "browser.sock";
    /** The relay folder is the default vault file's path with this suffix. */
    public static final String DIR_SUFFIX = ".browser";
    /** Held (locked) by the serving TUI for as long as it serves. */
    static final String LOCK_FILE = "relay.lock";
    /** Most requests served at once; more are answered {@code DENIED_BUSY}. */
    static final int MAX_CONNECTIONS = 4;
    /** How long the bridge waits for the user: the broker's prompt timeout and a margin. */
    public static final Duration APPROVAL_WAIT = ApprovalBroker.PROMPT_TIMEOUT.plusSeconds(5);
    /** How long the host waits for the TUI's reply before it gives up. */
    public static final Duration REPLY_WAIT = APPROVAL_WAIT.plusSeconds(30);
    /** The profile name under which a lookup is audited ({@code approval} entry, ADR 0014 §8). */
    static final String LOOKUP_PROFILE = "lookup";
    /**
     * Longest socket path the JDK binds on macOS and the BSDs, in bytes: {@code sun_path} holds
     * 104, and the JDK keeps two of them back ({@code MAX_UNIX_DOMAIN_PATH_LEN}), so a 103-byte
     * path fails with "Unix domain path too long" (measured with JDK 21 on macOS).
     */
    static final int MAC_SOCKET_PATH_BYTES = 102;
    /** Longest socket path the JDK binds on Linux, in bytes: {@code sun_path} holds 108, less two. */
    static final int LINUX_SOCKET_PATH_BYTES = 106;

    private static final String INTERNAL = HostException.Code.INTERNAL.name();
    private static final Pattern CALLER = Pattern.compile("([a-p]{32}) ([0-9a-f]{32})");
    /**
     * This process's host instance: 128 random bits, drawn once, sent with every request it
     * relays. It groups one host's requests for the per-host limits and tells two hosts apart in
     * the prompt; it proves nothing (any same-user process can send any value).
     */
    static final String HOST_INSTANCE = HexFormat.of().formatHex(Csprng.bytes(16));
    private static final int SHOWN_INSTANCE_CHARS = 8;
    private static final String EXTENSION_KIND = "EXTENSION";
    private static final Duration MINUTE = Duration.ofMinutes(1);
    /** Most host instances whose lookup budget is remembered; the oldest is forgotten first. */
    private static final int MAX_TRACKED_PEERS = 64;

    /**
     * Deadlines and rate limits.
     *
     * @param header time a peer has to send both frames
     * @param write time a peer has to take its reply
     * @param lookupsPerMinute lookups served per minute in all
     * @param peerLookupsPerMinute lookups served per minute to one host instance
     */
    record Limits(Duration header, Duration write, int lookupsPerMinute, int peerLookupsPerMinute) {
        /** Production limits: 5 s deadlines, 20 lookups a minute, 10 per host instance. */
        static final Limits DEFAULT = new Limits(Duration.ofSeconds(5), Duration.ofSeconds(5), 20, 10);

        Limits {
            Objects.requireNonNull(header, "header");
            Objects.requireNonNull(write, "write");
            if (lookupsPerMinute < 1 || peerLookupsPerMinute < 1) {
                throw new IllegalArgumentException("BAD_LIMIT");
            }
        }
    }

    /** Why the relay is not serving (the TUI's status line says so). */
    enum Unavailable {
        /** Another pm window on the default vault serves the browser. */
        IN_USE,
        /** The socket path is longer than the platform allows. */
        PATH_TOO_LONG,
        /** The relay folder or a file in it is a link, open to others, or cannot be created. */
        UNSAFE
    }

    /** The relay did not start; {@link #reason()} says why. */
    static final class NotStarted extends Exception {
        private static final long serialVersionUID = 1L;
        private final Unavailable why;

        NotStarted(Unavailable why, Throwable cause) {
            super(why.name(), cause);
            this.why = why;
        }

        Unavailable reason() {
            return why;
        }
    }

    /** What the TUI needs from its surroundings. */
    record Wiring(ApprovalBroker broker, Supplier<VaultPort> vault, Predicate<AuditEvent> audit, Clock clock,
            String osUser, Duration approvalWait, Limits limits) {
        Wiring {
            Objects.requireNonNull(broker, "broker");
            Objects.requireNonNull(vault, "vault");
            Objects.requireNonNull(audit, "audit");
            Objects.requireNonNull(clock, "clock");
            Objects.requireNonNull(osUser, "osUser");
            Objects.requireNonNull(approvalWait, "approvalWait");
            Objects.requireNonNull(limits, "limits");
        }
    }

    private final ServerSocketChannel server;
    private final Path socket;
    private final Path allowlist;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private final Wiring wiring;
    private final PasswordGenerator generator = PasswordGenerator.secure();
    private final RelayPeers peers = new RelayPeers();
    private final LookupLimiter lookups;
    private final ExecutorService workers;
    private final ScheduledExecutorService timer;
    private final Semaphore slots = new Semaphore(MAX_CONNECTIONS);
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final AtomicLong connections = new AtomicLong();

    private BrowserRelay(ServerSocketChannel server, Path socket, Path allowlist, FileChannel lockChannel,
            FileLock lock, Wiring wiring) {
        this.server = server;
        this.socket = socket;
        this.allowlist = allowlist;
        this.lockChannel = lockChannel;
        this.lock = lock;
        this.wiring = wiring;
        this.lookups = new LookupLimiter(wiring.limits());
        // Each connection may use two workers (serve, and the watch for the host going away).
        this.workers = Executors.newFixedThreadPool(2 * MAX_CONNECTIONS + 1, daemon("pm-browser-relay"));
        this.timer = Executors.newSingleThreadScheduledExecutor(daemon("pm-browser-relay-timer"));
    }

    // ---- where the socket lives ------------------------------------------------------------

    /**
     * The relay folder for the default vault {@code vaultFile}: {@code <vault file>}{@value #DIR_SUFFIX}
     * next to it. It depends on that path only, so the TUI and a host started by the browser (with
     * a different environment) always agree on it.
     */
    public static Path socketDir(Path vaultFile) {
        Path abs = vaultFile.toAbsolutePath().normalize();
        return abs.resolveSibling(Objects.requireNonNull(abs.getFileName(), "vault file") + DIR_SUFFIX);
    }

    /** The relay socket for the default vault {@code vaultFile}. */
    public static Path socketPath(Path vaultFile) {
        return socketDir(vaultFile).resolve(SOCKET);
    }

    /** The longest socket path the JDK binds on {@code osName}, in bytes. */
    static int maxSocketPathBytes(String osName) {
        String os = osName.toLowerCase(Locale.ROOT);
        return os.startsWith("mac") || os.startsWith("darwin") || os.contains("bsd")
                ? MAC_SOCKET_PATH_BYTES : LINUX_SOCKET_PATH_BYTES;
    }

    /** Whether the JDK can bind {@code socket} on {@code osName}. */
    static boolean fitsSocketPath(Path socket, String osName) {
        return socket.toString().getBytes(StandardCharsets.UTF_8).length <= maxSocketPathBytes(osName);
    }

    /**
     * Why binding {@code path} failed on {@code runningOs}, the OS this JVM runs on: a path too long
     * for it is {@code PATH_TOO_LONG}, a socket that another TUI bound first and that accepts
     * connections is {@code IN_USE}, and anything else is {@code UNSAFE}. Never {@code IN_USE}
     * without a live socket.
     */
    static Unavailable bindFailure(Path path, String runningOs) {
        if (!fitsSocketPath(path, runningOs)) {
            return Unavailable.PATH_TOO_LONG;
        }
        return isLive(path) ? Unavailable.IN_USE : Unavailable.UNSAFE;
    }

    // ---- starting and stopping -------------------------------------------------------------

    /**
     * Serves the browser for the default vault {@code vaultFile}. The relay folder is created
     * owner-only (0700) if needed. A socket left by a crashed TUI (nothing accepts on it) is
     * replaced; a live one, or the lock of a running TUI, means another pm window serves the
     * browser, and nothing is touched.
     *
     * @throws NotStarted {@code IN_USE}, {@code PATH_TOO_LONG} or {@code UNSAFE}
     */
    @SuppressWarnings("PMD.CloseResource") // CE-066: the channels and the lock pass to the relay, closed in close()
    static BrowserRelay start(Path vaultFile, Wiring wiring, String osName) throws NotStarted {
        Objects.requireNonNull(wiring, "wiring");
        Path path = socketPath(vaultFile);
        if (!fitsSocketPath(path, osName)) {
            throw new NotStarted(Unavailable.PATH_TOO_LONG, null);
        }
        RunDir dir;
        try {
            dir = RunDir.prepare(socketDir(vaultFile));
        } catch (IpcException e) {
            throw new NotStarted(Unavailable.UNSAFE, e);
        }
        FileChannel lockChannel;
        try {
            // 0600 on POSIX, an owner-only ACL on Windows (a POSIX attribute alone fails there).
            lockChannel = FileChannel.open(dir.path().resolve(LOCK_FILE),
                    Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
                    OwnerOnly.creationAttributes(dir.path(), false));
        } catch (IOException | UnsupportedOperationException | StorageException e) {
            throw new NotStarted(Unavailable.UNSAFE, e);
        }
        FileLock lock = tryLock(lockChannel);
        if (lock == null) {
            closeQuietly(lockChannel);
            throw new NotStarted(Unavailable.IN_USE, null);
        }
        ServerSocketChannel ch;
        try {
            ch = bind(path);
        } catch (NotStarted e) {
            closeQuietly(lockChannel); // releases the lock
            throw e;
        }
        BrowserRelay relay = new BrowserRelay(ch, path, vaultFile.toAbsolutePath().normalize()
                .resolveSibling(ExtensionAllowlist.FILE_NAME), lockChannel, lock, wiring);
        relay.workers.execute(relay::acceptLoop);
        return relay;
    }

    /** The lock, or null if another TUI (in this or another process) holds it. */
    private static FileLock tryLock(FileChannel ch) throws NotStarted {
        try {
            return ch.tryLock();
        } catch (OverlappingFileLockException e) {
            return null; // held by another relay in this JVM
        } catch (IOException e) {
            closeQuietly(ch);
            throw new NotStarted(Unavailable.UNSAFE, e);
        }
    }

    @SuppressWarnings("PMD.CloseResource") // CE-066: the bound channel is returned to the caller, closed on failure
    private static ServerSocketChannel bind(Path path) throws NotStarted {
        try {
            if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                BasicFileAttributes a = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (!a.isOther()) {
                    throw new NotStarted(Unavailable.UNSAFE, null);
                }
                if (isLive(path)) {
                    throw new NotStarted(Unavailable.IN_USE, null); // never steal a live socket
                }
                Files.delete(path); // stale: its TUI is gone
            }
        } catch (IOException e) {
            throw new NotStarted(Unavailable.UNSAFE, e);
        }
        ServerSocketChannel ch;
        try {
            ch = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        } catch (IOException e) {
            throw new NotStarted(Unavailable.UNSAFE, e);
        }
        try {
            ch.bind(UnixDomainSocketAddress.of(path));
            return ch;
        } catch (IOException e) {
            closeQuietly(ch);
            throw new NotStarted(bindFailure(path, System.getProperty("os.name", "")), e);
        }
    }

    /** Whether something accepts connections on {@code path}. */
    static boolean isLive(Path path) {
        try (SocketChannel probe = SocketChannel.open(UnixDomainSocketAddress.of(path))) {
            return probe.isConnected();
        } catch (IOException e) {
            return false; // refused: nobody listens, the socket is stale
        }
    }

    /** The socket this relay serves. */
    Path socketPath() {
        return socket;
    }

    /**
     * Requests being served right now. A request holds its slot until its reply is written or
     * its peer is cut off, so zero means every earlier connection is finished.
     */
    int busy() {
        return MAX_CONNECTIONS - slots.availablePermits();
    }

    /** The peer behind the waiting prompt {@code requestId}, if this relay asked it. */
    Optional<String> peerOf(java.util.UUID requestId) {
        return peers.line(requestId);
    }

    /**
     * False if this relay asked the prompt {@code requestId} for an extension that has since been
     * taken off the allowlist (read again now): the TUI then denies it without showing it.
     */
    boolean stillAllowed(java.util.UUID requestId) {
        return peers.stillAllowed(requestId);
    }

    @Override
    public void close() {
        if (!running.getAndSet(false)) {
            return;
        }
        closeQuietly(server);
        workers.shutdownNow();
        timer.shutdownNow();
        try {
            Files.deleteIfExists(socket);
        } catch (IOException e) {
            Objects.requireNonNull(e); // a stale socket is replaced by the next start
        }
        try {
            lock.release();
        } catch (IOException e) {
            Objects.requireNonNull(e); // closing the channel releases it too
        }
        closeQuietly(lockChannel);
    }

    // ---- the host's side -------------------------------------------------------------------

    /**
     * Forwards {@code request} from extension {@code extensionId} to the TUI serving the default
     * vault {@code vaultFile} and returns its reply. Runs in the native host process.
     *
     * @throws HostException {@code DENIED_LOCKED} when no TUI serves that vault (pm is not open,
     *     or locked and closed), {@code INTERNAL} when the TUI's answer is missing or not a JSON
     *     object, {@code UNKNOWN_TYPE} for a WebAuthn request ({@link #refuseUnserved}), before
     *     anything is opened
     */
    @SuppressWarnings("PMD.CloseResource") // CE-066: the channel closes with the try, the scheduler in finally after cancelling
    public static Json.Obj ask(Path vaultFile, String extensionId, Request request) throws HostException {
        Objects.requireNonNull(request, "request");
        refuseUnserved(request); // never relayed
        if (!ExtensionAllowlist.isValidId(extensionId)) {
            throw new IllegalArgumentException("BAD_EXTENSION_ID");
        }
        Path path;
        try {
            path = RunDir.existing(socketDir(vaultFile)).path().resolve(SOCKET);
        } catch (IpcException e) {
            throw HostException.denied(Decision.DENIED_LOCKED);
        }
        SocketChannel ch;
        try {
            ch = SocketChannel.open(UnixDomainSocketAddress.of(path));
        } catch (IOException e) {
            throw HostException.denied(Decision.DENIED_LOCKED); // nothing listens: no TUI is open
        }
        ScheduledExecutorService deadline = Executors.newSingleThreadScheduledExecutor(daemon("pm-browser-host"));
        ScheduledFuture<?> giveUp = deadline.schedule(() -> closeQuietly(ch), REPLY_WAIT.toMillis(), TimeUnit.MILLISECONDS);
        Json.Obj encoded = encode(request);
        String header = extensionId + " " + HOST_INSTANCE;
        try (ch; SecretBytes caller = SecretBytes.copyOf(header.getBytes(StandardCharsets.US_ASCII));
                SecretBytes body = JsonText.toUtf8(encoded)) {
            OutputStream out = Channels.newOutputStream(ch);
            try {
                NativeFrames.write(out, caller);
                NativeFrames.write(out, body);
            } catch (IOException e) {
                // A busy TUI answers before reading and closes: its DENIED_BUSY reply is still there to read.
                Objects.requireNonNull(e);
            }
            return reply(Channels.newInputStream(ch));
        } catch (IOException e) {
            throw new HostException(HostException.Code.INTERNAL);
        } finally {
            encoded.wipe();
            giveUp.cancel(false);
            deadline.shutdownNow();
        }
    }

    private static Json.Obj reply(InputStream in) throws IOException, HostException {
        byte[] frame;
        try {
            frame = NativeFrames.read(in);
        } catch (HostException e) {
            throw new HostException(HostException.Code.INTERNAL); // the TUI closed without answering
        }
        char[] text;
        try {
            text = NativeFrames.utf8(frame);
        } finally {
            Arrays.fill(frame, (byte) 0);
        }
        Json parsed;
        try {
            parsed = JsonText.parse(text);
        } finally {
            Arrays.fill(text, '\0');
        }
        if (parsed instanceof Json.Obj o) {
            return o;
        }
        parsed.wipe();
        throw new HostException(HostException.Code.INTERNAL);
    }

    /**
     * The request as the extension sent it, member for member (ADR 0014 §3). Dispatch uses
     * {@code Class.cast} rather than pattern bindings: PMD CloseResource reports every
     * {@code AutoCloseable} binding (as in {@code RecordDetailWindow#fields}); the request stays
     * the caller's to close.
     */
    static Json.Obj encode(Request request) {
        Map<String, Json> m = new LinkedHashMap<>();
        m.put("type", Json.Str.of(typeOf(request)));
        m.put("id", Json.Str.of(request.id()));
        if (request instanceof Request.Hello) {
            m.put("version", new Json.Num(Request.Hello.VERSION));
        } else if (request instanceof Request.Lookup) {
            m.put("origin", Json.Str.of(Request.Lookup.class.cast(request).origin()));
        } else if (request instanceof Request.Fill) {
            Request.Fill fill = Request.Fill.class.cast(request);
            m.put("origin", Json.Str.of(fill.origin()));
            m.put("entry", Json.Str.of(fill.entry().toString()));
        } else if (request instanceof Request.Save) {
            Request.Save save = Request.Save.class.cast(request);
            m.put("origin", Json.Str.of(save.origin()));
            m.put("username", Json.Str.of(save.username()));
            m.put("password", Json.Str.of(save.password()));
        } else {
            Request.Generate generate = Request.Generate.class.cast(request);
            m.put("origin", Json.Str.of(generate.origin()));
            m.put("username", Json.Str.of(generate.username()));
            Request.Policy p = generate.policy();
            Map<String, Json> policy = new LinkedHashMap<>();
            policy.put("length", new Json.Num(p.length()));
            policy.put("lower", new Json.Bool(p.lower()));
            policy.put("upper", new Json.Bool(p.upper()));
            policy.put("digits", new Json.Bool(p.digits()));
            policy.put("symbols", new Json.Bool(p.symbols()));
            m.put("policy", new Json.Obj(policy));
        }
        return new Json.Obj(m);
    }

    private static String typeOf(Request request) {
        if (request instanceof Request.Hello) {
            return "hello";
        } else if (request instanceof Request.Lookup) {
            return "lookup";
        } else if (request instanceof Request.Fill) {
            return "fill";
        } else if (request instanceof Request.Save) {
            return "save";
        } else if (request instanceof Request.Generate) {
            return "generate";
        }
        throw new IllegalArgumentException("NOT_RELAYED"); // see refuseUnserved
    }

    /**
     * Passkeys are not served through the browser in this version (M6.4 is out of scope):
     * {@code webauthn.create} and {@code webauthn.get} are answered {@code UNKNOWN_TYPE} from their
     * {@code type} member alone, exactly like a type nobody knows, by the host
     * ({@link pm.browser.host.NativeHost#runWithoutPasskeys}) and by the relay ({@link Messages#decodeWithoutPasskeys}).
     * This check is the backstop for a decoded request reaching {@link #ask} another way.
     */
    static void refuseUnserved(Request request) throws HostException {
        if (request instanceof Request.WebauthnCreate || request instanceof Request.WebauthnGet) {
            throw new HostException(HostException.Code.UNKNOWN_TYPE);
        }
    }

    // ---- the TUI's side --------------------------------------------------------------------

    @SuppressWarnings("PMD.CloseResource") // CE-066: each accepted channel is closed by serve or answerAndClose
    private void acceptLoop() {
        while (running.get()) {
            SocketChannel client;
            try {
                client = server.accept();
            } catch (ClosedChannelException e) {
                return;
            } catch (IOException e) {
                continue;
            }
            if (!slots.tryAcquire()) {
                answerAndClose(client, Messages.error(null, Decision.DENIED_BUSY.name()));
                continue;
            }
            long connection = connections.incrementAndGet();
            try {
                workers.execute(() -> {
                    try {
                        serve(client, connection);
                    } finally {
                        slots.release();
                    }
                });
            } catch (RejectedExecutionException e) {
                slots.release();
                closeQuietly(client); // closing down
            }
        }
    }

    private void serve(SocketChannel client, long connection) {
        if (!peerAllowed(client)) {
            closeQuietly(client);
            return;
        }
        Runnable cancel = closeLater(client, wiring.limits().header());
        byte[] header;
        byte[] body;
        try {
            InputStream in = Channels.newInputStream(client);
            header = NativeFrames.read(in);
            body = NativeFrames.read(in);
        } catch (IOException | HostException e) {
            closeQuietly(client); // silent past the deadline, or not framed
            return;
        } finally {
            cancel.run();
        }
        Matcher caller = CALLER.matcher(new String(header, StandardCharsets.US_ASCII));
        Arrays.fill(header, (byte) 0);
        if (!caller.matches()) {
            Arrays.fill(body, (byte) 0);
            closeQuietly(client);
            return;
        }
        CompletableFuture<Void> gone = new CompletableFuture<>();
        try {
            workers.execute(() -> watch(client, gone));
        } catch (RejectedExecutionException e) {
            Arrays.fill(body, (byte) 0);
            closeQuietly(client); // closing down
            return;
        }
        answerAndClose(client, answer(caller.group(1), caller.group(2), connection, body, gone));
    }

    /**
     * Completes {@code gone} when the host closes its end (or sends anything more, which the
     * protocol does not allow). Uses the channel directly: a channel stream would hold the
     * channel's blocking lock and stall the reply.
     */
    private static void watch(SocketChannel client, CompletableFuture<Void> gone) {
        try {
            int read = client.read(ByteBuffer.allocate(1));
            Objects.requireNonNull(Integer.valueOf(read)); // -1 (closed) or a stray byte: either way gone
        } catch (IOException e) {
            Objects.requireNonNull(e); // closed by us after the reply, or reset by the host
        } finally {
            gone.complete(null);
        }
    }

    /** The reply to one request, never an exception: one request, one reply (ADR 0014 §2). */
    private Json.Obj answer(String extensionId, String host, long connection, byte[] body,
            CompletableFuture<Void> gone) {
        Request request;
        try {
            request = Messages.decodeWithoutPasskeys(body); // passkeys: an unknown type's reply
        } catch (HostException e) {
            return Messages.error(null, e.getMessage());
        }
        try (request) {
            if (!allowlisted(extensionId)) {
                throw HostException.denied(Decision.DENIED_AUTH); // a format-valid ID is not enough
            }
            RelayPeers.Peer peer = peer(host);
            VaultPort port = wiring.vault().get();
            if (port == GuiThreadBrowserVault.LOCKED) {
                throw HostException.denied(Decision.DENIED_LOCKED); // no open session handed over
            }
            // The requester label names this connection: a policy made from this prompt can
            // never match a request on another connection, from this program or any other.
            RelayApproval approval = new RelayApproval(wiring.broker(), wiring.approvalWait(), gone, peer, peers,
                    () -> allowlisted(extensionId), this::auditOverruled);
            Bridge bridge = new Bridge(extensionId + " #" + connection, port, approval, wiring.clock(), generator,
                    PasskeyPort.NONE);
            if (request instanceof Request.Lookup) {
                return lookup(bridge, request, peer);
            }
            Json.Obj reply = bridge.handle(request);
            if (carriesSecret(request) && approval.granted() && !allowlisted(extensionId)) {
                // Taken off the allowlist while the vault was read: read again after the secret is
                // in hand and just before it is written, and it never leaves the TUI.
                reply.wipe();
                approval.withheld(Decision.DENIED_AUTH);
                throw HostException.denied(Decision.DENIED_AUTH);
            }
            return reply;
        } catch (HostException e) {
            return Messages.error(request.id(), e.getMessage());
        } catch (RuntimeException e) { // fault barrier: no exception text leaves the TUI
            return Messages.error(request.id(), INTERNAL);
        }
    }

    /**
     * A lookup needs no prompt (it returns titles and usernames, never a password), so it is
     * rate-limited per host instance and in all, and every served lookup is audited with its origin and
     * the number of logins found, never their titles or usernames. No audit entry, no answer.
     */
    private Json.Obj lookup(Bridge bridge, Request request, RelayPeers.Peer peer) throws HostException {
        Instant now = wiring.clock().instant();
        LookupLimiter.Verdict verdict = lookups.take(peer.key(), now);
        String asked = Request.Lookup.class.cast(request).origin();
        if (verdict != LookupLimiter.Verdict.SERVE) {
            if (verdict == LookupLimiter.Verdict.BUSY_FIRST
                    && !wiring.audit().test(lookupEvent(asked, -1, Decision.DENIED_BUSY))) {
                throw new HostException(HostException.Code.INTERNAL); // refused all the same
            }
            throw HostException.denied(Decision.DENIED_BUSY);
        }
        Json.Obj reply = bridge.handle(request);
        int hits = reply.get("entries") instanceof Json.Arr entries ? entries.items().size() : 0;
        String origin = reply.get("origin") instanceof Json.Str o ? o.text() : asked;
        if (!wiring.audit().test(lookupEvent(origin, hits, Decision.ALLOWED_ONCE))) {
            reply.wipe();
            throw new HostException(HostException.Code.INTERNAL);
        }
        return reply;
    }

    /** Whether the reply to {@code request} holds a password: a fill's, or a generated one. */
    private static boolean carriesSecret(Request request) {
        return request instanceof Request.Fill || request instanceof Request.Generate;
    }

    /**
     * Audits that {@code request}, which the user allowed and the broker audited as allowed, was
     * refused after all with {@code refusal} (ADR 0014 §8): a second {@code approval} entry for the
     * same request, so the log never shows a release that did not happen. The refusal stands
     * whether or not the entry could be written.
     */
    private boolean auditOverruled(ApprovalRequest request, Decision refusal) {
        ApprovalRequest.Scope scope = request.scope();
        return wiring.audit().test(new AuditEvent("approval", Optional.of(request.requestId()),
                Optional.of(request.requester().kind().name()), Optional.of(wiring.osUser()),
                Optional.of(scope.project()), Optional.of(scope.profile()), scope.vars().map(Set::size).orElse(-1),
                Optional.of(refusal.name()), request.argv0().isEmpty() ? Optional.empty() : Optional.of(request.argv0())));
    }

    private AuditEvent lookupEvent(String origin, int hits, Decision decision) {
        return new AuditEvent("approval", Optional.empty(), Optional.of(EXTENSION_KIND),
                Optional.of(wiring.osUser()), Optional.of(origin), Optional.of(LOOKUP_PROFILE), hits,
                Optional.of(decision.name()), Optional.empty());
    }

    private boolean allowlisted(String extensionId) {
        try {
            return ExtensionAllowlist.read(allowlist).allows(extensionId);
        } catch (IOException | IllegalArgumentException e) {
            return false; // missing or damaged: nobody is allowed
        }
    }

    /** The peer as the prompt shows it: the host instance it claims, marked as unverified. */
    static RelayPeers.Peer peer(String host) {
        return new RelayPeers.Peer(host, "browser host " + host.substring(0, SHOWN_INSTANCE_CHARS) + " (unverified)");
    }

    private boolean peerAllowed(SocketChannel client) {
        try {
            if (client.supportedOptions().contains(ExtendedSocketOptions.SO_PEERCRED)) {
                return wiring.osUser().equals(client.getOption(ExtendedSocketOptions.SO_PEERCRED).user().getName());
            }
        } catch (IOException | UnsupportedOperationException e) {
            return false; // credentials should be available but are not
        }
        return true; // no peer credentials on this platform: the 0700 folder is the gate
    }

    /** Writes {@code reply} and closes; a peer that does not take it within the write deadline is cut off. */
    private void answerAndClose(SocketChannel client, Json.Obj reply) {
        Runnable cancel = closeLater(client, wiring.limits().write());
        try (client; SecretBytes bytes = JsonText.toUtf8(reply)) {
            NativeFrames.write(Channels.newOutputStream(client), bytes);
        } catch (IOException | HostException | IllegalArgumentException e) {
            // The host went away, did not read in time, or the reply cannot be framed: not delivered.
            Objects.requireNonNull(e);
        } finally {
            cancel.run();
            reply.wipe();
        }
    }

    /**
     * Closes {@code client} after {@code delay} unless the returned action is run first; closes it
     * at once if the relay is closing.
     */
    private Runnable closeLater(SocketChannel client, Duration delay) {
        try {
            ScheduledFuture<?> later = timer.schedule(() -> closeQuietly(client), delay.toMillis(), TimeUnit.MILLISECONDS);
            return () -> later.cancel(false);
        } catch (RejectedExecutionException e) {
            closeQuietly(client);
            return () -> { };
        }
    }

    private static void closeQuietly(java.io.Closeable c) {
        try {
            c.close();
        } catch (IOException e) {
            Objects.requireNonNull(e);
        }
    }

    private static ThreadFactory daemon(String name) {
        AtomicInteger n = new AtomicInteger();
        return r -> {
            Thread t = new Thread(r, name + "-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
    }

    /**
     * Token buckets for {@code lookup}: one for all peers and one per host instance, each refilled
     * evenly over a minute. A refused lookup is audited once per minute, not once per attempt, so a
     * flood cannot grow the log.
     */
    static final class LookupLimiter {
        /** What to do with one lookup. */
        enum Verdict { SERVE, BUSY_FIRST, BUSY }

        private final ReentrantLock guard = new ReentrantLock();
        private final Bucket all;
        private final int perPeer;
        private final Map<String, Bucket> peers = new LinkedHashMap<>();
        private Instant lastBusy;

        LookupLimiter(Limits limits) {
            this.all = new Bucket(limits.lookupsPerMinute());
            this.perPeer = limits.peerLookupsPerMinute();
        }

        Verdict take(String peer, Instant now) {
            final ReentrantLock lock = guard;
            lock.lock();
            try {
                return decide(peer, now);
            } finally {
                lock.unlock();
            }
        }

        /** {@link #take} with {@code guard} held. */
        private Verdict decide(String peer, Instant now) {
            Bucket mine = peers.computeIfAbsent(peer, k -> new Bucket(perPeer));
            if (peers.size() > MAX_TRACKED_PEERS) {
                Iterator<String> oldest = peers.keySet().iterator();
                oldest.next();
                oldest.remove();
            }
            if (mine.has(now) && all.has(now)) {
                mine.take();
                all.take();
                return Verdict.SERVE;
            }
            boolean first = lastBusy == null || !now.isBefore(lastBusy.plus(MINUTE));
            if (first) {
                lastBusy = now;
            }
            return first ? Verdict.BUSY_FIRST : Verdict.BUSY;
        }
    }

    /** {@code perMinute} tokens, refilled continuously. Guarded by {@link LookupLimiter}. */
    private static final class Bucket {
        private final int perMinute;
        private double tokens;
        private Instant last;

        Bucket(int perMinute) {
            this.perMinute = perMinute;
            this.tokens = perMinute;
        }

        boolean has(Instant now) {
            if (last != null && now.isAfter(last)) {
                double refill = Duration.between(last, now).toMillis() * (double) perMinute / MINUTE.toMillis();
                tokens = Math.min(perMinute, tokens + refill);
            }
            if (last == null || now.isAfter(last)) {
                last = now;
            }
            return tokens >= 1;
        }

        void take() {
            tokens -= 1;
        }
    }
}
