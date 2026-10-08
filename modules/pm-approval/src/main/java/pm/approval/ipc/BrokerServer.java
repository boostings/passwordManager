package pm.approval.ipc;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.NetworkChannel;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;
import java.util.Optional;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import jdk.net.ExtendedSocketOptions;
import pm.approval.ApprovalBroker;
import pm.approval.Decision;
import pm.approval.Grant;
import pm.approval.Outcome;
import pm.crypto.SecretBytes;

/**
 * Serves an {@link ApprovalBroker} on the run directory's socket. One connection carries one
 * request and its reply. A request must arrive within five seconds; unanswered prompts are
 * expired every second, so a reply comes at most {@link ApprovalBroker#PROMPT_TIMEOUT} after the
 * request. Connections beyond {@link #MAX_CONNECTIONS} are answered {@code DENIED_BUSY}.
 *
 * <p>Where the platform reports the peer's credentials ({@code SO_PEERCRED} on Linux and macOS),
 * the broker denies a client running as another OS user even with a valid token.
 */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: TPS00-J executors; PMD 7 flags executors too
public final class BrokerServer implements AutoCloseable {
    /** Most connections served at once. */
    public static final int MAX_CONNECTIONS = 8;
    /** Time allowed for the client to send its request. */
    static final long READ_TIMEOUT_MS = 5_000;

    private final RunDir dir;
    private final ApprovalBroker broker;
    private final Releaser releaser;
    private final ServerSocketChannel server;
    private final ExecutorService workers;
    private final ScheduledExecutorService timer;
    private final Semaphore slots = new Semaphore(MAX_CONNECTIONS);
    private final AtomicBoolean running = new AtomicBoolean(true);

    private BrokerServer(RunDir dir, ApprovalBroker broker, Releaser releaser, ServerSocketChannel server) {
        this.dir = dir;
        this.broker = broker;
        this.releaser = releaser;
        this.server = server;
        this.workers = Executors.newFixedThreadPool(MAX_CONNECTIONS + 1, daemon("pm-broker"));
        this.timer = Executors.newSingleThreadScheduledExecutor(daemon("pm-broker-timer"));
    }

    /**
     * Binds the socket and starts serving. A stale socket left by a crashed broker is replaced; a
     * live one (another broker accepts on it) is left alone; any other file there is refused.
     *
     * @throws IpcException {@code UNSAFE_PATH} if the socket path holds a link or a regular file,
     *     {@code IO} if another broker serves on it or binding fails
     */
    @SuppressWarnings("PMD.CloseResource") // ownership of the channel passes to the server, closed in close()
    public static BrokerServer start(RunDir dir, ApprovalBroker broker, Releaser releaser) throws IpcException {
        Objects.requireNonNull(dir, "dir");
        Objects.requireNonNull(broker, "broker");
        Objects.requireNonNull(releaser, "releaser");
        Path socket = dir.socketPath();
        ServerSocketChannel ch;
        try {
            if (Files.exists(socket, LinkOption.NOFOLLOW_LINKS)) {
                BasicFileAttributes a = Files.readAttributes(socket, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (!a.isOther()) {
                    throw new IpcException(IpcException.Code.UNSAFE_PATH, null);
                }
                if (isLive(socket)) {
                    throw new IpcException(IpcException.Code.IO, null); // another broker serves: never steal it
                }
                Files.delete(socket);
            }
            ch = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        } catch (IOException e) {
            throw new IpcException(IpcException.Code.IO, e);
        }
        try {
            ch.bind(UnixDomainSocketAddress.of(socket));
        } catch (IOException e) {
            closeQuietly(ch);
            throw new IpcException(IpcException.Code.IO, e);
        }
        BrokerServer s = new BrokerServer(dir, broker, releaser, ch);
        if (broker.isUnlocked()) {
            dir.writeToken(broker);
        }
        ScheduledFuture<?> ticking = s.timer.scheduleAtFixedRate(s::expireQuietly, 1, 1, TimeUnit.SECONDS);
        Objects.requireNonNull(ticking); // cancelled by timer.shutdownNow() in close()
        s.workers.execute(s::acceptLoop);
        return s;
    }

    /** Whether something accepts connections on {@code socket}; a refused connection means it is stale. */
    private static boolean isLive(Path socket) {
        try (SocketChannel probe = SocketChannel.open(UnixDomainSocketAddress.of(socket))) {
            return probe.isConnected();
        } catch (IOException e) {
            return false;
        }
    }

    /** The vault unlocked: a new token is issued and written (approval-model §5). */
    public void unlocked() throws IpcException {
        broker.unlock();
        dir.writeToken(broker);
    }

    /** The vault locked: the token file goes first, then the broker forgets the token. */
    public void locked() throws IpcException {
        dir.deleteToken();
        broker.lock();
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
            dir.deleteToken();
            Files.deleteIfExists(dir.socketPath());
        } catch (IpcException | IOException e) {
            // Nothing secret remains: the token in memory dies with the broker's lock().
            Objects.requireNonNull(e);
        }
    }

    private void expireQuietly() {
        try {
            broker.expire();
        } catch (RuntimeException e) {
            // An audit write failed; keep ticking so later prompts still time out (and fail closed).
            Objects.requireNonNull(e);
        }
    }

    @SuppressWarnings("PMD.CloseResource") // each accepted channel is closed by replyAndClose or serve
    private void acceptLoop() {
        for (;;) {
            SocketChannel client;
            try {
                client = server.accept();
            } catch (ClosedChannelException e) {
                // close() closes the server channel, so this is the one way out, whenever close() runs.
                return;
            } catch (IOException e) {
                continue;
            }
            if (!slots.tryAcquire()) {
                replyAndClose(client, IpcCodec.encodeReply(Decision.DENIED_BUSY, new TreeMap<>()));
                continue;
            }
            workers.execute(() -> {
                try {
                    serve(client);
                } finally {
                    slots.release();
                }
            });
        }
    }

    private void serve(SocketChannel client) {
        Optional<String> peer = peerUser(client);
        ScheduledFuture<?> deadline = timer.schedule(() -> closeQuietly(client), READ_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        byte[] frame;
        try {
            frame = Frames.read(client, Frames.MAX_REQUEST);
        } catch (IpcException e) {
            deadline.cancel(false);
            if (e.code() != IpcException.Code.IO) {
                broker.rejectMalformed();
                replyAndClose(client, IpcCodec.encodeReply(Decision.DENIED_MALFORMED, new TreeMap<>()));
            } else {
                closeQuietly(client);
            }
            return;
        }
        deadline.cancel(false);
        IpcCodec.Decoded decoded;
        try {
            decoded = IpcCodec.decodeRequest(frame);
        } catch (IpcException e) {
            broker.rejectMalformed();
            replyAndClose(client, IpcCodec.encodeReply(Decision.DENIED_MALFORMED, new TreeMap<>()));
            return;
        } finally {
            java.util.Arrays.fill(frame, (byte) 0);
        }
        Outcome outcome;
        try (SecretBytes token = decoded.token()) {
            outcome = token.apply(t -> broker.submit(decoded.request(), t, peer)).join();
        }
        replyAndClose(client, answer(outcome));
    }

    private byte[] answer(Outcome outcome) {
        Optional<Grant> grant = outcome.grant(); // present exactly when the decision is an approval
        if (grant.isEmpty()) {
            return IpcCodec.encodeReply(outcome.decision(), new TreeMap<>());
        }
        SortedMap<String, SecretBytes> vars;
        try {
            vars = releaser.release(grant.get());
        } catch (RuntimeException e) {
            return IpcCodec.encodeReply(Decision.DENIED, new TreeMap<>()); // fail closed
        }
        try {
            return IpcCodec.encodeReply(outcome.decision(), vars);
        } finally {
            vars.values().forEach(SecretBytes::close);
        }
    }

    /**
     * The OS user at the other end: empty where the platform does not report it (Windows), and a
     * name that never matches when it should be reported but cannot be read.
     */
    static Optional<String> peerUser(NetworkChannel client) {
        try {
            if (client.supportedOptions().contains(ExtendedSocketOptions.SO_PEERCRED)) {
                return Optional.of(client.getOption(ExtendedSocketOptions.SO_PEERCRED).user().getName());
            }
        } catch (IOException | UnsupportedOperationException e) {
            return Optional.of(""); // credentials should be available but are not: never matches osUser
        }
        return Optional.empty();
    }

    private static void replyAndClose(SocketChannel client, byte[] reply) {
        try (client) {
            Frames.write(client, reply);
        } catch (IOException e) {
            // The client went away; nothing was released to it.
            Objects.requireNonNull(e);
        } finally {
            java.util.Arrays.fill(reply, (byte) 0);
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

}
