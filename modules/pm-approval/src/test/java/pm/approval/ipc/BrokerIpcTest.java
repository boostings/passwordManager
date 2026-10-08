package pm.approval.ipc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.LockSupport;
import jdk.net.ExtendedSocketOptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.approval.ApprovalBroker;
import pm.approval.ApprovalRequest;
import pm.approval.AuditEvent;
import pm.approval.Decision;
import pm.approval.PolicyStore;
import pm.crypto.SecretBytes;

/** approval-model §5: socket, token file, framing, authentication, rotation. */
class BrokerIpcTest {
    private static final String ME = System.getProperty("user.name");
    private static final byte[] SECRET_VALUE = "s3cret-value".getBytes(StandardCharsets.UTF_8);

    @TempDir
    Path tmp;

    private final List<AuditEvent> events = new CopyOnWriteArrayList<>();
    private final ApprovalBroker broker = new ApprovalBroker(Clock.systemUTC(), events::add, PolicyStore.inMemory(), ME);
    private BrokerServer server;

    private static final Releaser RELEASE_DB = grant -> {
        grant.consume();
        SortedMap<String, SecretBytes> out = new TreeMap<>();
        out.put("DB", SecretBytes.copyOf(SECRET_VALUE));
        return out;
    };

    private RunDir start() throws IpcException {
        return start(broker);
    }

    private RunDir start(ApprovalBroker b) throws IpcException {
        RunDir dir = RunDir.prepare(tmp.resolve("run"));
        server = BrokerServer.start(dir, b, RELEASE_DB);
        server.unlocked();
        return dir;
    }

    @AfterEach
    void stop() {
        if (server != null) {
            server.close();
        }
    }

    private static ApprovalRequest request() {
        return new ApprovalRequest(UUID.randomUUID(),
                new ApprovalRequest.Requester(ApprovalRequest.Kind.CLI, "pm env run"),
                ApprovalRequest.Operation.ENV_INJECT,
                new ApprovalRequest.Scope("app", "dev", Optional.of(new TreeSet<>(List.of("DB"))), List.of()),
                Duration.ZERO,
                new ApprovalRequest.Display(List.of("/usr/bin/env"), Optional.empty(), ApprovalRequest.Effect.INJECT),
                Instant.now());
    }

    private void awaitPrompt() {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (broker.pending().isEmpty()) {
            assertTrue(System.nanoTime() < deadline, "no prompt arrived");
            LockSupport.parkNanos(Duration.ofMillis(10).toNanos());
        }
    }

    private static byte[] raw(RunDir dir, byte[] bytes) throws IOException, IpcException {
        try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            ch.connect(UnixDomainSocketAddress.of(dir.socketPath()));
            ByteBuffer buf = ByteBuffer.wrap(bytes);
            while (buf.hasRemaining()) {
                ch.write(buf);
            }
            return Frames.read(ch, Frames.MAX_REPLY);
        }
    }

    private static Decision decision(byte[] reply) throws IpcException {
        try (Reply r = IpcCodec.decodeReply(reply)) {
            return r.decision();
        }
    }

    private boolean audited(Decision d) {
        return events.stream().anyMatch(e -> e.decision().equals(Optional.of(d.name())));
    }

    @Test
    void approvedRequestReceivesItsValues() throws IpcException {
        RunDir dir = start();
        CompletableFuture<Reply> call = CompletableFuture.supplyAsync(() -> {
            try {
                return BrokerClient.call(dir, request());
            } catch (IpcException e) {
                throw new IllegalStateException(e.code().name(), e);
            }
        });
        awaitPrompt();
        broker.pending().get(0).approveOnce();
        try (Reply reply = call.join()) {
            assertEquals(Decision.ALLOWED_ONCE, reply.decision());
            reply.vars().get("DB").withBytes(v -> assertArrayEquals(SECRET_VALUE, v));
        }
    }

    @Test
    void deniedRequestReceivesNothing() throws IpcException {
        RunDir dir = start();
        CompletableFuture<Reply> call = CompletableFuture.supplyAsync(() -> {
            try {
                return BrokerClient.call(dir, request());
            } catch (IpcException e) {
                throw new IllegalStateException(e.code().name(), e);
            }
        });
        awaitPrompt();
        broker.pending().get(0).deny();
        try (Reply reply = call.join()) {
            assertEquals(Decision.DENIED, reply.decision());
            assertTrue(reply.vars().isEmpty());
        }
    }

    @Test
    void wrongTokenIsDeniedAndAudited() throws IOException, IpcException {
        RunDir dir = start();
        byte[] frame;
        try (SecretBytes wrong = SecretBytes.copyOf(new byte[ApprovalBroker.TOKEN_BYTES])) {
            frame = IpcCodec.encodeRequest(request(), wrong);
        }
        ByteBuffer out = ByteBuffer.allocate(4 + frame.length).putInt(frame.length).put(frame);
        assertEquals(Decision.DENIED_AUTH, decision(raw(dir, out.array())));
        assertTrue(audited(Decision.DENIED_AUTH));
        assertTrue(broker.pending().isEmpty());
    }

    @Test
    void oversizedFrameIsRejectedBeforeReadingAndAudited() throws IOException, IpcException {
        RunDir dir = start();
        byte[] header = ByteBuffer.allocate(4).putInt(Frames.MAX_REQUEST + 1).array();
        assertEquals(Decision.DENIED_MALFORMED, decision(raw(dir, header)));
        assertTrue(audited(Decision.DENIED_MALFORMED));
    }

    @Test
    void garbageFrameIsMalformed() throws IOException, IpcException {
        RunDir dir = start();
        byte[] junk = {0, 0, 0, 3, (byte) 0xa1, 0x61, 0x76};
        assertEquals(Decision.DENIED_MALFORMED, decision(raw(dir, junk)));
    }

    @Test
    void tokenFileIsOwnerOnlyAndRotatesWithLock() throws IOException, IpcException {
        RunDir dir = start();
        Path token = dir.path().resolve(RunDir.AUTH_FILE);
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.path())));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(token)));
        byte[] first = Files.readAllBytes(token);

        server.locked();
        assertFalse(Files.exists(token));
        IpcException e = assertThrows(IpcException.class, () -> BrokerClient.call(dir, request()));
        assertEquals(IpcException.Code.NO_BROKER, e.code());

        server.unlocked();
        byte[] second = Files.readAllBytes(token);
        assertEquals(ApprovalBroker.TOKEN_BYTES, second.length);
        assertFalse(java.security.MessageDigest.isEqual(first, second), "a new token after every unlock");
    }

    @Test
    void stolenOldTokenIsUselessAfterRotation() throws IOException, IpcException {
        RunDir dir = start();
        byte[] old = Files.readAllBytes(dir.path().resolve(RunDir.AUTH_FILE));
        server.locked();
        server.unlocked();
        byte[] frame;
        try (SecretBytes stale = SecretBytes.copyOf(old)) {
            frame = IpcCodec.encodeRequest(request(), stale);
        }
        ByteBuffer out = ByteBuffer.allocate(4 + frame.length).putInt(frame.length).put(frame);
        assertEquals(Decision.DENIED_AUTH, decision(raw(dir, out.array())));
    }

    @Test
    void unsafeRunDirectoriesAreRefused() throws IOException {
        Path real = Files.createDirectory(tmp.resolve("real"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path link = Files.createSymbolicLink(tmp.resolve("link"), real);
        assertEquals(IpcException.Code.UNSAFE_PATH, assertThrows(IpcException.class, () -> RunDir.prepare(link)).code());
        Files.setPosixFilePermissions(real, PosixFilePermissions.fromString("rwxr-x---"));
        assertEquals(IpcException.Code.UNSAFE_PATH, assertThrows(IpcException.class, () -> RunDir.prepare(real)).code());
        assertEquals(IpcException.Code.NO_BROKER,
                assertThrows(IpcException.class, () -> RunDir.existing(tmp.resolve("absent"))).code());
    }

    @Test
    void linkedTokenFileIsRefused() throws IOException, IpcException {
        RunDir dir = RunDir.prepare(tmp.resolve("run"));
        Path target = Files.write(tmp.resolve("elsewhere"), new byte[32]);
        Files.createSymbolicLink(dir.path().resolve(RunDir.AUTH_FILE), target);
        assertEquals(IpcException.Code.UNSAFE_PATH,
                assertThrows(IpcException.class, () -> BrokerClient.call(dir, request())).code());
    }

    @Test
    void regularFileAtSocketPathIsRefused() throws IOException, IpcException {
        RunDir dir = RunDir.prepare(tmp.resolve("run"));
        Files.write(dir.socketPath(), new byte[1]);
        assertEquals(IpcException.Code.UNSAFE_PATH, assertThrows(IpcException.class,
                () -> BrokerServer.start(dir, broker, RELEASE_DB)).code());
    }

    @Test
    void liveSocketIsLeftAloneAndStaleOneIsReplaced() throws IOException, IpcException {
        RunDir dir = start();
        assertEquals(IpcException.Code.IO, assertThrows(IpcException.class,
                () -> BrokerServer.start(dir, broker, RELEASE_DB)).code(), "a second broker never steals a live socket");
        try (SocketChannel ch = SocketChannel.open(UnixDomainSocketAddress.of(dir.socketPath()))) {
            assertTrue(ch.isConnected(), "the first broker still serves");
        }
        server.close();
        server = null;
        // A crashed broker leaves its socket file behind, with nothing accepting on it.
        try (ServerSocketChannel dead = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            dead.bind(UnixDomainSocketAddress.of(dir.socketPath()));
        }
        assertTrue(Files.exists(dir.socketPath()));
        server = BrokerServer.start(dir, broker, RELEASE_DB);
        try (SocketChannel ch = SocketChannel.open(UnixDomainSocketAddress.of(dir.socketPath()))) {
            assertTrue(ch.isConnected(), "the stale socket was replaced");
        }
    }

    @Test
    void peerRunningAsAnotherUserIsDenied() throws IOException, IpcException {
        try (SocketChannel probe = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            assumeTrue(probe.supportedOptions().contains(ExtendedSocketOptions.SO_PEERCRED), "no SO_PEERCRED here");
        }
        RunDir dir = start(new ApprovalBroker(Clock.systemUTC(), events::add, PolicyStore.inMemory(), "someone-else"));
        try (Reply reply = BrokerClient.call(dir, request())) {
            assertEquals(Decision.DENIED_AUTH, reply.decision());
        }
    }
}
