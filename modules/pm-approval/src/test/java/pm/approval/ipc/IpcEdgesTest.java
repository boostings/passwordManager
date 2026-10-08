package pm.approval.ipc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.SocketAddress;
import java.net.SocketOption;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.NetworkChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.function.Consumer;
import jdk.net.ExtendedSocketOptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.approval.ApprovalBroker;
import pm.approval.ApprovalRequest;
import pm.approval.Decision;
import pm.approval.PolicyStore;
import pm.crypto.SecretBytes;
import pm.storage.OwnerOnly;
import pm.storage.StorageException;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/** The strict decoding, framing, busy and token-file paths of the broker IPC (approval-model §5). */
class IpcEdgesTest {
    private static final CborLimits LIMITS = new CborLimits(4, 4_096, 1 << 16, 1 << 20);
    private static final String ME = System.getProperty("user.name");

    @TempDir
    Path tmp;

    private static ApprovalRequest request(Optional<String> origin, List<UUID> records) {
        return new ApprovalRequest(UUID.randomUUID(),
                new ApprovalRequest.Requester(ApprovalRequest.Kind.CLI, "pm env run"),
                ApprovalRequest.Operation.ENV_INJECT,
                new ApprovalRequest.Scope("app", "dev", Optional.of(new TreeSet<>(List.of("DB"))), records),
                Duration.ZERO,
                new ApprovalRequest.Display(List.of("/usr/bin/env"), origin, ApprovalRequest.Effect.INJECT),
                Instant.ofEpochSecond(1_700_000_000L));
    }

    /** A valid request frame with one member changed by {@code edit}. */
    private static byte[] requestWith(Consumer<Map<String, CborValue>> edit) throws CborException {
        byte[] valid;
        try (SecretBytes token = SecretBytes.copyOf(new byte[ApprovalBroker.TOKEN_BYTES])) {
            valid = IpcCodec.encodeRequest(request(Optional.empty(), List.of()), token);
        }
        Map<String, CborValue> m = new LinkedHashMap<>(((CborValue.MapV) CborReader.decode(valid, LIMITS)).entries());
        edit.accept(m);
        return CborWriter.encode(new CborValue.MapV(m));
    }

    private static IpcException.Code requestCode(byte[] frame) {
        return assertThrows(IpcException.class, () -> IpcCodec.decodeRequest(frame)).code();
    }

    private static IpcException.Code replyCode(byte[] frame) {
        return assertThrows(IpcException.class, () -> IpcCodec.decodeReply(frame)).code();
    }

    private static CborValue text(String s) {
        return new CborValue.Text(s);
    }

    @Test
    void aRequestWithRecordsAndAnOriginRoundTrips() throws IpcException {
        UUID record = UUID.randomUUID();
        byte[] frame;
        try (SecretBytes token = SecretBytes.copyOf(new byte[ApprovalBroker.TOKEN_BYTES])) {
            frame = IpcCodec.encodeRequest(request(Optional.of("https://example.org"), List.of(record)), token);
        }
        IpcCodec.Decoded decoded = IpcCodec.decodeRequest(frame);
        decoded.token().close();
        assertEquals(List.of(record), decoded.request().scope().records());
        assertEquals(Optional.of("https://example.org"), decoded.request().display().origin());
    }

    @Test
    void aWholeProfileRequestRoundTripsWithoutVars() throws IpcException {
        ApprovalRequest whole = new ApprovalRequest(UUID.randomUUID(),
                new ApprovalRequest.Requester(ApprovalRequest.Kind.CLI, "pm env run"),
                ApprovalRequest.Operation.ENV_INJECT, ApprovalRequest.Scope.profile("app", "dev"), Duration.ZERO,
                new ApprovalRequest.Display(List.of("/usr/bin/env"), Optional.empty(), ApprovalRequest.Effect.INJECT),
                Instant.ofEpochSecond(1_700_000_000L));
        byte[] frame;
        try (SecretBytes token = SecretBytes.copyOf(new byte[ApprovalBroker.TOKEN_BYTES])) {
            frame = IpcCodec.encodeRequest(whole, token);
        }
        IpcCodec.Decoded decoded = IpcCodec.decodeRequest(frame);
        decoded.token().close();
        assertEquals(whole, decoded.request());
    }

    @Test
    void everyMalformedRequestShapeIsRefused() throws CborException {
        assertEquals(IpcException.Code.MALFORMED, requestCode(CborWriter.encode(new CborValue.Array(List.of()))));
        assertEquals(IpcException.Code.MALFORMED, requestCode(new byte[] {(byte) 0xff}), "not CBOR");
        assertEquals(IpcException.Code.MALFORMED, requestCode(requestWith(m -> m.remove("token"))), "missing");
        assertEquals(IpcException.Code.MALFORMED, requestCode(requestWith(m -> m.put("extra", text("x")))), "unknown");
        assertEquals(IpcException.Code.MALFORMED, requestCode(requestWith(m -> m.put("v", new CborValue.UInt(2)))));
        assertEquals(IpcException.Code.MALFORMED, requestCode(requestWith(m -> m.put("token", text("t")))));
        assertEquals(IpcException.Code.MALFORMED, requestCode(requestWith(m -> m.put("label", new CborValue.UInt(1)))));
        assertEquals(IpcException.Code.MALFORMED, requestCode(requestWith(m -> m.put("duration", text("1")))));
        assertEquals(IpcException.Code.MALFORMED, requestCode(requestWith(m -> m.put("argv", text("/bin/sh")))));
    }

    @Test
    void everyMalformedReplyShapeIsRefusedAndValuesTakenAreWiped() {
        assertEquals(IpcException.Code.MALFORMED, replyCode(CborWriter.encode(new CborValue.Array(List.of()))));
        assertEquals(IpcException.Code.MALFORMED, replyCode(new byte[] {(byte) 0xff}), "not CBOR");
        assertEquals(IpcException.Code.MALFORMED, replyCode(CborWriter.encode(new CborValue.MapV(Map.of()))));
        assertEquals(IpcException.Code.MALFORMED, replyCode(CborWriter.encode(new CborValue.MapV(
                Map.of("decision", text("DENIED"), "extra", text("x"))))));
        assertEquals(IpcException.Code.MALFORMED, replyCode(CborWriter.encode(new CborValue.MapV(
                Map.of("decision", text("ALLOWED_ONCE"), "vars", text("x"))))));
        byte[] taken = "first".getBytes(StandardCharsets.UTF_8);
        Map<String, CborValue> vars = new LinkedHashMap<>();
        vars.put("A", new CborValue.Bytes(taken));
        vars.put("B", text("not bytes"));
        assertEquals(IpcException.Code.MALFORMED, replyCode(CborWriter.encode(new CborValue.MapV(
                Map.of("decision", text("ALLOWED_ONCE"), "vars", new CborValue.MapV(vars))))));
        assertEquals(IpcException.Code.MALFORMED, replyCode(CborWriter.encode(new CborValue.MapV(
                Map.of("decision", text("DENIED"), "vars", new CborValue.MapV(Map.of("A",
                        new CborValue.Bytes(taken))))))), "a denial carries no values");
        assertEquals("DENIED_WITH_VALUES", assertThrows(IllegalArgumentException.class,
                () -> new Reply(Decision.DENIED, new TreeMap<>(Map.of("A", SecretBytes.copyOf(taken))))).getMessage());
    }

    @Test
    void aFrameWithANegativeLengthIsTooLarge() throws IOException {
        Path file = tmp.resolve("frame");
        Files.write(file, new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff});
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            assertEquals(IpcException.Code.TOO_LARGE,
                    assertThrows(IpcException.class, () -> Frames.read(ch, Frames.MAX_REQUEST)).code());
        }
    }

    @Test
    void tokenFilesOfTheWrongSizeOrModeAndAMissingRunDirAreRefused()
            throws IOException, IpcException, StorageException {
        assertEquals(IpcException.Code.NO_BROKER,
                assertThrows(IpcException.class, () -> RunDir.existing(tmp.resolve("absent"))).code());
        RunDir dir = RunDir.prepare(tmp.resolve("run"));
        assertEquals(dir.path(), RunDir.existing(dir.path()).path());
        Path authFile = dir.path().resolve(RunDir.AUTH_FILE);
        int expected = ApprovalBroker.TOKEN_BYTES;
        Files.write(authFile, new byte[expected + 1]);
        OwnerOnly.apply(authFile);
        assertEquals(IpcException.Code.MALFORMED, assertThrows(IpcException.class, dir::readToken).code(), "long");
        Files.write(authFile, new byte[expected - 1]);
        assertEquals(IpcException.Code.MALFORMED, assertThrows(IpcException.class, dir::readToken).code(), "short");
        Files.write(authFile, new byte[expected]);
        dir.readToken().close();
        if (Files.getFileAttributeView(authFile, PosixFileAttributeView.class) != null) {
            Files.setPosixFilePermissions(authFile, mode("rw-r-----"));
            assertEquals(IpcException.Code.UNSAFE_PATH, assertThrows(IpcException.class, dir::readToken).code());
        }
    }

    @Test
    // The clients stay open across the assertions and the server is closed twice on purpose, so
    // try-with-resources does not fit; the finally block closes everything.
    @SuppressWarnings({"PMD.CloseResource", "PMD.UseTryWithResources"})
    void theNinthWaitingClientIsBusyAndSilentOnesAreDroppedAfterTheReadDeadline()
            throws IOException, IpcException {
        ApprovalBroker broker = new ApprovalBroker(Clock.systemUTC(), e -> { }, PolicyStore.inMemory(), ME);
        RunDir dir = RunDir.prepare(tmp.resolve("busy"));
        List<SocketChannel> silent = new ArrayList<>();
        BrokerServer server = BrokerServer.start(dir, broker, grant -> new TreeMap<>());
        try {
            server.unlocked();
            for (int i = 0; i < BrokerServer.MAX_CONNECTIONS; i++) {
                SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX);
                ch.connect(UnixDomainSocketAddress.of(dir.socketPath()));
                silent.add(ch);
            }
            try (SocketChannel ninth = SocketChannel.open(StandardProtocolFamily.UNIX)) {
                ninth.connect(UnixDomainSocketAddress.of(dir.socketPath()));
                try (Reply r = IpcCodec.decodeReply(Frames.read(ninth, Frames.MAX_REPLY))) {
                    assertEquals(Decision.DENIED_BUSY, r.decision());
                }
            }
            for (SocketChannel ch : silent) {
                // The server closes a client that sent nothing before the deadline, without a reply.
                assertEquals(-1, ch.read(ByteBuffer.allocate(1)));
            }
        } finally {
            for (SocketChannel ch : silent) {
                ch.close();
            }
            server.close();
            server.close(); // a second close is harmless
        }
    }

    @Test
    void aFrameArrivingAByteAtATimeIsReadWholeAndOneCutShortIsMalformed() throws IpcException {
        byte[] frame = {0, 0, 0, 2, 'o', 'k'};
        assertEquals("ok", new String(Frames.read(new Trickle(frame, frame.length), 16), StandardCharsets.US_ASCII));
        for (int cut : new int[] {2, 5}) {
            assertEquals(IpcException.Code.MALFORMED,
                    assertThrows(IpcException.class, () -> Frames.read(new Trickle(frame, cut), 16)).code(), "cut " + cut);
        }
    }

    /** A channel that delivers {@code limit} bytes of {@code data}, one per read with an empty read between, then EOF. */
    private static final class Trickle implements java.nio.channels.ByteChannel {
        private final byte[] data;
        private final int limit;
        private int next;
        private boolean idle;

        Trickle(byte[] data, int limit) {
            this.data = data.clone();
            this.limit = limit;
        }

        @Override
        public int read(ByteBuffer dst) {
            if (next == limit) {
                return -1;
            }
            idle = !idle;
            if (idle) {
                return 0;
            }
            dst.put(data[next++]);
            return 1;
        }

        @Override
        public int write(ByteBuffer src) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isOpen() {
            return true;
        }

        @Override
        public void close() {
            // Nothing to release.
        }
    }

    @Test
    void thePeerIsUnknownWhereTheSocketCannotTellAndNeverMatchesWhenTheReadFails() {
        assertEquals(Optional.empty(), BrokerServer.peerUser(new FakeChannel(false, false)), "as on Windows");
        assertEquals(Optional.of(""), BrokerServer.peerUser(new FakeChannel(true, true)), "an I/O failure");
        assertEquals(Optional.of(""), BrokerServer.peerUser(new FakeChannel(true, false)), "unsupported after all");
    }

    private static Set<java.nio.file.attribute.PosixFilePermission> mode(String text) {
        return PosixFilePermissions.fromString(text);
    }

    /** A channel that does or does not offer peer credentials, and fails to read them. */
    private static final class FakeChannel implements NetworkChannel {
        private final boolean offers;
        private final boolean fails;

        FakeChannel(boolean offers, boolean fails) {
            this.offers = offers;
            this.fails = fails;
        }

        @Override
        public Set<SocketOption<?>> supportedOptions() {
            return offers ? Set.of(ExtendedSocketOptions.SO_PEERCRED) : Set.of();
        }

        @Override
        public <T> T getOption(SocketOption<T> name) throws IOException {
            if (fails) {
                throw new IOException("unreadable");
            }
            throw new UnsupportedOperationException(name.name());
        }

        @Override
        public NetworkChannel bind(SocketAddress local) {
            throw new UnsupportedOperationException();
        }

        @Override
        public <T> NetworkChannel setOption(SocketOption<T> name, T value) {
            throw new UnsupportedOperationException();
        }

        @Override
        public SocketAddress getLocalAddress() {
            return null;
        }

        @Override
        public boolean isOpen() {
            return true;
        }

        @Override
        public void close() {
            // nothing to release
        }
    }
}
