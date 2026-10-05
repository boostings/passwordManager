package pm.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.StandardSocketOptions;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.ssh.AgentIdentity;
import pm.crypto.ssh.SshAgentClient;
import pm.crypto.ssh.SshException;

/**
 * Fuzz harness for the ssh-agent reply parser (ADR 0013, SR-062, T-FUZZ-AGENT): the real
 * {@link SshAgentClient}, through its public API, against a fake agent on a Unix domain socket in an
 * owner-only temporary directory. No thread is used: the client's connect completes from the
 * listener's backlog, the harness then accepts the server end, writes the fuzzed reply into the
 * socket (non-blocking, so only what fits is sent) and shuts its output, so the client reads exactly
 * those bytes followed by end-of-stream.
 *
 * <p>Input: byte 0 picks the call ({@code list} when even, {@code removeAll} when odd); the rest is
 * the byte stream the agent sends, in one of two forms:
 * <ul>
 *   <li>raw, frame header included, optionally {@link Stretch stretched} with a run so a 4 KiB
 *       input can reach the 16 KiB blob and 256 KiB frame limits;</li>
 *   <li>a <b>frame near a limit</b> ({@code '#' u8 mode, u8 delta, unit}), built by {@link #frame}
 *       with the signed {@code delta}: mode 0 is an identities answer whose header counts
 *       {@code 1024 + delta} identities, each a copy of {@code unit} (so a 12-byte minimal identity
 *       reaches 1,024 and 1,025 cheaply); mode 1 is a complete answer of exactly
 *       {@code 256 KiB + delta} bytes, {@code unit} then identities at the blob and comment limits
 *       filling the rest; modes 2 and 3 are a header claiming {@code 1 MiB + delta} or
 *       {@code 256 KiB + delta} bytes followed only by {@code unit}.</li>
 * </ul>
 * Oracles, independent of the client:
 * <ul>
 *   <li>differential: the outcome (identities, {@code AGENT_REFUSED} or {@code BAD_REPLY}) equals
 *       {@link #reference}, a separate reading of the wire format and limits in ADR 0013
 *       (1 byte to 256 KiB frames, at most 1,024 identities, 16 KiB blobs whose first string is at
 *       most 64 bytes, 4 KiB comments, no trailing bytes, exact 1-byte success/failure);</li>
 *   <li>no other exception and no other code (a {@code TIMEOUT} would mean the client hung on a
 *       reply that had already ended);</li>
 *   <li>every printed field is free of control, format and separator characters;</li>
 *   <li>bounded allocation, measured around the client call alone: under {@link #ALLOCATION_BOUND}
 *       (one 256 KiB frame buffer plus 256 KiB) plus {@link #PER_STREAM_BYTE} per byte sent, so a
 *       client that sized its buffer from a frame header past 256 KiB without reading the bytes
 *       (a 1 MiB header followed by a few bytes) fails it.</li>
 * </ul>
 */
@Tag("T-FUZZ-SSH")
class AgentReplyFuzzTest {
    // ADR 0013 limits, written here independently of the client constants (an oracle must not
    // borrow the limits it checks from the code under test).
    static final int MAX_FRAME = 256 * 1024;
    static final int MAX_IDENTITIES = 1024;
    static final int MAX_BLOB = 16 * 1024;
    static final int MAX_NAME = 64;
    static final int MAX_COMMENT = 4096;
    /** Longest stream a stretched input may describe: just past the frame limit. */
    static final int MAX_STREAM = MAX_FRAME + 64 * 1024;
    private static final int FAILURE = 5;
    private static final int SUCCESS = 6;
    private static final int IDENTITIES_ANSWER = 12;
    /** Asks the kernel for room for a whole over-limit frame, so the write is not cut short. */
    private static final int SEND_BUFFER = 1 << 20;
    private static final Duration DEADLINE = Duration.ofSeconds(5);
    /**
     * Fixed part of the per-call allocation ceiling: the client may allocate a whole frame (at most
     * 256 KiB) from its header before the bytes arrive, plus 256 KiB for the selector, request and
     * reply objects. It is tied to the frame limit, so a buffer sized from a 1 MiB header fails it
     * unless the stream itself is long; the ceiling grows by {@link #PER_STREAM_BYTE} per byte sent
     * for the copies a long accepted reply needs (blobs, comment strings) and the per-byte
     * allocation of the fuzzing instrumentation.
     */
    static final long ALLOCATION_BOUND = MAX_FRAME + 256 * 1024;
    static final long PER_STREAM_BYTE = 64;
    /** Marks a frame-near-a-limit input (see the class comment). */
    static final byte FRAME_MARK = '#';
    /** One identity at the blob and comment limits: string blob, string comment. */
    private static final int BIG_IDENTITY = 4 + MAX_BLOB + 4 + MAX_COMMENT;
    /** The smallest identity: a 4-byte blob naming an empty type, and an empty comment. */
    private static final int MIN_IDENTITY = 4 + 4 + 4;

    private static Path sock;
    private static ServerSocketChannel agent;

    @BeforeAll
    static void listen(@TempDir Path tmp) throws IOException {
        Path dir = Files.createDirectory(tmp.resolve("a"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        sock = dir.resolve("s");
        agent = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        agent.bind(UnixDomainSocketAddress.of(sock));
        // Load and initialise every class on the path once (accepted list, refusal, malformed
        // reply, simple reply), so the allocation oracle measures the reply handling and not
        // one-time class loading.
        for (String seed : new String[] {"two-identities.bin", "list-refused.bin", "oversized-frame.bin", "success.bin"}) {
            exercise(Seeds.read(AgentReplyFuzzTest.class, seed), Long.MAX_VALUE);
        }
        // The near-limit frames, built here rather than read from seeds a planted-bug run may
        // withhold: 1,024 minimal identities, a full 256 KiB answer, a 1 MiB header.
        byte[] minimal = {0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0};
        for (byte[] near : new byte[][] {frame(0, 0, minimal), frame(1, 0, minimal), frame(2, 0, new byte[] {12})}) {
            byte[] in = new byte[1 + near.length];
            System.arraycopy(near, 0, in, 1, near.length);
            exercise(in, Long.MAX_VALUE);
        }
    }

    @AfterAll
    static void shut() throws IOException {
        agent.close();
    }

    /** One identity as the reference reads it: blob, type name and comment. */
    record Identity(String blobHex, String type, String comment) {
    }

    /** What the reference expects: identities (for {@code list}), or an error code, or success. */
    record Outcome(List<Identity> identities, SshException.Code error) {
        static Outcome failed(SshException.Code code) {
            return new Outcome(List.of(), code);
        }
    }

    @FuzzTest
    void fuzz(byte[] in) throws IOException {
        exercise(in, ALLOCATION_BOUND);
    }

    /** Runs one input; returns how many stream bytes reached the client. */
    private static int exercise(byte[] in, long allocationBound) throws IOException {
        if (in.length == 0) {
            return 0;
        }
        boolean list = (in[0] & 1) == 0;
        byte[] stream = stream(Arrays.copyOfRange(in, 1, in.length));
        Outcome actual;
        byte[] sent;
        try (SshAgentClient client = SshAgentClient.connect(sock, DEADLINE);
                SocketChannel peer = agent.accept()) {
            peer.setOption(StandardSocketOptions.SO_SNDBUF, SEND_BUFFER);
            peer.configureBlocking(false);
            ByteBuffer out = ByteBuffer.wrap(stream);
            peer.write(out);
            sent = Arrays.copyOf(stream, out.position());
            peer.shutdownOutput();
            actual = call(client, list, allocationBound == Long.MAX_VALUE
                    ? Long.MAX_VALUE : allocationBound + PER_STREAM_BYTE * sent.length);
        } catch (SshException e) {
            throw new AssertionError("could not reach the fake agent: " + e.code(), e);
        }
        assertEquals(reference(sent, list), actual);
        return sent.length;
    }

    /** The agent's byte stream an input describes: a frame near a limit, or raw (maybe stretched). */
    static byte[] stream(byte[] in) {
        if (in.length >= 3 && in[0] == FRAME_MARK) {
            return frame(in[1] & 3, in[2], Arrays.copyOfRange(in, 3, in.length));
        }
        return Stretch.apply(in, MAX_STREAM);
    }

    /** A frame near the count or size limit (see the class comment), {@code delta} from it. */
    static byte[] frame(int mode, int delta, byte[] unit) {
        ByteBuffer b;
        switch (mode) {
            case 0 -> {
                int count = MAX_IDENTITIES + delta;
                int copies = unit.length == 0 ? count : Math.min(count, (MAX_STREAM - 9) / unit.length);
                b = ByteBuffer.allocate(4 + 1 + 4 + copies * unit.length);
                b.putInt(b.capacity() - 4).put((byte) IDENTITIES_ANSWER).putInt(count);
                for (int i = 0; i < copies; i++) {
                    b.put(unit);
                }
            }
            case 1 -> {
                int length = MAX_FRAME + delta;
                int rest = length - 1 - 4 - unit.length;
                // Too little room for even one identity: the gap stays zeros (trailing bytes).
                int fillers = rest < MIN_IDENTITY ? 0 : (rest + BIG_IDENTITY - 1) / BIG_IDENTITY;
                b = ByteBuffer.allocate(4 + Math.max(length, 1 + 4 + unit.length));
                b.putInt(length).put((byte) IDENTITIES_ANSWER).putInt(1 + fillers).put(unit);
                for (int i = 0; i < fillers; i++) {
                    // Spread the rest so each filler is at most BIG_IDENTITY and at least MIN_IDENTITY.
                    int size = rest / (fillers - i);
                    rest -= size;
                    int blob = Math.min(MAX_BLOB, Math.max(4, size - 8));
                    b.putInt(blob).putInt(0).put(new byte[blob - 4]).putInt(size - 8 - blob).put(new byte[size - 8 - blob]);
                }
            }
            default -> {
                b = ByteBuffer.allocate(4 + unit.length);
                b.putInt((mode == 2 ? 4 * MAX_FRAME : MAX_FRAME) + delta).put(unit);
            }
        }
        return b.array();
    }

    /** Runs the call, measuring the client's allocation alone against {@code bound}. */
    private static Outcome call(SshAgentClient client, boolean list, long bound) {
        long start = Allocation.current();
        try {
            if (!list) {
                client.removeAll();
                checkAllocation(start, bound);
                return new Outcome(List.of(), null);
            }
            List<AgentIdentity> ids = client.list();
            checkAllocation(start, bound);
            List<Identity> got = new ArrayList<>();
            for (AgentIdentity id : ids) {
                assertTrue(printable(id.type()) && printable(id.comment()), "unsafe text reached the caller");
                got.add(new Identity(hex(id.publicKeyBlob()), id.type(), id.comment()));
            }
            return new Outcome(got, null);
        } catch (SshException e) {
            checkAllocation(start, bound);
            assertEquals(e.code().name(), e.getMessage());
            assertTrue(e.code() == SshException.Code.BAD_REPLY || e.code() == SshException.Code.AGENT_REFUSED,
                    "unexpected code " + e.code());
            return Outcome.failed(e.code());
        }
    }

    private static void checkAllocation(long start, long bound) {
        long used = Allocation.current() - start;
        assertTrue(used < bound, () -> "allocation bound: " + used + " bytes, bound " + bound);
    }

    /** The expected outcome of the stream {@code sent}, read independently of the client. */
    static Outcome reference(byte[] sent, boolean list) {
        ByteBuffer b = ByteBuffer.wrap(sent);
        if (b.remaining() < Integer.BYTES) {
            return Outcome.failed(SshException.Code.BAD_REPLY);
        }
        long n = Integer.toUnsignedLong(b.getInt());
        if (n == 0 || n > MAX_FRAME || n > b.remaining()) {
            return Outcome.failed(SshException.Code.BAD_REPLY);
        }
        ByteBuffer body = ByteBuffer.wrap(sent, 4, (int) n).slice();
        int type = body.get() & 0xff;
        if (!list) {
            if (n == 1 && type == SUCCESS) {
                return new Outcome(List.of(), null);
            }
            return Outcome.failed(n == 1 && type == FAILURE ? SshException.Code.AGENT_REFUSED : SshException.Code.BAD_REPLY);
        }
        if (type == FAILURE && n == 1) {
            return Outcome.failed(SshException.Code.AGENT_REFUSED);
        }
        if (type != IDENTITIES_ANSWER || body.remaining() < Integer.BYTES) {
            return Outcome.failed(SshException.Code.BAD_REPLY);
        }
        long count = Integer.toUnsignedLong(body.getInt());
        if (count > MAX_IDENTITIES) {
            return Outcome.failed(SshException.Code.BAD_REPLY);
        }
        List<Identity> ids = new ArrayList<>();
        for (long i = 0; i < count; i++) {
            ByteBuffer blob = string(body, MAX_BLOB);
            ByteBuffer name = blob == null ? null : string(blob.duplicate(), MAX_NAME);
            ByteBuffer comment = name == null ? null : string(body, MAX_COMMENT);
            if (comment == null) {
                return Outcome.failed(SshException.Code.BAD_REPLY);
            }
            ids.add(new Identity(hex(bytes(blob)), printableCopy(StandardCharsets.US_ASCII.decode(name).toString()),
                    printableCopy(StandardCharsets.UTF_8.decode(comment).toString())));
        }
        return body.hasRemaining() ? Outcome.failed(SshException.Code.BAD_REPLY) : new Outcome(ids, null);
    }

    /** An SSH {@code string} of at most {@code max} bytes, or null if it does not fit. */
    private static ByteBuffer string(ByteBuffer b, int max) {
        if (b.remaining() < Integer.BYTES) {
            return null;
        }
        long len = Integer.toUnsignedLong(b.getInt());
        if (len > max || len > b.remaining()) {
            return null;
        }
        byte[] out = new byte[(int) len];
        b.get(out);
        return ByteBuffer.wrap(out);
    }

    private static byte[] bytes(ByteBuffer b) {
        byte[] out = new byte[b.remaining()];
        b.duplicate().get(out);
        return out;
    }

    private static boolean unsafe(int c) {
        int t = Character.getType(c);
        return c < 0x20 || (c >= 0x7f && c <= 0x9f) || t == Character.FORMAT || c == 0x2028 || c == 0x2029;
    }

    private static boolean printable(String s) {
        return s.codePoints().noneMatch(AgentReplyFuzzTest::unsafe);
    }

    private static String printableCopy(String s) {
        StringBuilder b = new StringBuilder();
        s.codePoints().forEach(c -> b.appendCodePoint(unsafe(c) ? '?' : c));
        return b.toString();
    }

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    /** Each seed gives the outcome its name says, from both the client and the reference. */
    @Test
    void seedCorpusBehavesAsLabelled() throws IOException {
        SshException.Code bad = SshException.Code.BAD_REPLY;
        Map<String, SshException.Code> errors = Map.ofEntries(Map.entry("list-refused.bin", SshException.Code.AGENT_REFUSED),
                Map.entry("failure.bin", SshException.Code.AGENT_REFUSED), Map.entry("trailing-byte.bin", bad),
                Map.entry("oversized-frame.bin", bad), Map.entry("count-over-limit.bin", bad),
                Map.entry("stretch-frame-over-limit.bin", bad), Map.entry("count-1025.bin", bad),
                Map.entry("frame-over-limit-by-one.bin", bad), Map.entry("frame-claims-1MiB.bin", bad),
                Map.entry("failure-trailing-byte.bin", bad));
        for (Map.Entry<String, SshException.Code> seed : errors.entrySet()) {
            byte[] in = Seeds.read(AgentReplyFuzzTest.class, seed.getKey());
            Outcome expected = reference(stream(Arrays.copyOfRange(in, 1, in.length)), (in[0] & 1) == 0);
            assertEquals(seed.getValue(), expected.error(), seed.getKey());
            fuzz(in);
        }
        Map<String, Integer> accepted = Map.of("two-identities.bin", 2, "no-identities.bin", 0,
                "unsafe-comment.bin", 1, "success.bin", 0, "duplicate-identity.bin", 2, "stretch-blob-at-limit.bin", 1,
                "count-1024.bin", MAX_IDENTITIES, "frame-at-limit.bin", 14);
        for (Map.Entry<String, Integer> seed : accepted.entrySet()) {
            byte[] in = Seeds.read(AgentReplyFuzzTest.class, seed.getKey());
            Outcome expected = reference(stream(Arrays.copyOfRange(in, 1, in.length)), (in[0] & 1) == 0);
            assertEquals(null, expected.error(), seed.getKey());
            assertEquals(seed.getValue(), expected.identities().size(), seed.getKey());
            fuzz(in);
        }
        byte[] unsafe = Seeds.read(AgentReplyFuzzTest.class, "unsafe-comment.bin");
        assertEquals("a?[31m?b", reference(Arrays.copyOfRange(unsafe, 1, unsafe.length), true)
                .identities().get(0).comment(), "control and bidi characters become ?");
        Outcome truncated = reference(Arrays.copyOfRange(unsafe, 1, unsafe.length - 1), true);
        assertEquals(SshException.Code.BAD_REPLY, truncated.error(), "a reply cut short is BAD_REPLY");
        fuzz(Arrays.copyOf(unsafe, unsafe.length - 1));
    }

    /**
     * The limits, at and one past each, deterministically: the fuzzer's 4096-byte inputs reach them
     * only through {@link Stretch}, so these pin the over-limit paths independently of a campaign.
     */
    @Test
    void limitsHoldAtAndJustPastTheirValues() throws IOException {
        assertLimit(true, answer(MAX_IDENTITIES, identity(0, 4, 0)));
        assertLimit(false, answer(MAX_IDENTITIES + 1, identity(0, 4, 0)));
        assertLimit(true, answer(1, identity(MAX_NAME, MAX_BLOB, MAX_COMMENT)));
        assertLimit(false, answer(1, identity(MAX_NAME + 1, MAX_BLOB, 0)));
        assertLimit(false, answer(1, identity(11, MAX_BLOB + 1, 0)));
        assertLimit(false, answer(1, identity(11, 15, MAX_COMMENT + 1)));
        // A frame of exactly 256 KiB: 12 identities at the blob and comment limits, then one sized
        // to fill the rest; one byte more in its blob takes the frame past the limit.
        int full = 4 + MAX_BLOB + 4 + MAX_COMMENT;
        int rest = MAX_FRAME - 1 - 4 - 12 * full - 4 - 4 - MAX_COMMENT;
        assertLimit(true, answer(13, identity(11, MAX_BLOB, MAX_COMMENT), 12, identity(11, rest, MAX_COMMENT)));
        assertLimit(false, answer(13, identity(11, MAX_BLOB, MAX_COMMENT), 12, identity(11, rest + 1, MAX_COMMENT)));
    }

    /** Sends the frame whole and checks the client and the reference agree on accept or reject. */
    private static void assertLimit(boolean accepted, byte[] body) throws IOException {
        ByteBuffer frame = ByteBuffer.allocate(Integer.BYTES + body.length).putInt(body.length).put(body);
        byte[] in = new byte[1 + frame.capacity()];
        System.arraycopy(frame.array(), 0, in, 1, frame.capacity());
        assertEquals(frame.capacity(), exercise(in, ALLOCATION_BOUND), "frame not sent whole");
        Outcome expected = reference(frame.array(), true);
        assertEquals(accepted ? null : SshException.Code.BAD_REPLY, expected.error(), "body of " + body.length);
    }

    /** An identities answer: {@code count} identities, the first {@code times} of them {@code first}. */
    private static byte[] answer(int count, byte[] each) {
        return answer(count, each, count, each);
    }

    private static byte[] answer(int count, byte[] first, int times, byte[] last) {
        ByteBuffer b = ByteBuffer.allocate(1 + Integer.BYTES + times * first.length + (count - times) * last.length);
        b.put((byte) IDENTITIES_ANSWER).putInt(count);
        for (int i = 0; i < count; i++) {
            b.put(i < times ? first : last);
        }
        return b.array();
    }

    /** One identity: a blob of {@code blobLength} bytes opening with a name, and a comment. */
    private static byte[] identity(int nameLength, int blobLength, int commentLength) {
        ByteBuffer blob = ByteBuffer.allocate(blobLength);
        blob.putInt(nameLength);
        for (int i = 0; i < nameLength && blob.hasRemaining(); i++) {
            blob.put((byte) 'n');
        }
        return ByteBuffer.allocate(Integer.BYTES + blobLength + Integer.BYTES + commentLength)
                .putInt(blobLength).put(blob.array()).putInt(commentLength).array();
    }
}
