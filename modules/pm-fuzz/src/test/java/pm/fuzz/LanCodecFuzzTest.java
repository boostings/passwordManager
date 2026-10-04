package pm.fuzz;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.sharing.wire.Frames;
import pm.sharing.wire.Message;
import pm.sharing.wire.Messages;
import pm.sharing.wire.Octets;
import pm.sharing.wire.WireException;
import pm.sharing.wire.WireException.Code;

/**
 * Fuzz harness for the LAN wire format (SR-206, T-FUZZ-LAN). The input is read twice: as a stream
 * of frames, each body handed to the message decoder, and as one frame body. {@link Frames#read}
 * may only refuse with {@code CLOSED}, {@code TRUNCATED} or {@code FRAME_SIZE}, and
 * {@link Messages#decode} only with {@code MALFORMED}, {@code UNKNOWN_TYPE}, {@code BAD_FIELD} or
 * {@code VERSION}. Any other exception fails the run.
 *
 * <p>Two oracles judge every message the decoder accepts. The body must be exactly what the encoder
 * writes for it, so no second spelling gets past. Every field must also be within the limits of
 * {@code docs/schemas/lan-share.cddl}, which are written out again in {@link Cddl} rather than
 * taken from the codec's constants, so a bound the codec forgets is a finding even though the
 * message round-trips.
 *
 * <p>libFuzzer inputs are at most 4096 bytes, so a frame header between 1 MiB and 4 GiB only ever
 * meets a short stream here. {@link #anOversizedHeaderIsRefusedBeforeAnyBodyByteIsRead} covers that
 * bound with an endless stream instead.
 *
 * <p>Without {@code JAZZER_FUZZ=1} the harness replays the seed corpus in
 * {@code LanCodecFuzzTestInputs} (one frame of each message type, plus a duplicate-key map) as a
 * regression test.
 */
@Tag("T-FUZZ-LAN")
class LanCodecFuzzTest {
    private static final int BSTR_MAJOR = 0x40;
    private static final int BSTR_INLINE_MAX = 24;
    /** Byte strings of fixed size in the seed messages: 4 pairing values, 6 ids. */
    private static final int FIXED_SIZE_FIELDS = 10;
    private static final Set<Code> FRAME_CODES = EnumSet.of(Code.CLOSED, Code.TRUNCATED, Code.FRAME_SIZE);
    private static final Set<Code> DECODE_CODES =
            EnumSet.of(Code.MALFORMED, Code.UNKNOWN_TYPE, Code.BAD_FIELD, Code.VERSION);

    /** The limits of docs/schemas/lan-share.cddl, restated for the oracle. */
    static final class Cddl {
        /** {@code u32 big-endian length (1 .. 1 MiB)}. */
        static final long MAX_FRAME = 1_048_576;
        /** {@code device_id = bstr .size 16}. */
        static final int DEVICE_ID = 16;
        /** {@code share_id = bstr .size 16}. */
        static final int SHARE_ID = 16;
        /** {@code pairing_value = bstr .size 32}. */
        static final int PAIRING_VALUE = 32;
        /** {@code label32}: 1..32 UTF-16 units. */
        static final int LABEL32 = 32;
        /** {@code label512}: 1..512 UTF-16 units. */
        static final int LABEL512 = 512;
        /** {@code caps: [* cap] ; caps ≤ 16}. */
        static final int MAX_CAPS = 16;
        /** {@code cap = tstr .regexp "[a-z0-9_-]{1,32}"}. */
        static final Pattern CAP = Pattern.compile("[a-z0-9_-]{1,32}");
        /** {@code payload: bstr .size (1..1048320)}. */
        static final int MAX_PAYLOAD = 1_048_320;
        /** {@code code: 0..65535}. */
        static final long MAX_CODE = 65_535;

        private Cddl() {
        }
    }

    @FuzzTest
    void fuzz(byte[] in) throws IOException {
        InputStream stream = new ByteArrayInputStream(in);
        int frames = 0;
        while (true) {
            byte[] body;
            try {
                body = Frames.read(stream);
            } catch (WireException e) {
                assertTrue(FRAME_CODES.contains(e.code()), e.code().name());
                break;
            }
            assertTrue(body.length >= 1 && body.length <= Cddl.MAX_FRAME, "frame length");
            decodeStrictly(body);
            frames++;
        }
        assertTrue(frames * Integer.BYTES <= in.length, "more frames than headers");
        decodeStrictly(in);
    }

    /** Decodes {@code body}; returns the message, or null if it was refused with a decoder code. */
    static Message decodeStrictly(byte[] body) {
        Message m;
        try {
            m = Messages.decode(body);
        } catch (WireException e) {
            assertTrue(DECODE_CODES.contains(e.code()), e.code().name());
            return null;
        }
        withinSchema(m);
        assertArrayEquals(body, Messages.encode(m), "accepted a second spelling of " + m.getClass().getSimpleName());
        return m;
    }

    /** Fails unless every field of {@code m} is within the CDDL limits. */
    static void withinSchema(Message m) {
        String type = m.getClass().getSimpleName();
        assertTrue(m.seq() >= 0, type + ": seq");
        switch (m) {
            case Message.Hello h -> {
                size(h.deviceId(), Cddl.DEVICE_ID, type + ".device_id");
                label(h.name(), Cddl.LABEL32, type + ".name");
                assertTrue(h.caps().size() <= Cddl.MAX_CAPS, type + ".caps count");
                h.caps().forEach(c -> assertTrue(Cddl.CAP.matcher(c).matches(), type + ".caps token"));
            }
            case Message.PairCommit c -> size(c.commit(), Cddl.PAIRING_VALUE, type + ".commit");
            case Message.PairNonce n -> size(n.nonce(), Cddl.PAIRING_VALUE, type + ".nonce");
            case Message.PairReveal r -> size(r.nonce(), Cddl.PAIRING_VALUE, type + ".nonce");
            case Message.PairSasOk s -> size(s.mac(), Cddl.PAIRING_VALUE, type + ".mac");
            case Message.ShareOffer o -> {
                size(o.shareId(), Cddl.SHARE_ID, type + ".share_id");
                label(o.summary(), Cddl.LABEL512, type + ".summary");
                assertTrue(o.expires() >= 1, type + ".expires");
            }
            case Message.ShareAccept a -> size(a.shareId(), Cddl.SHARE_ID, type + ".share_id");
            case Message.ShareData d -> {
                size(d.shareId(), Cddl.SHARE_ID, type + ".share_id");
                int n = d.payload().length();
                assertTrue(n >= 1 && n <= Cddl.MAX_PAYLOAD, type + ".payload size " + n);
            }
            case Message.ShareAck a -> size(a.shareId(), Cddl.SHARE_ID, type + ".share_id");
            case Message.Revoke r -> size(r.deviceId(), Cddl.DEVICE_ID, type + ".device_id");
            case Message.ErrorReport e -> assertTrue(e.code() >= 0 && e.code() <= Cddl.MAX_CODE, type + ".code");
            case Message.PairReq r -> assertTrue(r.seq() >= 0, type);
            case Message.PairDone d -> assertTrue(d.seq() >= 0, type);
            case Message.Bye b -> assertTrue(b.seq() >= 0, type);
        }
    }

    private static void size(Octets value, int exact, String field) {
        assertEquals(exact, value.length(), field + " size");
    }

    /** 1..max UTF-16 units, no Unicode control (Cc) or format (Cf) characters. */
    private static void label(String value, int max, String field) {
        assertTrue(!value.isEmpty() && value.length() <= max, field + " length " + value.length());
        assertTrue(value.codePoints().noneMatch(cp -> Character.getType(cp) == Character.CONTROL
                || Character.getType(cp) == Character.FORMAT), field + " has a control or format character");
    }

    /** One message of each type, as the seeds hold them. */
    static Map<String, Message> everyType() {
        Octets id16 = Octets.copyOf(new byte[Message.SHARE_ID_BYTES]);
        Octets v32 = Octets.copyOf(new byte[Message.PAIRING_VALUE_BYTES]);
        return Map.ofEntries(
                Map.entry("hello.frame", new Message.Hello(0, id16, "laptop", List.of("pair", "share"))),
                Map.entry("pair-req.frame", new Message.PairReq(1)),
                Map.entry("pair-commit.frame", new Message.PairCommit(2, v32)),
                Map.entry("pair-nonce.frame", new Message.PairNonce(1, v32)),
                Map.entry("pair-reveal.frame", new Message.PairReveal(3, v32)),
                Map.entry("pair-sas-ok.frame", new Message.PairSasOk(4, v32)),
                Map.entry("pair-done.frame", new Message.PairDone(5)),
                Map.entry("share-offer.frame", new Message.ShareOffer(1, id16, Message.Kind.PROJECT,
                        "api: 2 profiles", 1_790_000_000L, true)),
                Map.entry("share-accept.frame", new Message.ShareAccept(1, id16)),
                Map.entry("share-data.frame", new Message.ShareData(2, id16, Octets.copyOf(new byte[] {1, 2, 3}))),
                Map.entry("share-ack.frame", new Message.ShareAck(2, id16, true)),
                Map.entry("revoke.frame", new Message.Revoke(3, id16)),
                Map.entry("error.frame", new Message.ErrorReport(3, 7)),
                Map.entry("bye.frame", new Message.Bye(4)));
    }

    /** {@code m} as one frame. */
    static byte[] frame(Message m) throws IOException {
        return frame(Messages.encode(m));
    }

    private static byte[] frame(byte[] body) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Frames.write(out, body);
        return out.toByteArray();
    }

    /**
     * PAIR_REQ with {@code seq} twice: {@code {"t": "pair_req", "seq": 1, "seq": 1}}. Keys are in
     * deterministic order and each one is canonical, so only duplicate detection refuses it.
     */
    static byte[] duplicateKeyBody() {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(0xA3);
        b.writeBytes(new byte[] {0x61, 't', 0x68, 'p', 'a', 'i', 'r', '_', 'r', 'e', 'q'});
        b.writeBytes(new byte[] {0x63, 's', 'e', 'q', 0x01});
        b.writeBytes(new byte[] {0x63, 's', 'e', 'q', 0x01});
        return b.toByteArray();
    }

    /** Each seed is one frame of the message type its name says, and the harness accepts it. */
    @Test
    void seedCorpusIsOneFrameOfEachType() throws IOException, WireException {
        for (Map.Entry<String, Message> seed : everyType().entrySet()) {
            byte[] file = Seeds.read(LanCodecFuzzTest.class, seed.getKey());
            assertArrayEquals(frame(seed.getValue()), file, seed.getKey());
            Message decoded = Messages.decode(Frames.read(new ByteArrayInputStream(file)));
            assertInstanceOf(seed.getValue().getClass(), decoded, seed.getKey());
            fuzz(file);
        }
    }

    /** The duplicate-key seed is that frame, and the decoder refuses it with a documented code. */
    @Test
    void aMapWithADuplicateKeyIsRefused() throws IOException, WireException {
        byte[] file = Seeds.read(LanCodecFuzzTest.class, "pair-req-duplicate-seq.frame");
        assertArrayEquals(frame(duplicateKeyBody()), file);
        assertNull(decodeStrictly(Frames.read(new ByteArrayInputStream(file))));
        fuzz(file);
    }

    /**
     * {@code m}'s body with its all-zero byte string of {@code from} bytes re-spelled as {@code to}
     * zero bytes (header adjusted, still canonical), or empty if {@code m} has no such field.
     */
    static byte[] resized(Message m, int from, int to) {
        byte[] body = Messages.encode(m);
        byte[] old = bstr(from);
        for (int i = 0; i + old.length <= body.length; i++) {
            if (Arrays.equals(body, i, i + old.length, old, 0, old.length)) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                out.write(body, 0, i);
                out.writeBytes(bstr(to));
                out.write(body, i + old.length, body.length - i - old.length);
                return out.toByteArray();
            }
        }
        return new byte[0];
    }

    /** A canonical CBOR byte string of {@code n} zero bytes, {@code n} below 256. */
    private static byte[] bstr(int n) {
        if (n < BSTR_INLINE_MAX) {
            byte[] b = new byte[1 + n];
            b[0] = (byte) (BSTR_MAJOR | n);
            return b;
        }
        byte[] b = new byte[2 + n];
        b[0] = (byte) (BSTR_MAJOR | BSTR_INLINE_MAX);
        b[1] = (byte) n;
        return b;
    }

    /**
     * Every fixed-size byte string one byte short or one byte long is refused. These are the bodies
     * a missing field-length check lets through, so with {@code Checks.length} disabled the schema
     * oracle fails on each one. Two are committed as seeds so the gate's replay catches it as well.
     */
    @Test
    void everyFixedSizeFieldOneByteOffIsRefused() throws IOException {
        int variants = 0;
        for (Message m : everyType().values()) {
            for (int size : new int[] {Cddl.SHARE_ID, Cddl.PAIRING_VALUE}) {
                for (int to : new int[] {size - 1, size + 1}) {
                    byte[] body = resized(m, size, to);
                    if (body.length > 0) {
                        assertNull(decodeStrictly(body), m.getClass().getSimpleName() + " " + size + " -> " + to);
                        fuzz(frame(body));
                        variants++;
                    }
                }
            }
        }
        assertEquals(FIXED_SIZE_FIELDS * 2, variants, "fixed-size fields across the seed messages");
        assertArrayEquals(frame(resized(everyType().get("pair-commit.frame"), Cddl.PAIRING_VALUE,
                Cddl.PAIRING_VALUE - 1)), Seeds.read(LanCodecFuzzTest.class, "pair-commit-31-byte-commit.frame"));
        assertArrayEquals(frame(resized(everyType().get("hello.frame"), Cddl.DEVICE_ID,
                Cddl.DEVICE_ID + 1)), Seeds.read(LanCodecFuzzTest.class, "hello-17-byte-device-id.frame"));
    }

    /** The round-trip oracle is not vacuous: a valid body round-trips and a non-canonical one is refused. */
    @Test
    void decodeStrictlyAcceptsOnlyTheEncoderSpelling() {
        Message bye = new Message.Bye(0);
        assertEquals(bye, decodeStrictly(Messages.encode(bye)));
        byte[] body = Messages.encode(bye);
        byte[] longForm = new byte[body.length + 1];
        // Re-spell the map header with a one-byte length argument (0xB8 n), which deterministic CBOR forbids.
        longForm[0] = (byte) 0xB8;
        longForm[1] = (byte) (body[0] & 0x1F);
        System.arraycopy(body, 1, longForm, 2, body.length - 1);
        assertNull(decodeStrictly(longForm));
    }

    /** The schema oracle accepts every seed message, so its passing branches run in the gate. */
    @Test
    void everySeedMessageIsWithinTheSchema() {
        everyType().values().forEach(LanCodecFuzzTest::withinSchema);
    }

    /**
     * Frame headers above 1 MiB, up to the largest u32, are refused as {@code FRAME_SIZE} before a
     * single body byte is read. The stream behind the header never ends, so a missing or loosened
     * bound shows up as a body being read (and returned), not as {@code TRUNCATED}.
     */
    @Test
    void anOversizedHeaderIsRefusedBeforeAnyBodyByteIsRead() throws IOException {
        for (long length : oversizedLengths()) {
            try (Endless in = new Endless(length)) {
                WireException e = assertThrows(WireException.class, () -> Frames.read(in), "length " + length);
                assertEquals(Code.FRAME_SIZE, e.code(), "length " + length);
                assertEquals(0, in.bodyBytesRead(), "body bytes read for length " + length);
            }
        }
        try (Endless zero = new Endless(0)) {
            assertEquals(Code.FRAME_SIZE, assertThrows(WireException.class, () -> Frames.read(zero)).code());
        }
    }

    /** The endless stream is not vacuous: at and below the bound the body is read in full. */
    @Test
    void headersUpToTheBoundReadExactlyTheirBody() throws IOException, WireException {
        for (long length : List.of(1L, 4096L, Cddl.MAX_FRAME)) {
            try (Endless in = new Endless(length)) {
                assertEquals(length, Frames.read(in).length);
                assertEquals(length, in.bodyBytesRead());
            }
        }
    }

    /** The edges above the bound, then 4096 lengths spread evenly up to 2^32 - 1. */
    static List<Long> oversizedLengths() {
        List<Long> lengths = new ArrayList<>(List.of(Cddl.MAX_FRAME + 1, 2 * Cddl.MAX_FRAME,
                16 * Cddl.MAX_FRAME, 16 * Cddl.MAX_FRAME + 1, (long) Integer.MAX_VALUE, 1L << 31, 0xFFFF_FFFFL));
        long steps = 4096;
        long step = (0xFFFF_FFFFL - Cddl.MAX_FRAME) / steps;
        for (long k = 1; k <= steps; k++) {
            lengths.add(Cddl.MAX_FRAME + k * step);
        }
        return lengths;
    }

    /** A frame header for {@code length}, then zero bytes for ever; counts body bytes handed out. */
    private static final class Endless extends InputStream {
        private final byte[] header;
        private int headerRead;
        private long bodyRead;

        Endless(long length) {
            this.header = ByteBuffer.allocate(Integer.BYTES).putInt((int) length).array();
        }

        long bodyBytesRead() {
            return bodyRead;
        }

        @Override
        public int read() {
            if (headerRead < header.length) {
                return header[headerRead++] & 0xFF;
            }
            bodyRead++;
            return 0;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            int n = 0;
            while (n < len && headerRead < header.length) {
                b[off + n++] = header[headerRead++];
            }
            for (int i = n; i < len; i++) {
                b[off + i] = 0;
            }
            bodyRead += len - n;
            return len;
        }
    }
}
