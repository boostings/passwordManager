package pm.crypto.ssh;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.crypto.ConstantTime;
import pm.crypto.SecretBytes;
import pm.fuzz.Allocation;
import pm.fuzz.Seeds;
import pm.fuzz.Stretch;

/**
 * Fuzz harness for the strict {@code openssh-key-v1} parser (plan.md §13 M4, SR-062, T-FUZZ-SSH).
 * It lives in {@code pm.crypto.ssh} so it can reach the package-private encoder for the round trip;
 * nothing outside the test class path sees it.
 *
 * <p>Three input modes, so the fuzzer reaches both the armour and the binary layers:
 * <ul>
 *   <li><b>armour edits</b> ({@code 'A'} first): a valid seed key, chosen by byte 1, is armoured with
 *       the line length byte 2 picks (0 for one line), then each following 4-byte group
 *       {@code u16 position, u8 op, u8 value} edits the text: insert, delete, replace, a line break
 *       ({@code LF}, {@code CRLF}, {@code CR}, blank line), a trailer byte, a prefix byte, a base64
 *       character (padding included) or a short deletion. A position with its top bit set counts
 *       from the end, so edits reach the padding, the END line and what follows it;</li>
 *   <li><b>binary</b> (starts with the magic {@code openssh-key-v1\0}, after an optional
 *       {@link Stretch}): armoured here, so mutations reach the binary layout and the 4 KiB comment
 *       and 64 KiB file limits;</li>
 *   <li><b>text</b> (anything else): passed to the parser as it is.</li>
 * </ul>
 * Oracles, each independent of the parser:
 * <ul>
 *   <li>an exact expected outcome, computed here before the parse: a file over 64 KiB, or text
 *       {@link #strictDearmour the armour grammar} rejects, is {@code MALFORMED_KEY}; otherwise
 *       {@link #expect the header model} reads magic, cipher, kdf, kdf options, key count, the two
 *       outer strings, block size, check integers and key type and names the one code the parser
 *       must raise ({@code MALFORMED_KEY}, {@code ENCRYPTED_KEY} or {@code UNSUPPORTED_KEY}); past
 *       the header, the parser may only accept or raise {@code MALFORMED_KEY}, and a binary equal to
 *       a valid seed key must be accepted. The parser accepting anything the grammar or the model
 *       rejects is a failure;</li>
 *   <li>limits from ADR 0013 and the key formats, written in this class rather than read from the
 *       parser: an accepted file is at most 64 KiB, its comment at most 4 KiB of UTF-8, its type
 *       name at most 64 bytes, and its public key blob exactly the size its type fixes (51 bytes
 *       for Ed25519, 104 for P-256);</li>
 *   <li>the exception message is the code name alone, and the caller's buffer is unchanged;</li>
 *   <li>bounded allocation: at most {@link #ALLOCATION_BOUND} plus {@link #PER_INPUT_BYTE} per input byte per call;</li>
 *   <li>parse, encode, decode round trip against the binary the grammar decoded: an accepted file
 *       re-encodes to the same binary except the two (random) check integers, and the re-encoded
 *       file parses to the same type, comment and public key.</li>
 * </ul>
 * Seeds are the published RFC 8032 §7.1 TEST 1 Ed25519 key and RFC 6979 A.2.5 P-256 key, in
 * binary form so no armoured private key is committed (gitleaks, ADR 0013).
 */
@Tag("T-FUZZ-SSH")
class OpenSshKeyFuzzTest {
    /**
     * Per-call allocation ceiling. Once warm, parsing a seed key allocates about 80 KiB (the probe
     * signature and the JCA key objects; measured 2026-10-04) and the file is capped at 64 KiB; a
     * buffer sized from an unchecked {@code uint32} would allocate up to 4 GiB. In fuzzing mode the
     * instrumentation itself allocates per byte scanned (a 32 KiB stretched file measured 4.6 MiB
     * there but passed the 4 MiB bound uninstrumented, 2026-10-04), so the ceiling also grows with the input:
     * {@link #PER_INPUT_BYTE} per byte, at most 36 MiB for a 64 KiB file, which still rules out a
     * hostile-length buffer and quadratic work.
     */
    static final long ALLOCATION_BOUND = 4L << 20;
    static final long PER_INPUT_BYTE = 512;
    private static final int CHECK_BYTES = 8;
    // ADR 0013 limits, PROTOCOL.key fields and RFC 8709 / RFC 5656 blob sizes, written here
    // independently of the parser's constants (an oracle must not borrow the limits it checks from
    // the code under test).
    static final int MAX_FILE = 64 * 1024;
    static final int MAX_COMMENT = 4096;
    static final int MAX_NAME = 64;
    static final int MAX_BLOB = 16 * 1024;
    /** The parser's documented bound on the kdf options string; any non-empty one is refused anyway. */
    static final int MAX_KDF_OPTIONS = 1024;
    static final int BLOCK = 8;
    /** string "ssh-ed25519", string 32-byte key. */
    static final int ED25519_BLOB = 4 + 11 + 4 + 32;
    /** string "ecdsa-sha2-nistp256", string "nistp256", string 65-byte uncompressed point. */
    static final int P256_BLOB = 4 + 19 + 4 + 8 + 4 + 65;
    private static final byte[] KEY_MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] NONE = "none".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] ED25519_NAME = "ssh-ed25519".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] P256_NAME = "ecdsa-sha2-nistp256".getBytes(StandardCharsets.US_ASCII);
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    /** The byte that marks an armour-edit input. */
    static final byte ARMOUR_MARK = 'A';
    private static final int EDIT = 4;
    private static final int FROM_END = 0x8000;
    private static final byte[][] BREAKS = {{'\n'}, {'\r', '\n'}, {'\r'}, {'\n', '\n'}};
    /** The RFC 8032 §7.1 TEST 1 seed file (a published test vector, not a credential). */
    private static final String ED25519_SEED = "ed25519-rfc8032.bin";
    /** Valid keys the armour mode starts from; byte 1 of an armour-edit input picks one. */
    private static final String[] VALID_SEEDS = {ED25519_SEED, "ecdsa-p256-rfc6979.bin", "ed25519-no-padding.bin"};
    private static final byte[][] VALID = new byte[VALID_SEEDS.length][];

    static {
        try {
            for (int i = 0; i < VALID_SEEDS.length; i++) {
                VALID[i] = Seeds.read(OpenSshKeyFuzzTest.class, VALID_SEEDS[i]);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * What the parser must do with one input, worked out before it runs: refuse with {@code code},
     * or (code null) accept or refuse with {@code MALFORMED_KEY}, and accept when {@code mustAccept}.
     */
    static final class Expect {
        private final SshException.Code refusal;
        private final boolean accept;
        private final byte[] decoded;
        private final String reason;

        Expect(SshException.Code code, boolean mustAccept, byte[] binary, String why) {
            this.refusal = code;
            this.accept = mustAccept;
            this.decoded = binary.clone();
            this.reason = why;
        }

        static Expect refuse(SshException.Code code, String why) {
            return new Expect(code, false, new byte[0], why);
        }

        SshException.Code code() {
            return refusal;
        }

        boolean mustAccept() {
            return accept;
        }

        /** The binary the grammar decoded when the header allowed it; empty for a refusal. */
        byte[] binary() {
            return decoded.clone();
        }

        String why() {
            return reason;
        }
    }

    /**
     * Initialises the JCA providers and every class on the path before anything is measured. It
     * asserts nothing and reads no seed a planted-bug run may withhold, so any finding comes from
     * the fuzzed inputs: both key types, encoded again; a short armour; an encrypted header; an
     * unknown key type; and the armour-edit path (as it is, a line break after END, a CR edit).
     */
    @BeforeAll
    static void warmUp() {
        byte[] good = ed25519File(1);
        for (byte[] in : new byte[][] {good, VALID[1], variant(good, KEY_MAGIC.length + 4, "aes2"),
            variant(good, checkOffset(good) + CHECK_BYTES + 4, "x"), {ARMOUR_MARK, 1, 64},
            {ARMOUR_MARK, 0, 70, 0, 0, 4, '\n'}, {ARMOUR_MARK, 2, 0, 0, 0, 3, 2}, "-".getBytes(StandardCharsets.US_ASCII)}) {
            byte[] text = text(in);
            expect(text);
            load(text);
        }
    }

    /** Parses {@code text} and re-encodes it if accepted, asserting nothing; whether it was accepted. */
    private static boolean load(byte[] text) {
        try (SecretBytes file = SecretBytes.copyOf(text); SshKey key = SshKey.parse(file);
                SecretBytes again = OpenSshFormat.encode(key)) {
            return strictDearmour(again.apply(byte[]::clone)).isPresent();
        } catch (SshException refusal) {
            return false;
        }
    }

    @FuzzTest
    void fuzz(byte[] in) {
        check(in, ALLOCATION_BOUND);
    }

    private static void check(byte[] in, long allocationBound) {
        byte[] text = text(in);
        Expect expected = expect(text);
        byte[] before = text.clone();
        long start = Allocation.current();
        try (SecretBytes file = SecretBytes.copyOf(text); SshKey parsed = parse(file, expected)) {
            long used = Allocation.current() - start;
            assertTrue(allocationBound == Long.MAX_VALUE || used < allocationBound + PER_INPUT_BYTE * text.length,
                    () -> "allocation bound: " + used + " bytes for " + text.length);
            assertArrayEquals(before, file.apply(byte[]::clone), "caller's buffer modified");
            if (parsed != null) {
                assertTrue(text.length <= MAX_FILE, "accepted a file over 64 KiB");
                roundTrip(parsed, expected.binary());
            }
        }
    }

    /** The parse, checked against {@code expected}; null when (correctly) refused. */
    private static SshKey parse(SecretBytes file, Expect expected) {
        SshKey key;
        try {
            key = SshKey.parse(file);
        } catch (SshException e) {
            assertEquals(e.code().name(), e.getMessage(), "message carries data");
            if (expected.code() == null) {
                assertFalse(expected.mustAccept(), "refused a valid key: " + e.code());
                assertEquals(SshException.Code.MALFORMED_KEY, e.code(), "past the header only MALFORMED_KEY");
            } else {
                assertEquals(expected.code(), e.code(), expected.why());
            }
            return null;
        }
        if (expected.code() != null) {
            key.close();
            throw new AssertionError("accepted, expected " + expected.code() + ": " + expected.why());
        }
        return key;
    }

    /** The text an input describes (see the class comment for the three modes). */
    static byte[] text(byte[] in) {
        if (in.length >= 3 && in[0] == ARMOUR_MARK) {
            return edited(in);
        }
        byte[] raw = Stretch.apply(in, MAX_FILE + 1);
        return startsWithMagic(raw) ? armour(raw) : raw;
    }

    /** Armour-edit mode: a valid key's armour with the input's edits applied in order. */
    private static byte[] edited(byte[] in) {
        byte[] t = armour(VALID[(in[1] & 0xff) % VALID.length], in[2] & 0xff);
        for (int i = 3; i + EDIT <= in.length; i += EDIT) {
            int p = (in[i] & 0xff) << 8 | (in[i + 1] & 0xff);
            int at = (p & FROM_END) != 0 ? t.length - (p & ~FROM_END) : p;
            at = Math.max(0, Math.min(t.length, at));
            byte v = in[i + 3];
            switch (in[i + 2] & 7) {
                case 0 -> t = splice(t, at, 0, new byte[] {v});
                case 1 -> t = splice(t, at, 1, new byte[0]);
                case 2 -> t = splice(t, at, 1, new byte[] {v});
                case 3 -> t = splice(t, at, 0, BREAKS[v & 3]);
                case 4 -> t = splice(t, t.length, 0, new byte[] {v});
                case 5 -> t = splice(t, 0, 0, new byte[] {v});
                case 6 -> t = splice(t, at, 1, new byte[] {(byte) (ALPHABET + "=").charAt((v & 0xff) % 65)});
                default -> t = splice(t, at, 1 + (v & 7), new byte[0]);
            }
        }
        return t;
    }

    /** {@code t} with up to {@code remove} bytes at {@code at} replaced by {@code insert}. */
    private static byte[] splice(byte[] t, int at, int remove, byte[] insert) {
        int cut = Math.min(remove, t.length - at);
        byte[] out = new byte[t.length - cut + insert.length];
        System.arraycopy(t, 0, out, 0, at);
        System.arraycopy(insert, 0, out, at, insert.length);
        System.arraycopy(t, at + cut, out, at + insert.length, t.length - at - cut);
        return out;
    }

    /**
     * The outcome the parser must produce for {@code text}: the 64 KiB file limit, then the armour
     * grammar, then {@link #header}.
     */
    static Expect expect(byte[] text) {
        if (text.length > MAX_FILE) {
            return Expect.refuse(SshException.Code.MALFORMED_KEY, "file over 64 KiB");
        }
        Optional<byte[]> bin = strictDearmour(text);
        if (bin.isEmpty()) {
            return Expect.refuse(SshException.Code.MALFORMED_KEY, "armour grammar");
        }
        return header(bin.get());
    }

    /**
     * The armour grammar of ADR 0013 (pm's own: it differs from OpenSSH's in four places the ADR
     * lists), read independently of the parser: the BEGIN line opens the file and ends in a line break; the END line starts a line and
     * is followed only by line breaks; a line break is CR, LF or both; the body is base64 in lines of
     * any length, strict: alphabet only, a multiple of 4 characters, {@code =} only as the final
     * padding, and the unused bits before the padding zero (one encoding per binary). Returns the
     * binary, or empty when the text is not in the grammar.
     */
    static Optional<byte[]> strictDearmour(byte[] text) {
        String s = new String(text, StandardCharsets.ISO_8859_1);
        String begin = OpenSshFormat.BEGIN;
        String end = OpenSshFormat.END;
        if (!s.startsWith(begin) || s.length() == begin.length() || !lineBreak(s.charAt(begin.length()))) {
            return Optional.empty();
        }
        int endAt = s.indexOf(end, begin.length());
        if (endAt < 0 || !lineBreak(s.charAt(endAt - 1))) {
            return Optional.empty();
        }
        for (int i = endAt + end.length(); i < s.length(); i++) {
            if (!lineBreak(s.charAt(i))) {
                return Optional.empty();
            }
        }
        StringBuilder q = new StringBuilder();
        for (int i = begin.length(); i < endAt; i++) {
            char c = s.charAt(i);
            if (c == '=' || ALPHABET.indexOf(c) >= 0) {
                q.append(c);
            } else if (!lineBreak(c)) {
                return Optional.empty();
            }
        }
        int n = q.length();
        int pad = n >= 2 && q.charAt(n - 1) == '=' ? (q.charAt(n - 2) == '=' ? 2 : 1) : 0;
        int firstPad = q.indexOf("=");
        if (n % 4 != 0 || (firstPad >= 0 && firstPad < n - pad)) {
            return Optional.empty();
        }
        int unusedBits = pad == 2 ? 0xf : 0x3;
        if (pad > 0 && (ALPHABET.indexOf(q.charAt(n - pad - 1)) & unusedBits) != 0) {
            return Optional.empty();
        }
        // Validated above, so this decoding is the only one the text has.
        return Optional.of(Base64.getDecoder().decode(q.toString()));
    }

    private static boolean lineBreak(char c) {
        return c == '\n' || c == '\r';
    }

    /**
     * The code the header fields name, in the order {@code PROTOCOL.key} lays them out and ADR 0013
     * decides on them: the three leading strings are read (bounded) before the cipher is judged, so
     * a non-{@code none} cipher is {@code ENCRYPTED_KEY} only when they are well formed; then kdf,
     * kdf options, one key, the public and private strings filling the file exactly, the private
     * section a whole number of 8-byte blocks with equal check integers, and the key type. Past
     * that, the outcome is accept or {@code MALFORMED_KEY}, and accept for a known valid key.
     */
    static Expect header(byte[] bin) {
        SshException.Code malformed = SshException.Code.MALFORMED_KEY;
        if (bin.length < KEY_MAGIC.length || !Arrays.equals(bin, 0, KEY_MAGIC.length, KEY_MAGIC, 0, KEY_MAGIC.length)) {
            return Expect.refuse(malformed, "magic");
        }
        ByteBuffer b = ByteBuffer.wrap(bin, KEY_MAGIC.length, bin.length - KEY_MAGIC.length);
        Optional<byte[]> cipher = string(b, MAX_NAME);
        Optional<byte[]> kdf = cipher.flatMap(c -> string(b, MAX_NAME));
        Optional<byte[]> kdfOptions = kdf.flatMap(k -> string(b, MAX_KDF_OPTIONS));
        if (kdfOptions.isEmpty()) {
            return Expect.refuse(malformed, "cipher, kdf or kdf options string");
        }
        if (!ConstantTime.equals(cipher.get(), NONE)) {
            return Expect.refuse(SshException.Code.ENCRYPTED_KEY,
                    "cipher " + new String(cipher.get(), StandardCharsets.ISO_8859_1));
        }
        if (!ConstantTime.equals(kdf.get(), NONE) || kdfOptions.get().length != 0 || b.remaining() < Integer.BYTES
                || b.getInt() != 1) {
            return Expect.refuse(malformed, "kdf, kdf options or key count");
        }
        Optional<byte[]> priv = string(b, MAX_BLOB).flatMap(publicBlob -> string(b, MAX_FILE));
        if (priv.isEmpty() || b.hasRemaining() || priv.get().length % BLOCK != 0) {
            return Expect.refuse(malformed, "outer strings, trailing bytes or block size");
        }
        ByteBuffer p = ByteBuffer.wrap(priv.get());
        if (p.remaining() < CHECK_BYTES) {
            return Expect.refuse(malformed, "check integers");
        }
        int check1 = p.getInt();
        int check2 = p.getInt();
        Optional<byte[]> type = check1 == check2 ? string(p, MAX_NAME) : Optional.empty();
        if (type.isEmpty()) {
            return Expect.refuse(malformed, "check integers or key type string");
        }
        if (!ConstantTime.equals(type.get(), ED25519_NAME) && !ConstantTime.equals(type.get(), P256_NAME)) {
            return Expect.refuse(SshException.Code.UNSUPPORTED_KEY, "key type");
        }
        boolean valid = false;
        for (byte[] v : VALID) {
            valid |= ConstantTime.equals(v, bin);
        }
        return new Expect(null, valid, bin, "key body");
    }

    /** An SSH {@code string} of at most {@code max} bytes, or empty if it does not fit. */
    private static Optional<byte[]> string(ByteBuffer b, int max) {
        if (b.remaining() < Integer.BYTES) {
            return Optional.empty();
        }
        long len = Integer.toUnsignedLong(b.getInt());
        if (len > max || len > b.remaining()) {
            return Optional.empty();
        }
        byte[] out = new byte[(int) len];
        b.get(out);
        return Optional.of(out);
    }

    private static void roundTrip(SshKey parsed, byte[] original) {
        assertTrue(parsed.comment().codePoints().noneMatch(OpenSshKeyFuzzTest::unsafe), "unsafe comment");
        byte[] blob = parsed.publicKeyBlob();
        byte[] name = parsed.type().wireName().getBytes(StandardCharsets.US_ASCII);
        assertTrue(parsed.comment().getBytes(StandardCharsets.UTF_8).length <= MAX_COMMENT, "comment over 4 KiB");
        assertTrue(name.length <= MAX_NAME, "type name over 64 bytes");
        assertEquals(parsed.type() == SshKeyType.ED25519 ? ED25519_BLOB : P256_BLOB, blob.length,
                "public key blob is not the size its type fixes");
        assertEquals(name.length, ByteBuffer.wrap(blob).getInt(), "blob starts with the type");
        assertArrayEquals(name, Arrays.copyOfRange(blob, 4, 4 + name.length), "blob starts with the type");
        try (SecretBytes again = OpenSshFormat.encode(parsed)) {
            byte[] reencoded = strictDearmour(again.apply(byte[]::clone))
                    .orElseThrow(() -> new AssertionError("the encoder's armour is outside the grammar"));
            int checks = checkOffset(original);
            assertEquals(original.length, reencoded.length, "re-encoded length");
            assertArrayEquals(Arrays.copyOfRange(original, checks, checks + 4),
                    Arrays.copyOfRange(original, checks + 4, checks + CHECK_BYTES), "check integers differ");
            for (int i = 0; i < original.length; i++) {
                if (i < checks || i >= checks + CHECK_BYTES) {
                    assertEquals(original[i], reencoded[i], "round trip differs at byte " + i);
                }
            }
            try (SshKey back = SshKey.parse(again)) {
                assertEquals(parsed.type(), back.type());
                assertEquals(parsed.comment(), back.comment());
                assertArrayEquals(blob, back.publicKeyBlob());
            }
        } catch (SshException e) {
            throw new AssertionError("re-encoded key does not parse: " + e.code(), e);
        }
    }

    /** Offset of the first check integer: magic, cipher, kdf, kdf options, nkeys, public key, length. */
    private static int checkOffset(byte[] bin) {
        ByteBuffer b = ByteBuffer.wrap(bin);
        b.position(KEY_MAGIC.length);
        for (int i = 0; i < 3; i++) {
            b.position(b.position() + 4 + b.getInt(b.position()));
        }
        b.position(b.position() + 4);
        b.position(b.position() + 4 + b.getInt(b.position()));
        return b.position() + 4;
    }

    private static boolean unsafe(int c) {
        int t = Character.getType(c);
        return c < 0x20 || (c >= 0x7f && c <= 0x9f) || t == Character.FORMAT
                || c == 0x2028 || c == 0x2029;
    }

    private static boolean startsWithMagic(byte[] in) {
        return in.length >= KEY_MAGIC.length && Arrays.equals(in, 0, KEY_MAGIC.length, KEY_MAGIC, 0, KEY_MAGIC.length);
    }

    /** ssh-keygen's armour: BEGIN line, base64 in 70-column lines, END line. */
    static byte[] armour(byte[] bin) {
        return armour(bin, 70);
    }

    /** BEGIN line, base64 in {@code line}-column lines (one line for 0), END line, each ending in LF. */
    static byte[] armour(byte[] bin, int line) {
        String b64 = Base64.getEncoder().encodeToString(bin);
        StringBuilder t = new StringBuilder(OpenSshFormat.BEGIN).append('\n');
        int step = line == 0 ? Math.max(1, b64.length()) : line;
        for (int i = 0; i < b64.length(); i += step) {
            t.append(b64, i, Math.min(b64.length(), i + step)).append('\n');
        }
        return t.append(OpenSshFormat.END).append('\n').toString().getBytes(StandardCharsets.US_ASCII);
    }

    /** Each seed is accepted or refused with the code its name says, by the parser and the model. */
    @Test
    void seedCorpusParsesAsLabelled() throws IOException, SshException {
        Map<String, SshKeyType> accepted = Map.of(ED25519_SEED, SshKeyType.ED25519,
                "ed25519-no-padding.bin", SshKeyType.ED25519, "ecdsa-p256-rfc6979.bin", SshKeyType.ECDSA_P256,
                "stretch-comment-4096.bin", SshKeyType.ED25519, "armour-edit-crlf.bin", SshKeyType.ECDSA_P256,
                "armour-edit-one-line.bin", SshKeyType.ED25519);
        for (Map.Entry<String, SshKeyType> seed : accepted.entrySet()) {
            byte[] text = text(Seeds.read(OpenSshKeyFuzzTest.class, seed.getKey()));
            assertNull(expect(text).code(), seed.getKey());
            try (SecretBytes file = SecretBytes.copyOf(text); SshKey k = SshKey.parse(file)) {
                assertEquals(seed.getValue(), k.type(), seed.getKey());
            }
            fuzz(Seeds.read(OpenSshKeyFuzzTest.class, seed.getKey()));
        }
        Map<String, SshException.Code> rejected = Map.ofEntries(
                Map.entry("encrypted-header.bin", SshException.Code.ENCRYPTED_KEY),
                Map.entry("unsupported-rsa.bin", SshException.Code.UNSUPPORTED_KEY),
                Map.entry("armour-short.txt", SshException.Code.MALFORMED_KEY),
                Map.entry("two-keys.bin", SshException.Code.MALFORMED_KEY),
                Map.entry("stretch-comment-4097.bin", SshException.Code.MALFORMED_KEY),
                Map.entry("armour-edit-trailer.bin", SshException.Code.MALFORMED_KEY),
                Map.entry("armour-edit-unpadded.bin", SshException.Code.MALFORMED_KEY),
                Map.entry("armour-edit-noncanonical.bin", SshException.Code.MALFORMED_KEY),
                Map.entry("armour-edit-end-mid-line.bin", SshException.Code.MALFORMED_KEY));
        for (Map.Entry<String, SshException.Code> seed : rejected.entrySet()) {
            byte[] in = Seeds.read(OpenSshKeyFuzzTest.class, seed.getKey());
            byte[] text = text(in);
            // The model names header codes; a body fault (the 4097-byte comment) is past it.
            SshException.Code model = expect(text).code();
            assertEquals(seed.getValue(), model == null ? SshException.Code.MALFORMED_KEY : model, seed.getKey());
            try (SecretBytes file = SecretBytes.copyOf(text)) {
                SshException e = assertThrows(SshException.class, () -> SshKey.parse(file), seed.getKey());
                assertEquals(seed.getValue(), e.code(), seed.getKey());
            }
            fuzz(in);
        }
    }

    /**
     * The grammar oracle is not vacuous: it takes the armour ssh-keygen writes and the variants
     * ADR 0013 allows (any line length, LF, CRLF or CR, blank lines, trailing line breaks) and refuses
     * each variant outside pm's grammar, two of which OpenSSH accepts (a space in the body, bytes
     * after END).
     */
    @Test
    void armourGrammarAcceptsOpenSshArmourAndRefusesLaxVariants() {
        byte[] bin = VALID[0];
        String good = new String(armour(bin, 64), StandardCharsets.US_ASCII);
        for (String ok : new String[] {good, good.replace("\n", "\r\n"), good.replace("\n", "\r"),
            good.replace("\n", "\n\n"), good + "\n\n", new String(armour(bin, 0), StandardCharsets.US_ASCII),
            new String(armour(bin, 1), StandardCharsets.US_ASCII)}) {
            assertArrayEquals(bin, strictDearmour(ok.getBytes(StandardCharsets.US_ASCII)).orElseThrow(), ok);
        }
        String b64 = Base64.getEncoder().encodeToString(bin);
        assertTrue(b64.endsWith("="), "the seed's base64 needs padding for these cases");
        String head = OpenSshFormat.BEGIN + "\n";
        String tail = "\n" + OpenSshFormat.END + "\n";
        int last = b64.indexOf('=') - 1;
        String flipped = b64.substring(0, last) + ALPHABET.charAt(ALPHABET.indexOf(b64.charAt(last)) | 1)
                + b64.substring(last + 1);
        for (String bad : new String[] {head + b64.replace("=", "") + tail, head + flipped + tail,
            head + b64 + tail + "x", head + b64 + tail + " ", head + b64 + OpenSshFormat.END + "\n",
            " " + head + b64 + tail, head.trim() + " \n" + b64 + tail, head + b64.substring(0, 8) + " "
                + b64.substring(8) + tail, head + "====" + b64 + tail, head + b64 + "AAAA" + tail,
            head + b64 + "\n" + OpenSshFormat.END + " \n", OpenSshFormat.BEGIN + OpenSshFormat.END + "\n"}) {
            assertTrue(strictDearmour(bad.getBytes(StandardCharsets.ISO_8859_1)).isEmpty(), bad);
            assertEquals(SshException.Code.MALFORMED_KEY, refused(bad.getBytes(StandardCharsets.ISO_8859_1)), bad);
        }
    }

    /**
     * The comment and file limits, at and one past each, deterministically: libFuzzer's 4096-byte
     * inputs reach them only through {@link Stretch}, so these pin the over-limit paths independently
     * of a campaign.
     */
    @Test
    void limitsHoldAtAndJustPastTheirValues() throws IOException, SshException {
        byte[] atLimit = armour(ed25519File(MAX_COMMENT));
        try (SecretBytes file = SecretBytes.copyOf(atLimit); SshKey k = SshKey.parse(file)) {
            assertEquals(MAX_COMMENT, k.comment().length());
        }
        check(ed25519File(MAX_COMMENT), ALLOCATION_BOUND);
        assertEquals(SshException.Code.MALFORMED_KEY, refused(armour(ed25519File(MAX_COMMENT + 1))));
        // A file of exactly 64 KiB (the longest key, then line breaks) is accepted; one byte more is not.
        byte[] fullFile = Arrays.copyOf(atLimit, MAX_FILE);
        Arrays.fill(fullFile, atLimit.length, fullFile.length, (byte) '\n');
        try (SecretBytes file = SecretBytes.copyOf(fullFile); SshKey k = SshKey.parse(file)) {
            assertEquals(MAX_COMMENT, k.comment().length(), "a 64 KiB file");
        }
        check(fullFile, ALLOCATION_BOUND);
        byte[] key = armour(ed25519File(1));
        byte[] padded = Arrays.copyOf(key, MAX_FILE + 1);
        Arrays.fill(padded, key.length, padded.length, (byte) '\n');
        assertEquals(SshException.Code.MALFORMED_KEY, refused(padded), "a file one byte over 64 KiB");
        check(padded, ALLOCATION_BOUND);
        byte[] stretched = Stretch.encode(KEY_MAGIC.length, MAX_FILE, (byte) 0, ed25519File(1));
        assertEquals(ed25519File(1).length + MAX_FILE, Stretch.apply(stretched, MAX_FILE + 1).length,
                "stretch inserts the zero run");
        check(stretched, ALLOCATION_BOUND);
    }

    private static SshException.Code refused(byte[] text) {
        try (SecretBytes file = SecretBytes.copyOf(text)) {
            return assertThrows(SshException.class, () -> SshKey.parse(file).close()).code();
        }
    }

    /**
     * The RFC 8032 §7.1 TEST 1 key as an unencrypted {@code openssh-key-v1} binary with a comment of
     * {@code commentLength} letters, built here from the format rather than by the encoder under
     * test.
     */
    static byte[] ed25519File(int commentLength) {
        byte[] pub = HexFormat.of().parseHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] d = HexFormat.of().parseHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] comment = new byte[commentLength];
        Arrays.fill(comment, (byte) 'c');
        ByteBuffer blob = ByteBuffer.allocate(ED25519_BLOB).putInt(ED25519_NAME.length).put(ED25519_NAME)
                .putInt(pub.length).put(pub);
        int body = 8 + 4 + ED25519_NAME.length + 4 + pub.length + 4 + d.length + pub.length + 4 + commentLength;
        int pad = (BLOCK - body % BLOCK) % BLOCK;
        ByteBuffer priv = ByteBuffer.allocate(body + pad).putInt(0x5eed5eed).putInt(0x5eed5eed)
                .putInt(ED25519_NAME.length).put(ED25519_NAME).putInt(pub.length).put(pub)
                .putInt(d.length + pub.length).put(d).put(pub).putInt(commentLength).put(comment);
        for (int i = 1; i <= pad; i++) {
            priv.put((byte) i);
        }
        return ByteBuffer.allocate(KEY_MAGIC.length + 4 + NONE.length + 4 + NONE.length + 4 + 4 + 4 + ED25519_BLOB + 4
                + priv.capacity())
                .put(KEY_MAGIC).putInt(NONE.length).put(NONE).putInt(NONE.length).put(NONE).putInt(0)
                .putInt(1).putInt(ED25519_BLOB).put(blob.array()).putInt(priv.capacity()).put(priv.array()).array();
    }

    /** {@code bin} with the ASCII {@code text} written over it at {@code at}. */
    private static byte[] variant(byte[] bin, int at, String text) {
        byte[] out = bin.clone();
        byte[] b = text.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(b, 0, out, at, b.length);
        return out;
    }

    /**
     * The header model is not vacuous: each header field changed on a valid key gives the code
     * ADR 0013 assigns, and the parser agrees.
     */
    @Test
    void headerModelNamesTheExactCode() {
        byte[] good = ed25519File(1);
        assertNull(header(good).code());
        assertTrue(header(VALID[0]).mustAccept());
        byte[] encrypted = variant(good, KEY_MAGIC.length + 4, "aes2");
        assertEquals(SshException.Code.ENCRYPTED_KEY, header(encrypted).code());
        byte[] kdf = variant(good, KEY_MAGIC.length + 4 + 4 + 4, "bcry");
        assertEquals(SshException.Code.MALFORMED_KEY, header(kdf).code());
        byte[] check = variant(good, checkOffset(good), "x");
        assertEquals(SshException.Code.MALFORMED_KEY, header(check).code());
        byte[] trailing = Arrays.copyOf(good, good.length + 1);
        assertEquals(SshException.Code.MALFORMED_KEY, header(trailing).code());
        byte[] type = variant(good, checkOffset(good) + CHECK_BYTES + 4, "x");
        assertEquals(SshException.Code.UNSUPPORTED_KEY, header(type).code());
        for (byte[] bin : new byte[][] {encrypted, kdf, check, trailing, type}) {
            assertEquals(header(bin).code(), refused(armour(bin)));
        }
    }

    /** The round-trip oracle is not vacuous: a wrong padding byte that a lax parser kept is caught. */
    @Test
    void roundTripOracleCatchesAnAcceptedNonCanonicalFile() throws IOException, SshException {
        byte[] bin = Seeds.read(OpenSshKeyFuzzTest.class, ED25519_SEED);
        byte[] text = armour(bin);
        try (SecretBytes file = SecretBytes.copyOf(text); SshKey parsed = SshKey.parse(file)) {
            byte[] tampered = bin.clone();
            tampered[tampered.length - 1] ^= 0x40; // last padding byte, as if the parser had not checked it
            assertThrows(AssertionError.class, () -> roundTrip(parsed, tampered));
            assertFalse(parsed.isClosed());
        }
    }
}
