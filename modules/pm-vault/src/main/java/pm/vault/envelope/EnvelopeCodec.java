package pm.vault.envelope;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import pm.crypto.Argon2Params;
import pm.vault.VaultException;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/**
 * Reads and writes the vault file layout of ADR 0003 (all integers big-endian):
 *
 * <pre>
 * magic(8) ‖ u16 version ‖ u32 headerLen ‖ header (deterministic CBOR) ‖ dataSalt(32) ‖ ciphertext
 * </pre>
 *
 * <p>{@link #decode} is a structural parser only. It bounds every length before it
 * allocates (MSC05-J, NUM00-J) and fails at the first problem. Its output is not trusted
 * until the caller has verified the GCM tag over {@link ParsedEnvelope#aad()} (SR-020).
 *
 * <p>Contract note: §2 of the M1 sprint plan lists {@code MAGIC} as a public static array.
 * A public mutable static violates OBJ13-J and OBJ10-J, so the array is private and
 * {@link #magic()} returns a copy.
 */
public final class EnvelopeCodec {

    /** Current and only supported format version. */
    public static final int VERSION = 1;

    /** Largest accepted header, in bytes (ADR 0003). */
    public static final int MAX_HEADER = 64 * 1024;

    /** Header {@code schema_version} (ADR 0006). */
    public static final int SCHEMA_VERSION = 1;

    /** Length of {@code dataSalt} and of the KDF salt. */
    public static final int SALT_LENGTH = 32;

    /** Length of an RFC 5649 wrap of a 32-byte key. */
    public static final int WRAPPED_KEY_LENGTH = 40;

    /** Largest accepted slot count. */
    public static final int MAX_SLOTS = 16;

    /** KDF algorithm name. */
    public static final String KDF_ALG = "argon2id";

    /** Upper bound on Argon2 memory in KiB (ADR 0007: 1 GiB). */
    public static final int MAX_MEMORY_KIB = 1_048_576;

    /** Upper bound on Argon2 iterations (ADR 0007). */
    public static final int MAX_ITERATIONS = 10;

    /** Upper bound on Argon2 lanes. */
    public static final int MAX_PARALLELISM = 16;

    private static final byte[] FILE_MAGIC = {'P', 'M', 'V', 'A', 'U', 'L', 'T', 0};
    private static final int MAGIC_LENGTH = 8;
    private static final int VERSION_LENGTH = 2;
    private static final int HEADER_LEN_LENGTH = 4;
    /** Bytes before the header: magic ‖ version ‖ headerLen. */
    private static final int PREFIX_LENGTH = MAGIC_LENGTH + VERSION_LENGTH + HEADER_LEN_LENGTH;
    private static final int TAG_LENGTH = 16;
    private static final int UUID_LENGTH = 16;
    private static final int MIN_FILE_LENGTH = PREFIX_LENGTH + SALT_LENGTH + TAG_LENGTH;
    private static final long MIN_SAVE_SEQ = 1L;

    private static final String K_SCHEMA_VERSION = "schema_version";
    private static final String K_KDF = "kdf";
    private static final String K_SLOTS = "slots";
    private static final String K_CREATED = "created";
    private static final String K_SAVED = "saved";
    private static final String K_SAVE_SEQ = "save_seq";
    private static final String K_ALG = "alg";
    private static final String K_M = "m";
    private static final String K_T = "t";
    private static final String K_P = "p";
    private static final String K_SALT = "salt";
    private static final String K_ID = "id";
    private static final String K_TYPE = "type";
    private static final String K_WRAPPED_KEY = "wrapped_key";

    private EnvelopeCodec() {
    }

    /** Returns a copy of the 8-byte file magic {@code "PMVAULT\0"}. */
    public static byte[] magic() {
        return FILE_MAGIC.clone();
    }

    /**
     * Encodes a complete vault file.
     *
     * @param h          header to write
     * @param dataSalt32 32-byte per-save salt
     * @param ciphertext AES-GCM output, at least the 16-byte tag
     * @return the file bytes, equal to {@code aadOf(encodeHeader(h), dataSalt32) ‖ ciphertext}
     */
    public static byte[] encode(EnvelopeHeader h, byte[] dataSalt32, byte[] ciphertext) {
        Objects.requireNonNull(ciphertext, "ciphertext");
        if (ciphertext.length < TAG_LENGTH) {
            throw new IllegalArgumentException("ciphertext");
        }
        byte[] aad = aadOf(encodeHeader(h), dataSalt32);
        byte[] out = Arrays.copyOf(aad, Math.addExact(aad.length, ciphertext.length));
        System.arraycopy(ciphertext, 0, out, aad.length, ciphertext.length);
        return out;
    }

    /**
     * Returns the deterministic CBOR encoding of {@code h}.
     *
     * @param h header to encode
     * @throws IllegalArgumentException if the header would not pass {@link #decode}
     */
    public static byte[] encodeHeader(EnvelopeHeader h) {
        Objects.requireNonNull(h, "h");
        validate(h);
        KdfHeader k = h.kdf();
        CborValue kdf = new CborValue.MapV(Map.of(
                K_ALG, new CborValue.Text(k.alg()),
                K_M, new CborValue.UInt(k.m()),
                K_T, new CborValue.UInt(k.t()),
                K_P, new CborValue.UInt(k.p()),
                K_SALT, new CborValue.Bytes(k.salt())));
        List<CborValue> slots = new ArrayList<>(h.slots().size());
        for (SlotHeader s : h.slots()) {
            slots.add(new CborValue.MapV(Map.of(
                    K_ID, new CborValue.Bytes(uuidBytes(s.id())),
                    K_TYPE, new CborValue.Text(s.type()),
                    K_WRAPPED_KEY, new CborValue.Bytes(s.wrappedKey()))));
        }
        CborValue root = new CborValue.MapV(Map.of(
                K_SCHEMA_VERSION, new CborValue.UInt(SCHEMA_VERSION),
                K_KDF, kdf,
                K_SLOTS, new CborValue.Array(slots),
                K_CREATED, new CborValue.UInt(h.created()),
                K_SAVED, new CborValue.UInt(h.saved()),
                K_SAVE_SEQ, new CborValue.UInt(h.saveSeq())));
        byte[] cbor = CborWriter.encode(root);
        if (cbor.length > MAX_HEADER) {
            throw new IllegalArgumentException("header too large");
        }
        return cbor;
    }

    /**
     * Returns the AAD for a header and data salt: {@code magic ‖ version ‖ len ‖ header ‖ salt}.
     * This is exactly the file prefix that precedes the ciphertext.
     *
     * @param headerCbor encoded header, 1..{@link #MAX_HEADER} bytes
     * @param dataSalt32 32-byte data salt
     */
    public static byte[] aadOf(byte[] headerCbor, byte[] dataSalt32) {
        Objects.requireNonNull(headerCbor, "headerCbor");
        Objects.requireNonNull(dataSalt32, "dataSalt32");
        if (headerCbor.length == 0 || headerCbor.length > MAX_HEADER) {
            throw new IllegalArgumentException("headerCbor length");
        }
        if (dataSalt32.length != SALT_LENGTH) {
            throw new IllegalArgumentException("dataSalt32 length");
        }
        ByteBuffer buf = ByteBuffer.allocate(PREFIX_LENGTH + headerCbor.length + SALT_LENGTH);
        buf.put(FILE_MAGIC);
        buf.putShort((short) VERSION);
        buf.putInt(headerCbor.length);
        buf.put(headerCbor);
        buf.put(dataSalt32);
        return buf.array();
    }

    /**
     * Parses and structurally validates a vault file. Checks run in a fixed order and stop
     * at the first failure: minimum length, magic, version, header length, header CBOR,
     * header fields.
     *
     * @param file complete file bytes
     * @return the parsed, still unauthenticated, envelope
     * @throws VaultException {@code UNSUPPORTED_VERSION} for a newer version, otherwise
     *                        {@code CORRUPT}
     */
    public static ParsedEnvelope decode(byte[] file) throws VaultException {
        Objects.requireNonNull(file, "file");
        // 1. Minimum length.
        if (file.length < MIN_FILE_LENGTH) {
            throw corrupt(null);
        }
        // 2. Magic. It is a public constant, so a plain comparison is fine here.
        if (!Arrays.equals(file, 0, MAGIC_LENGTH, FILE_MAGIC, 0, MAGIC_LENGTH)) {
            throw corrupt(null);
        }
        ByteBuffer buf = ByteBuffer.wrap(file);
        // 3. Version, read as unsigned (NUM03-J).
        int version = Short.toUnsignedInt(buf.getShort(MAGIC_LENGTH));
        if (version > VERSION) {
            throw new VaultException(VaultException.Code.UNSUPPORTED_VERSION, null);
        }
        if (version != VERSION) {
            throw corrupt(null);
        }
        // 4. Header length, read as unsigned and checked in long arithmetic (NUM00-J).
        long headerLen = Integer.toUnsignedLong(buf.getInt(MAGIC_LENGTH + VERSION_LENGTH));
        if (headerLen == 0 || headerLen > MAX_HEADER) {
            throw corrupt(null);
        }
        long aadEnd = Math.addExact(Math.addExact((long) PREFIX_LENGTH, headerLen), (long) SALT_LENGTH);
        if (Math.addExact(aadEnd, (long) TAG_LENGTH) > file.length) {
            throw corrupt(null);
        }
        // The bounds above make these int conversions exact (NUM12-J).
        int headerEnd = Math.toIntExact(PREFIX_LENGTH + headerLen);
        int aadLength = Math.toIntExact(aadEnd);
        byte[] headerCbor = Arrays.copyOfRange(file, PREFIX_LENGTH, headerEnd);
        // 5. Header CBOR and fields.
        EnvelopeHeader header = parseHeader(headerCbor);
        return new ParsedEnvelope(header,
                Arrays.copyOfRange(file, 0, aadLength),
                Arrays.copyOfRange(file, headerEnd, aadLength),
                Arrays.copyOfRange(file, aadLength, file.length));
    }

    private static EnvelopeHeader parseHeader(byte[] headerCbor) throws VaultException {
        CborValue root;
        try {
            root = CborReader.decode(headerCbor, CborLimits.HEADER);
        } catch (CborException e) {
            throw corrupt(e);
        }
        Map<String, CborValue> top = map(root);
        if (uint(top, K_SCHEMA_VERSION) != SCHEMA_VERSION) {
            throw corrupt(null);
        }
        Map<String, CborValue> kdfMap = map(required(top, K_KDF));
        KdfHeader kdf = new KdfHeader(
                text(kdfMap, K_ALG),
                boundedInt(kdfMap, K_M, Argon2Params.FLOOR.memoryKiB(), MAX_MEMORY_KIB),
                boundedInt(kdfMap, K_T, Argon2Params.FLOOR.iterations(), MAX_ITERATIONS),
                boundedInt(kdfMap, K_P, Argon2Params.FLOOR.parallelism(), MAX_PARALLELISM),
                bytes(kdfMap, K_SALT, SALT_LENGTH));
        if (!KDF_ALG.equals(kdf.alg())) {
            throw corrupt(null);
        }
        List<SlotHeader> slots = parseSlots(required(top, K_SLOTS));
        EnvelopeHeader header = new EnvelopeHeader(kdf, slots,
                uint(top, K_CREATED), uint(top, K_SAVED), uint(top, K_SAVE_SEQ));
        if (header.saveSeq() < MIN_SAVE_SEQ) {
            throw corrupt(null);
        }
        return header;
    }

    private static List<SlotHeader> parseSlots(CborValue v) throws VaultException {
        if (!(v instanceof CborValue.Array arr)) {
            throw corrupt(null);
        }
        List<CborValue> items = arr.items();
        if (items.isEmpty() || items.size() > MAX_SLOTS) {
            throw corrupt(null);
        }
        List<SlotHeader> slots = new ArrayList<>(items.size());
        Set<UUID> ids = new HashSet<>();
        int passphraseSlots = 0;
        int recoverySlots = 0;
        for (CborValue item : items) {
            Map<String, CborValue> m = map(item);
            UUID id = uuidOf(bytes(m, K_ID, UUID_LENGTH));
            String type = text(m, K_TYPE);
            if (SlotHeader.MASTER.equals(type)) {
                passphraseSlots++;
            } else if (SlotHeader.RECOVERY.equals(type)) {
                recoverySlots++;
            } else {
                throw corrupt(null);
            }
            if (!ids.add(id)) {
                throw corrupt(null);
            }
            slots.add(new SlotHeader(id, type, bytes(m, K_WRAPPED_KEY, WRAPPED_KEY_LENGTH)));
        }
        // M1 profile (vault-header.cddl): exactly one passphrase slot, at most one recovery slot.
        if (passphraseSlots != 1 || recoverySlots > 1) {
            throw corrupt(null);
        }
        return slots;
    }

    /** Applies the same rules as {@link #decode} so {@link #encodeHeader} never writes an unreadable file. */
    private static void validate(EnvelopeHeader h) {
        KdfHeader k = h.kdf();
        boolean ok = KDF_ALG.equals(k.alg())
                && inRange(k.m(), Argon2Params.FLOOR.memoryKiB(), MAX_MEMORY_KIB)
                && inRange(k.t(), Argon2Params.FLOOR.iterations(), MAX_ITERATIONS)
                && inRange(k.p(), Argon2Params.FLOOR.parallelism(), MAX_PARALLELISM)
                && k.salt().length == SALT_LENGTH
                && !h.slots().isEmpty() && h.slots().size() <= MAX_SLOTS
                && h.created() >= 0 && h.saved() >= 0 && h.saveSeq() >= MIN_SAVE_SEQ;
        int passphraseSlots = 0;
        int recoverySlots = 0;
        Set<UUID> ids = new HashSet<>();
        for (SlotHeader s : h.slots()) {
            ok &= s.wrappedKey().length == WRAPPED_KEY_LENGTH && ids.add(s.id());
            if (SlotHeader.MASTER.equals(s.type())) {
                passphraseSlots++;
            } else if (SlotHeader.RECOVERY.equals(s.type())) {
                recoverySlots++;
            } else {
                ok = false;
            }
        }
        if (!ok || passphraseSlots != 1 || recoverySlots > 1) {
            throw new IllegalArgumentException("invalid header");
        }
    }

    private static boolean inRange(int v, int min, int max) {
        return v >= min && v <= max;
    }

    private static Map<String, CborValue> map(CborValue v) throws VaultException {
        if (v instanceof CborValue.MapV m) {
            return m.entries();
        }
        throw corrupt(null);
    }

    private static CborValue required(Map<String, CborValue> m, String key) throws VaultException {
        CborValue v = m.get(key);
        if (v == null) {
            throw corrupt(null);
        }
        return v;
    }

    private static long uint(Map<String, CborValue> m, String key) throws VaultException {
        if (required(m, key) instanceof CborValue.UInt u && u.value() >= 0) {
            return u.value();
        }
        throw corrupt(null);
    }

    private static int boundedInt(Map<String, CborValue> m, String key, int min, int max) throws VaultException {
        long v = uint(m, key);
        if (v < min || v > max) {
            throw corrupt(null);
        }
        return (int) v;
    }

    private static String text(Map<String, CborValue> m, String key) throws VaultException {
        if (required(m, key) instanceof CborValue.Text t) {
            return t.value();
        }
        throw corrupt(null);
    }

    private static byte[] bytes(Map<String, CborValue> m, String key, int length) throws VaultException {
        if (required(m, key) instanceof CborValue.Bytes b) {
            byte[] value = b.value();
            if (value.length == length) {
                return value.clone();
            }
        }
        throw corrupt(null);
    }

    private static byte[] uuidBytes(UUID id) {
        return ByteBuffer.allocate(UUID_LENGTH)
                .putLong(id.getMostSignificantBits())
                .putLong(id.getLeastSignificantBits())
                .array();
    }

    private static UUID uuidOf(byte[] b) {
        ByteBuffer buf = ByteBuffer.wrap(b);
        return new UUID(buf.getLong(), buf.getLong());
    }

    private static VaultException corrupt(Throwable cause) {
        return new VaultException(VaultException.Code.CORRUPT, cause);
    }
}
