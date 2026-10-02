package pm.vault.cbor;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * RFC 8949 §4.2.1 deterministic encoder for the CBOR subset of the ADR 0006 amendment:
 * shortest argument encoding, definite lengths only, map keys sorted by the bytewise
 * lexicographic order of their encoded form.
 */
public final class CborWriter {
    static final int MAJOR_UINT = 0;
    static final int MAJOR_BYTES = 2;
    static final int MAJOR_TEXT = 3;
    static final int MAJOR_ARRAY = 4;
    static final int MAJOR_MAP = 5;
    static final int MAJOR_SHIFT = 5;
    /** Largest argument stored directly in the initial byte. */
    static final int MAX_INLINE = 23;
    static final int ARG_1_BYTE = 24;
    static final int ARG_2_BYTES = 25;
    static final int ARG_4_BYTES = 26;
    static final int ARG_8_BYTES = 27;
    static final long MAX_1_BYTE = 0xFFL;
    static final long MAX_2_BYTES = 0xFFFFL;
    static final long MAX_4_BYTES = 0xFFFF_FFFFL;
    static final int FALSE_BYTE = 0xF4;
    static final int TRUE_BYTE = 0xF5;
    private static final int BYTE_BITS = 8;
    private static final int BYTE_MASK = 0xFF;

    private CborWriter() {}

    /**
     * Encodes a value deterministically.
     *
     * @param value the value tree, never null
     * @return the canonical encoding
     */
    public static byte[] encode(CborValue value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeValue(out, value);
        return out.toByteArray();
    }

    /**
     * Bytewise unsigned lexicographic comparison of two encoded map keys (RFC 8949 §4.2.1).
     * Keys are not secret, so this short-circuits by design; it is not {@code Arrays.compare}
     * only because SR-016 bans that call on byte arrays outside pm-crypto.
     */
    static int compareKeys(byte[] left, byte[] right) {
        int common = Math.min(left.length, right.length);
        for (int i = 0; i < common; i++) {
            int diff = (left[i] & BYTE_MASK) - (right[i] & BYTE_MASK);
            if (diff != 0) {
                return diff;
            }
        }
        return left.length - right.length;
    }

    private static void writeValue(ByteArrayOutputStream out, CborValue value) {
        switch (value) {
            case CborValue.UInt u -> writeUnsigned(out, MAJOR_UINT, u.value());
            case CborValue.Bytes b -> {
                byte[] copy = b.value();
                writeUnsigned(out, MAJOR_BYTES, copy.length);
                out.writeBytes(copy);
                Arrays.fill(copy, (byte) 0); // best-effort wipe of a possible secret (R-003)
            }
            case CborValue.Text t -> {
                byte[] textBytes = t.value().getBytes(StandardCharsets.UTF_8);
                writeUnsigned(out, MAJOR_TEXT, textBytes.length);
                out.writeBytes(textBytes);
            }
            case CborValue.Array a -> {
                writeUnsigned(out, MAJOR_ARRAY, a.items().size());
                for (CborValue item : a.items()) {
                    writeValue(out, item);
                }
            }
            case CborValue.MapV m -> writeMap(out, m);
            case CborValue.Bool b -> out.write(b.value() ? TRUE_BYTE : FALSE_BYTE);
        }
    }

    private static void writeMap(ByteArrayOutputStream out, CborValue.MapV m) {
        List<Map.Entry<byte[], CborValue>> entries = new ArrayList<>(m.entries().size());
        for (Map.Entry<String, CborValue> entry : m.entries().entrySet()) {
            entries.add(Map.entry(encode(new CborValue.Text(entry.getKey())), entry.getValue()));
        }
        entries.sort((left, right) -> compareKeys(left.getKey(), right.getKey()));
        writeUnsigned(out, MAJOR_MAP, entries.size());
        for (Map.Entry<byte[], CborValue> entry : entries) {
            out.writeBytes(entry.getKey());
            writeValue(out, entry.getValue());
        }
    }

    private static void writeUnsigned(ByteArrayOutputStream out, int majorType, long value) {
        int major = majorType << MAJOR_SHIFT;
        int argBytes;
        if (value <= MAX_INLINE) {
            out.write(major | (int) value);
            return;
        } else if (value <= MAX_1_BYTE) {
            out.write(major | ARG_1_BYTE);
            argBytes = Byte.BYTES;
        } else if (value <= MAX_2_BYTES) {
            out.write(major | ARG_2_BYTES);
            argBytes = Short.BYTES;
        } else if (value <= MAX_4_BYTES) {
            out.write(major | ARG_4_BYTES);
            argBytes = Integer.BYTES;
        } else {
            out.write(major | ARG_8_BYTES);
            argBytes = Long.BYTES;
        }
        for (int shift = (argBytes - 1) * BYTE_BITS; shift >= 0; shift -= BYTE_BITS) {
            out.write((int) ((value >>> shift) & BYTE_MASK));
        }
    }
}
