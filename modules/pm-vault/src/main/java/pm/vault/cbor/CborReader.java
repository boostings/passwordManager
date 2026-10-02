package pm.vault.cbor;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Strict recursive-descent decoder for the deterministic CBOR subset (ADR 0006 amendment,
 * MSC05-J). Rejects indefinite lengths, tags, floats, negative ints, non-shortest arguments,
 * duplicate or unsorted map keys, invalid UTF-8, trailing bytes, and any exceeded
 * {@link CborLimits} bound. Every length is checked before allocation.
 */
public final class CborReader {
    private static final int MAJOR_NEGATIVE = 1;
    private static final int MAJOR_SIMPLE = 7;
    private static final int MAJOR_MASK = 0x07;
    private static final int ADDITIONAL_MASK = 0x1F;
    private static final int INDEFINITE = 31;
    private static final int SIMPLE_FALSE = 20;
    private static final int SIMPLE_TRUE = 21;
    private static final int BYTE_MASK = 0xFF;
    private static final int BYTE_BITS = 8;

    private CborReader() {}

    /**
     * Decodes exactly one value occupying all of {@code in}.
     *
     * @param in  the encoded bytes; not modified
     * @param lim resource limits
     * @return the decoded value tree
     * @throws CborException {@code MALFORMED}, {@code LIMIT} or {@code NON_CANONICAL}
     */
    public static CborValue decode(byte[] in, CborLimits lim) throws CborException {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(lim, "lim");
        if (in.length > lim.maxTotalBytes()) {
            throw new CborException(CborException.Code.LIMIT);
        }
        ReaderState state = new ReaderState(in, lim);
        CborValue value = readValue(state, 0);
        if (state.pos != in.length) {
            throw new CborException(CborException.Code.MALFORMED); // trailing bytes
        }
        return value;
    }

    private static CborValue readValue(ReaderState state, int depth) throws CborException {
        if (depth > state.limits.maxDepth()) {
            throw new CborException(CborException.Code.LIMIT);
        }
        state.countItem();
        ensureAvailable(state, 1);
        int initial = state.data[state.pos++] & BYTE_MASK;
        int major = (initial >>> CborWriter.MAJOR_SHIFT) & MAJOR_MASK;
        int additional = initial & ADDITIONAL_MASK;
        if (additional == INDEFINITE) {
            throw new CborException(CborException.Code.MALFORMED); // indefinite length
        }
        if (major == MAJOR_SIMPLE) {
            return readSimple(additional);
        }
        long length = readLength(state, additional);
        return switch (major) {
            case CborWriter.MAJOR_UINT -> new CborValue.UInt(requireUInt(length));
            case CborWriter.MAJOR_BYTES -> new CborValue.Bytes(readString(state, length));
            case CborWriter.MAJOR_TEXT -> new CborValue.Text(decodeUtf8(readString(state, length)));
            case CborWriter.MAJOR_ARRAY -> readArray(state, length, depth);
            case CborWriter.MAJOR_MAP -> readMap(state, length, depth);
            case MAJOR_NEGATIVE -> throw new CborException(CborException.Code.MALFORMED);
            default -> throw new CborException(CborException.Code.MALFORMED); // tags
        };
    }

    private static CborValue readSimple(int additional) throws CborException {
        if (additional == SIMPLE_FALSE) {
            return new CborValue.Bool(false);
        }
        if (additional == SIMPLE_TRUE) {
            return new CborValue.Bool(true);
        }
        throw new CborException(CborException.Code.MALFORMED); // floats, null, other simples
    }

    private static long requireUInt(long value) throws CborException {
        if (value < 0) {
            throw new CborException(CborException.Code.LIMIT); // above Long.MAX_VALUE
        }
        return value;
    }

    private static CborValue readArray(ReaderState state, long length, int depth)
            throws CborException {
        state.checkCount(length);
        List<CborValue> items = new ArrayList<>((int) length);
        for (long i = 0; i < length; i++) {
            items.add(readValue(state, depth + 1));
        }
        return new CborValue.Array(items);
    }

    private static CborValue readMap(ReaderState state, long length, int depth)
            throws CborException {
        state.checkCount(length);
        Map<String, CborValue> entries = new LinkedHashMap<>();
        byte[] previousKey = null;
        for (long i = 0; i < length; i++) {
            int keyStart = state.pos;
            CborValue keyValue = readValue(state, depth + 1);
            if (!(keyValue instanceof CborValue.Text keyText)) {
                throw new CborException(CborException.Code.MALFORMED); // non-text key
            }
            byte[] encodedKey = Arrays.copyOfRange(state.data, keyStart, state.pos);
            if (previousKey != null && CborWriter.compareKeys(previousKey, encodedKey) >= 0) {
                throw new CborException(CborException.Code.NON_CANONICAL); // unsorted or duplicate
            }
            previousKey = encodedKey;
            entries.put(keyText.value(), readValue(state, depth + 1));
        }
        return new CborValue.MapV(entries);
    }

    private static long readLength(ReaderState state, int additional) throws CborException {
        int argBytes;
        long floor;
        if (additional <= CborWriter.MAX_INLINE) {
            return additional;
        } else if (additional == CborWriter.ARG_1_BYTE) {
            argBytes = Byte.BYTES;
            floor = CborWriter.MAX_INLINE;
        } else if (additional == CborWriter.ARG_2_BYTES) {
            argBytes = Short.BYTES;
            floor = CborWriter.MAX_1_BYTE;
        } else if (additional == CborWriter.ARG_4_BYTES) {
            argBytes = Integer.BYTES;
            floor = CborWriter.MAX_2_BYTES;
        } else if (additional == CborWriter.ARG_8_BYTES) {
            argBytes = Long.BYTES;
            floor = CborWriter.MAX_4_BYTES;
        } else {
            throw new CborException(CborException.Code.MALFORMED); // reserved 28..30
        }
        ensureAvailable(state, argBytes);
        long value = 0;
        for (int i = 0; i < argBytes; i++) {
            value = (value << BYTE_BITS) | (state.data[state.pos++] & BYTE_MASK);
        }
        // Unsigned comparison: an 8-byte argument above Long.MAX_VALUE is negative here.
        if (Long.compareUnsigned(value, floor) <= 0) {
            throw new CborException(CborException.Code.NON_CANONICAL); // not shortest form
        }
        return value;
    }

    private static byte[] readString(ReaderState state, long length) throws CborException {
        if (length < 0 || length > state.limits.maxStringBytes()) {
            throw new CborException(CborException.Code.LIMIT);
        }
        int count = (int) length;
        ensureAvailable(state, count);
        byte[] copy = Arrays.copyOfRange(state.data, state.pos, state.pos + count);
        state.pos += count;
        return copy;
    }

    private static String decodeUtf8(byte[] bytes) throws CborException {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return decoder.decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException ex) {
            throw new CborException(CborException.Code.MALFORMED, ex);
        }
    }

    private static void ensureAvailable(ReaderState state, int count) throws CborException {
        if (count > state.data.length - state.pos) {
            throw new CborException(CborException.Code.MALFORMED); // truncated
        }
    }

    /** Cursor plus the running item counter for the whole document. */
    private static final class ReaderState {
        private final byte[] data;
        private final CborLimits limits;
        private int pos;
        private long items;

        private ReaderState(byte[] data, CborLimits limits) {
            this.data = data;
            this.limits = limits;
        }

        private void countItem() throws CborException {
            items++;
            if (items > limits.maxItems()) {
                throw new CborException(CborException.Code.LIMIT);
            }
        }

        /** Rejects a container count above the item limit or the bytes left, before allocating. */
        private void checkCount(long count) throws CborException {
            if (count < 0 || count > limits.maxItems() - items) {
                throw new CborException(CborException.Code.LIMIT);
            }
            if (count > data.length - pos) {
                throw new CborException(CborException.Code.MALFORMED); // each item needs a byte
            }
        }
    }
}
