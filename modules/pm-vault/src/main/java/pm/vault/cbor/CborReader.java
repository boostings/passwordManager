package pm.vault.cbor;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Bounded, strict decoder for the deterministic CBOR subset (ADR 0006 Amendment 1, SR-021).
 *
 * <p>It parses bytes an attacker may control: the vault header is read before it is authenticated.
 * It therefore accepts exactly what {@link CborWriter} can produce and rejects everything else with
 * a {@link CborException}; no input makes it throw anything else:
 *
 * <ul>
 *   <li>{@code MALFORMED}: truncated input, trailing bytes, indefinite lengths, tags, floats,
 *       simple values other than the booleans, negative integers, map keys that are not text,
 *       invalid UTF-8.
 *   <li>{@code NON_CANONICAL}: an integer or a length that is not in its shortest form, map keys
 *       that are duplicated or not in bytewise order of their encoding (RFC 8949 section 4.2.1).
 *   <li>{@code LIMIT}: any {@link CborLimits} bound exceeded, or a number of 2^63 or more.
 * </ul>
 *
 * <p>Every length is checked against its limit and against the bytes that remain before anything
 * is allocated (MSC05-J, NUM00-J), and recursion is bounded by {@link CborLimits#maxDepth()}. If
 * decoding fails, the byte strings read so far are zero-filled, best effort (ADR 0008, risk R-003).
 */
public final class CborReader {

    private static final long SHORTEST_TWO_BYTES = 0x100L;
    private static final long SHORTEST_FOUR_BYTES = 0x1_0000L;
    private static final long SHORTEST_EIGHT_BYTES = 0x1_0000_0000L;
    /** Cap on the initial capacity of a container; the declared length is still honoured. */
    private static final int PREALLOCATE_MAX = 64;
    private static final int BYTES_PER_ARRAY_ITEM = 1;
    private static final int BYTES_PER_MAP_ENTRY = 2;

    private CborReader() {
    }

    /**
     * Decodes exactly one item that spans all of {@code in}.
     *
     * @param in the encoded bytes; not modified
     * @param lim the bounds to enforce
     * @return the decoded value
     * @throws CborException if {@code in} is not a deterministic encoding of the supported subset,
     *     or exceeds {@code lim}
     */
    public static CborValue decode(byte[] in, CborLimits lim) throws CborException {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(lim, "lim");
        if (in.length > lim.maxTotalBytes()) {
            throw limit("input exceeds the total size limit");
        }
        Cursor cursor = new Cursor(in, lim);
        boolean complete = false;
        try {
            CborValue value = readValue(cursor, 0);
            if (cursor.position != in.length) {
                throw malformed("trailing bytes after the value");
            }
            complete = true;
            return value;
        } finally {
            if (!complete) {
                cursor.wipeByteStrings();
            }
        }
    }

    /** Reads one item. {@code depth} is the number of containers that enclose it. */
    private static CborValue readValue(Cursor cursor, int depth) throws CborException {
        cursor.countItem();
        int initial = cursor.readByte();
        int info = initial & Wire.INFO_MASK;
        return switch (initial >>> Wire.MAJOR_SHIFT) {
            case Wire.MAJOR_UINT -> new CborValue.UInt(cursor.readArgument(info));
            case Wire.MAJOR_BYTES -> readBytes(cursor, info);
            case Wire.MAJOR_TEXT -> readText(cursor, info);
            case Wire.MAJOR_ARRAY -> readArray(cursor, info, depth);
            case Wire.MAJOR_MAP -> readMap(cursor, info, depth);
            case Wire.MAJOR_SIMPLE -> readSimple(info);
            case Wire.MAJOR_NEGATIVE -> throw malformed("negative integers are not supported");
            default -> throw malformed("tags are not supported");
        };
    }

    private static CborValue readBytes(Cursor cursor, int info) throws CborException {
        int length = cursor.readStringLength(info);
        byte[] raw = Arrays.copyOfRange(cursor.data, cursor.position, cursor.position + length);
        cursor.position += length;
        try {
            return cursor.track(new CborValue.Bytes(raw));
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    private static CborValue readText(Cursor cursor, int info) throws CborException {
        int length = cursor.readStringLength(info);
        try {
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(cursor.data, cursor.position, length))
                    .toString();
            cursor.position += length;
            return new CborValue.Text(text);
        } catch (CharacterCodingException e) {
            throw new CborException(CborException.Code.MALFORMED, "text is not valid UTF-8", e);
        }
    }

    private static CborValue readArray(Cursor cursor, int info, int depth) throws CborException {
        int count = cursor.readContainerLength(info, BYTES_PER_ARRAY_ITEM, depth);
        List<CborValue> items = new ArrayList<>(Math.min(count, PREALLOCATE_MAX));
        for (int i = 0; i < count; i++) {
            items.add(readValue(cursor, depth + 1));
        }
        return new CborValue.Array(items);
    }

    private static CborValue readMap(Cursor cursor, int info, int depth) throws CborException {
        int count = cursor.readContainerLength(info, BYTES_PER_MAP_ENTRY, depth);
        Map<String, CborValue> entries = new HashMap<>();
        int previousStart = 0;
        int previousEnd = 0;
        for (int i = 0; i < count; i++) {
            int keyStart = cursor.position;
            if (!(readValue(cursor, depth + 1) instanceof CborValue.Text key)) {
                throw malformed("map keys must be text");
            }
            int keyEnd = cursor.position;
            if (i > 0) {
                // Keys were read in shortest form, so the input bytes are their encoded form.
                int order = compareRanges(cursor.data, previousStart, previousEnd, keyStart, keyEnd);
                if (order == 0) {
                    throw nonCanonical("duplicate map key");
                }
                if (order > 0) {
                    throw nonCanonical("map keys are not in deterministic order");
                }
            }
            previousStart = keyStart;
            previousEnd = keyEnd;
            entries.put(key.value(), readValue(cursor, depth + 1));
        }
        return new CborValue.MapV(entries);
    }

    private static CborValue readSimple(int info) throws CborException {
        if (info == Wire.SIMPLE_FALSE) {
            return new CborValue.Bool(false);
        }
        if (info == Wire.SIMPLE_TRUE) {
            return new CborValue.Bool(true);
        }
        if (info == Wire.INFO_INDEFINITE) {
            throw malformed("unexpected break");
        }
        throw malformed("floats and simple values other than booleans are not supported");
    }

    /**
     * Orders two ranges of {@code data} bytewise, each byte compared as unsigned (RFC 8949 section
     * 4.2.1). Map keys are not secrets, so this is a plain loop that stops at the first difference;
     * it is not for comparing secret material (SR-016).
     */
    private static int compareRanges(byte[] data, int leftStart, int leftEnd, int rightStart, int rightEnd) {
        int leftLength = leftEnd - leftStart;
        int rightLength = rightEnd - rightStart;
        int common = Math.min(leftLength, rightLength);
        for (int i = 0; i < common; i++) {
            int difference = (data[leftStart + i] & Wire.BYTE_MASK) - (data[rightStart + i] & Wire.BYTE_MASK);
            if (difference != 0) {
                return difference;
            }
        }
        return Integer.compare(leftLength, rightLength);
    }

    private static CborException malformed(String message) {
        return new CborException(CborException.Code.MALFORMED, message);
    }

    private static CborException nonCanonical(String message) {
        return new CborException(CborException.Code.NON_CANONICAL, message);
    }

    private static CborException limit(String message) {
        return new CborException(CborException.Code.LIMIT, message);
    }

    /** Read position, running item count and the byte strings created so far. */
    private static final class Cursor {
        private final byte[] data;
        private final CborLimits limits;
        private final List<CborValue.Bytes> byteStrings = new ArrayList<>();
        private int position;
        private int items;

        Cursor(byte[] data, CborLimits limits) {
            this.data = data;
            this.limits = limits;
        }

        int remaining() {
            return data.length - position;
        }

        /** Counts one data item against the running total. */
        void countItem() throws CborException {
            if (items >= limits.maxItems()) {
                throw limit("item count exceeds the limit");
            }
            items++;
        }

        int readByte() throws CborException {
            if (remaining() <= 0) {
                throw malformed("unexpected end of input");
            }
            return data[position++] & Wire.BYTE_MASK;
        }

        /**
         * Reads the argument that the additional information {@code info} announces.
         *
         * @return the argument, 0 to {@link Long#MAX_VALUE}
         */
        long readArgument(int info) throws CborException {
            if (info < Wire.INFO_ONE_BYTE) {
                return info;
            }
            if (info == Wire.INFO_INDEFINITE) {
                throw malformed("indefinite lengths are not supported");
            }
            if (info > Wire.INFO_EIGHT_BYTES) {
                throw malformed("reserved additional information");
            }
            int width = 1 << (info - Wire.INFO_ONE_BYTE);
            if (width > remaining()) {
                throw malformed("unexpected end of input");
            }
            long value = 0;
            for (int i = 0; i < width; i++) {
                value = (value << Byte.SIZE) | (data[position++] & Wire.BYTE_MASK);
            }
            if (Long.compareUnsigned(value, shortestFormFloor(info)) < 0) {
                throw nonCanonical("integer or length is not in its shortest form");
            }
            if (value < 0) {
                throw limit("integer or length exceeds the supported range");
            }
            return value;
        }

        /** Reads a string length and checks it against the limit, then the remaining input. */
        int readStringLength(int info) throws CborException {
            long length = readArgument(info);
            if (length > limits.maxStringBytes()) {
                throw limit("string exceeds the length limit");
            }
            if (length > remaining()) {
                throw malformed("unexpected end of input");
            }
            return (int) length;
        }

        /**
         * Reads the entry count of a container opened inside {@code depth} containers and checks it
         * against the depth limit, the item limit and the remaining input, in that order. Every
         * entry occupies at least {@code minBytesPerEntry} bytes, so a count larger than the input
         * can hold is rejected before anything is allocated.
         */
        int readContainerLength(int info, int minBytesPerEntry, int depth) throws CborException {
            long length = readArgument(info);
            if (depth >= limits.maxDepth()) {
                throw limit("nesting exceeds the depth limit");
            }
            if (length > limits.maxItems()) {
                throw limit("container exceeds the item limit");
            }
            if (length * minBytesPerEntry > remaining()) {
                throw malformed("unexpected end of input");
            }
            return (int) length;
        }

        CborValue.Bytes track(CborValue.Bytes bytes) {
            byteStrings.add(bytes);
            return bytes;
        }

        void wipeByteStrings() {
            byteStrings.forEach(CborValue.Bytes::wipe);
        }

        /** Smallest value that needs the argument width announced by {@code info}. */
        private static long shortestFormFloor(int info) {
            return switch (info) {
                case Wire.INFO_ONE_BYTE -> Wire.INFO_ONE_BYTE;
                case Wire.INFO_TWO_BYTES -> SHORTEST_TWO_BYTES;
                case Wire.INFO_FOUR_BYTES -> SHORTEST_FOUR_BYTES;
                default -> SHORTEST_EIGHT_BYTES;
            };
        }
    }
}
