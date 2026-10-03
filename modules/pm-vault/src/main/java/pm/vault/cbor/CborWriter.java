package pm.vault.cbor;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Encodes a {@link CborValue} with RFC 8949 section 4.2.1 deterministic encoding (ADR 0006
 * Amendment 1): definite lengths only, the shortest form of every integer and length, and map keys
 * in bytewise lexicographic order of their encoded form.
 *
 * <p>The same value always encodes to the same bytes, which is what lets the vault header be used
 * as authenticated data (SR-015). Byte strings may carry secrets, so the working buffer is
 * zero-filled whenever it is replaced and before {@code encode} returns. This is best effort
 * (ADR 0008, risk R-003).
 */
public final class CborWriter {

    private static final long MAX_ONE_BYTE = 0xFFL;
    private static final long MAX_TWO_BYTES = 0xFFFFL;
    private static final long MAX_FOUR_BYTES = 0xFFFF_FFFFL;
    private static final int INITIAL_CAPACITY = 256;
    /** One initial byte plus an eight-byte argument. */
    private static final int MAX_HEAD_BYTES = 9;
    /** Largest array size every JVM can allocate. */
    private static final int MAX_CAPACITY = Integer.MAX_VALUE - 8;
    private static final CborLimits UNBOUNDED =
            new CborLimits(Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE);

    private CborWriter() {
    }

    /**
     * Encodes {@code value} with no bounds other than the largest possible array.
     *
     * @param value the item to encode
     * @return the deterministic encoding
     * @throws IllegalArgumentException if the encoding would not fit in one array
     */
    public static byte[] encode(CborValue value) {
        return encode(value, UNBOUNDED);
    }

    /**
     * Encodes {@code value} and enforces {@code limits} with the counting rules of
     * {@link CborReader}, so the result is always accepted by
     * {@code CborReader.decode(result, limits)}.
     *
     * @param value the item to encode
     * @param limits bounds on depth, item count, string length and total size
     * @return the deterministic encoding
     * @throws IllegalArgumentException if a bound would be exceeded; nothing is returned
     */
    public static byte[] encode(CborValue value, CborLimits limits) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(limits, "limits");
        try (Sink sink = new Sink(limits, INITIAL_CAPACITY)) {
            writeValue(sink, value, 0);
            return sink.toByteArray();
        }
    }

    /**
     * Orders two encoded map keys bytewise, each byte compared as unsigned (RFC 8949 section
     * 4.2.1). Map keys are not secrets, so this is a plain loop that stops at the first difference;
     * it is not for comparing secret material (SR-016).
     */
    static int compareEncodedKeys(byte[] left, byte[] right) {
        int common = Math.min(left.length, right.length);
        for (int i = 0; i < common; i++) {
            int difference = (left[i] & Wire.BYTE_MASK) - (right[i] & Wire.BYTE_MASK);
            if (difference != 0) {
                return difference;
            }
        }
        return Integer.compare(left.length, right.length);
    }

    /** Writes one item. {@code depth} is the number of containers that enclose it. */
    private static void writeValue(Sink sink, CborValue value, int depth) {
        sink.countItem();
        switch (value) {
            case CborValue.UInt u -> sink.head(Wire.MAJOR_UINT, u.value());
            case CborValue.Bytes b -> {
                sink.stringHead(Wire.MAJOR_BYTES, b.length());
                sink.putBytes(b);
            }
            case CborValue.Text t -> {
                byte[] utf8 = t.value().getBytes(StandardCharsets.UTF_8);
                sink.stringHead(Wire.MAJOR_TEXT, utf8.length);
                sink.putAll(utf8);
            }
            case CborValue.Array a -> {
                sink.enterContainer(depth);
                sink.head(Wire.MAJOR_ARRAY, a.items().size());
                for (CborValue item : a.items()) {
                    writeValue(sink, item, depth + 1);
                }
            }
            case CborValue.MapV m -> writeMap(sink, m, depth);
            case CborValue.Bool b -> sink.put(
                    (Wire.MAJOR_SIMPLE << Wire.MAJOR_SHIFT) | (b.value() ? Wire.SIMPLE_TRUE : Wire.SIMPLE_FALSE));
        }
    }

    private static void writeMap(Sink sink, CborValue.MapV map, int depth) {
        sink.enterContainer(depth);
        TreeMap<byte[], CborValue> sorted = new TreeMap<>(CborWriter::compareEncodedKeys);
        for (Map.Entry<String, CborValue> entry : map.entries().entrySet()) {
            if (sorted.put(encodeKey(entry.getKey(), sink.limits), entry.getValue()) != null) {
                // Unreachable for well-formed keys: distinct strings have distinct UTF-8 encodings.
                throw new IllegalArgumentException("two map keys have the same encoding");
            }
        }
        sink.head(Wire.MAJOR_MAP, sorted.size());
        for (Map.Entry<byte[], CborValue> entry : sorted.entrySet()) {
            sink.countItem();
            sink.putAll(entry.getKey());
            writeValue(sink, entry.getValue(), depth + 1);
        }
    }

    /** Returns the complete encoding of a text key: head followed by its UTF-8 bytes. */
    private static byte[] encodeKey(String key, CborLimits limits) {
        byte[] utf8 = key.getBytes(StandardCharsets.UTF_8);
        try (Sink item = new Sink(limits, utf8.length + MAX_HEAD_BYTES)) {
            item.stringHead(Wire.MAJOR_TEXT, utf8.length);
            item.putAll(utf8);
            return item.toByteArray();
        }
    }

    /** Growable output buffer that enforces the limits and never leaves a stale copy behind. */
    private static final class Sink implements AutoCloseable {
        private final CborLimits limits;
        private byte[] buffer;
        private int size;
        private int items;

        Sink(CborLimits limits, int capacity) {
            this.limits = limits;
            this.buffer = new byte[capacity];
        }

        void countItem() {
            if (items >= limits.maxItems()) {
                throw new IllegalArgumentException("value exceeds the item limit");
            }
            items++;
        }

        /** Checks that a container opened inside {@code depth} containers is allowed. */
        void enterContainer(int depth) {
            if (depth >= limits.maxDepth()) {
                throw new IllegalArgumentException("value exceeds the depth limit");
            }
        }

        void stringHead(int major, int length) {
            if (length > limits.maxStringBytes()) {
                throw new IllegalArgumentException("string exceeds the length limit");
            }
            head(major, length);
        }

        /** Writes the initial byte and the shortest-form argument. */
        void head(int major, long argument) {
            int prefix = major << Wire.MAJOR_SHIFT;
            if (argument < 0) {
                throw new IllegalArgumentException("argument must not be negative");
            }
            if (argument < Wire.INFO_ONE_BYTE) {
                put(prefix | (int) argument);
            } else if (argument <= MAX_ONE_BYTE) {
                put(prefix | Wire.INFO_ONE_BYTE);
                putBigEndian(argument, Byte.BYTES);
            } else if (argument <= MAX_TWO_BYTES) {
                put(prefix | Wire.INFO_TWO_BYTES);
                putBigEndian(argument, Short.BYTES);
            } else if (argument <= MAX_FOUR_BYTES) {
                put(prefix | Wire.INFO_FOUR_BYTES);
                putBigEndian(argument, Integer.BYTES);
            } else {
                put(prefix | Wire.INFO_EIGHT_BYTES);
                putBigEndian(argument, Long.BYTES);
            }
        }

        private void putBigEndian(long value, int width) {
            for (int shift = (width - 1) * Byte.SIZE; shift >= 0; shift -= Byte.SIZE) {
                put((int) (value >>> shift) & Wire.BYTE_MASK);
            }
        }

        // In the three methods below reserve() runs first, in its own statement: it may replace
        // the buffer, and Java evaluates an array reference before the index or argument after it.

        void put(int b) {
            int offset = reserve(1);
            buffer[offset] = (byte) b;
        }

        void putAll(byte[] source) {
            int offset = reserve(source.length);
            System.arraycopy(source, 0, buffer, offset, source.length);
        }

        void putBytes(CborValue.Bytes source) {
            int offset = reserve(source.length());
            source.copyInto(buffer, offset);
        }

        /** Makes room for {@code count} more bytes and returns the offset where they go. */
        int reserve(int count) {
            long needed = (long) size + count;
            if (needed > limits.maxTotalBytes() || needed > MAX_CAPACITY) {
                throw new IllegalArgumentException("encoding exceeds the size limit");
            }
            if (needed > buffer.length) {
                long doubled = Math.max(needed, 2L * buffer.length);
                byte[] bigger = Arrays.copyOf(buffer, (int) Math.min(doubled, MAX_CAPACITY));
                Arrays.fill(buffer, (byte) 0);
                buffer = bigger;
            }
            int offset = size;
            size += count;
            return offset;
        }

        byte[] toByteArray() {
            return Arrays.copyOf(buffer, size);
        }

        /** Zero-fills the working buffer (ADR 0008, risk R-003). */
        @Override
        public void close() {
            Arrays.fill(buffer, (byte) 0);
        }
    }
}
