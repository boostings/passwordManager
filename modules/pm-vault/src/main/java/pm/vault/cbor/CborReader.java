package pm.vault.cbor;

import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class CborReader {
    private CborReader() {}

    public static CborValue decode(byte[] in, CborLimits lim) throws CborException {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(lim, "lim");
        if (in.length > lim.maxTotalBytes()) {
            throw new CborException(CborException.Code.LIMIT, "input exceeds configured total bytes");
        }
        ReaderState state = new ReaderState(in, lim);
        CborValue value = readValue(state, 0);
        if (state.pos != in.length) {
            throw new CborException(CborException.Code.MALFORMED, "trailing bytes after value");
        }
        return value;
    }

    private static CborValue readValue(ReaderState state, int depth) throws CborException {
        if (depth > state.limits.maxDepth()) {
            throw new CborException(CborException.Code.LIMIT, "depth exceeds limit");
        }
        if (state.pos >= state.data.length) {
            throw new CborException(CborException.Code.MALFORMED, "unexpected end of input");
        }
        int initial = state.data[state.pos++] & 0xFF;
        int major = (initial & 0xE0) >>> 5;
        int additional = initial & 0x1F;

        if (additional == 31) {
            throw new CborException(CborException.Code.MALFORMED, "indefinite lengths are not supported");
        }

        long length = readLength(state, additional);
        switch (major) {
            case 0 -> {
                if (!isCanonicalUnsigned(length, additional)) {
                    throw new CborException(CborException.Code.NON_CANONICAL, "non-shortest integer encoding");
                }
                return new CborValue.UInt(length);
            }
            case 1 -> throw new CborException(CborException.Code.MALFORMED, "negative integers are not supported");
            case 2 -> {
                if (length > state.limits.maxStringBytes()) {
                    throw new CborException(CborException.Code.LIMIT, "byte string exceeds limit");
                }
                byte[] bytes = readBytes(state, length);
                return new CborValue.Bytes(bytes);
            }
            case 3 -> {
                if (length > state.limits.maxStringBytes()) {
                    throw new CborException(CborException.Code.LIMIT, "text string exceeds limit");
                }
                byte[] bytes = readBytes(state, length);
                CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
                decoder.onMalformedInput(CodingErrorAction.REPORT);
                decoder.onUnmappableCharacter(CodingErrorAction.REPORT);
                try {
                    return new CborValue.Text(decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString());
                } catch (Exception ex) {
                    throw new CborException(CborException.Code.MALFORMED, "invalid UTF-8", ex);
                }
            }
            case 4 -> {
                if (length > state.limits.maxItems()) {
                    throw new CborException(CborException.Code.LIMIT, "array exceeds item limit");
                }
                List<CborValue> items = new ArrayList<>((int) Math.min(length, Integer.MAX_VALUE));
                for (long i = 0; i < length; i++) {
                    items.add(readValue(state, depth + 1));
                }
                return new CborValue.Array(items);
            }
            case 5 -> {
                if (length > state.limits.maxItems()) {
                    throw new CborException(CborException.Code.LIMIT, "map exceeds item limit");
                }
                LinkedHashMap<String, CborValue> entries = new LinkedHashMap<>();
                for (long i = 0; i < length; i++) {
                    CborValue keyValue = readValue(state, depth + 1);
                    if (!(keyValue instanceof CborValue.Text keyText)) {
                        throw new CborException(CborException.Code.MALFORMED, "map keys must be text");
                    }
                    CborValue value = readValue(state, depth + 1);
                    if (entries.containsKey(keyText.value())) {
                        throw new CborException(CborException.Code.NON_CANONICAL, "duplicate map key");
                    }
                    entries.put(keyText.value(), value);
                }
                return new CborValue.MapV(Map.copyOf(entries));
            }
            case 7 -> {
                if (additional == 20) {
                    return new CborValue.Bool(false);
                }
                if (additional == 21) {
                    return new CborValue.Bool(true);
                }
                throw new CborException(CborException.Code.MALFORMED, "unsupported simple value");
            }
            default -> throw new CborException(CborException.Code.MALFORMED, "unsupported major type: " + major);
        }
    }

    private static long readLength(ReaderState state, int additional) throws CborException {
        if (additional < 24) {
            return additional;
        }
        if (additional == 24) {
            ensureAvailable(state, 1);
            int value = state.data[state.pos++] & 0xFF;
            return value;
        }
        if (additional == 25) {
            ensureAvailable(state, 2);
            int hi = (state.data[state.pos++] & 0xFF) << 8;
            int lo = state.data[state.pos++] & 0xFF;
            return (hi | lo) & 0xFFFFL;
        }
        if (additional == 26) {
            ensureAvailable(state, 4);
            long value = 0;
            for (int i = 0; i < 4; i++) {
                value = (value << 8) | (state.data[state.pos++] & 0xFFL);
            }
            return value;
        }
        if (additional == 27) {
            ensureAvailable(state, 8);
            long value = 0;
            for (int i = 0; i < 8; i++) {
                value = (value << 8) | (state.data[state.pos++] & 0xFFL);
            }
            return value;
        }
        throw new CborException(CborException.Code.MALFORMED, "invalid length encoding");
    }

    private static boolean isCanonicalUnsigned(long value, int additional) {
        if (additional < 24) {
            return true;
        }
        if (additional == 24 && value < 24) {
            return false;
        }
        if (additional == 25 && value < (1 << 8)) {
            return false;
        }
        if (additional == 26 && value < (1 << 16)) {
            return false;
        }
        if (additional == 27 && value < (1L << 32)) {
            return false;
        }
        return true;
    }

    private static byte[] readBytes(ReaderState state, long length) throws CborException {
        if (length < 0 || length > Integer.MAX_VALUE) {
            throw new CborException(CborException.Code.LIMIT, "length out of supported range");
        }
        int lengthInt = (int) length;
        ensureAvailable(state, lengthInt);
        byte[] copy = Arrays.copyOfRange(state.data, state.pos, state.pos + lengthInt);
        state.pos += lengthInt;
        return copy;
    }

    private static void ensureAvailable(ReaderState state, int count) throws CborException {
        if (state.pos + count > state.data.length) {
            throw new CborException(CborException.Code.MALFORMED, "unexpected end of input");
        }
    }

    private static final class ReaderState {
        private final byte[] data;
        private final CborLimits limits;
        private int pos;

        private ReaderState(byte[] data, CborLimits limits) {
            this.data = data;
            this.limits = limits;
        }
    }
}
