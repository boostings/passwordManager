package pm.browser.webauthn;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small, independent RFC 8949 decoder for tests: it shares no code with
 * {@code pm.vault.cbor}, so encoder bugs cannot cancel out. Major types 0 to 5 and simple
 * true/false only; definite lengths only. Maps keep their encoded key order; integers are
 * {@link Long}, byte strings {@code byte[]}, text {@link String}.
 */
final class TestCbor {
    /** Additional information 24: the argument follows in one byte; below it, it is inline. */
    private static final int ONE_BYTE = 24;
    private final byte[] in;
    private int pos;

    private TestCbor(byte[] in) {
        this.in = in;
    }

    /** Decodes exactly one item; trailing bytes are an error. */
    static Object decode(byte[] data) {
        TestCbor reader = new TestCbor(data);
        Object item = reader.item();
        if (reader.pos != data.length) {
            throw new IllegalArgumentException("trailing bytes");
        }
        return item;
    }

    private Object item() {
        int initial = in[pos++] & 0xFF;
        int major = initial >>> 5;
        long arg = argument(initial & 0x1F);
        return switch (major) {
            case 0 -> arg;
            case 1 -> -1 - arg;
            case 2 -> take((int) arg);
            case 3 -> new String(take((int) arg), StandardCharsets.UTF_8);
            case 4 -> array(arg);
            case 5 -> map(arg);
            default -> simple(initial);
        };
    }

    private List<Object> array(long count) {
        List<Object> items = new ArrayList<>();
        for (long i = 0; i < count; i++) {
            items.add(item());
        }
        return items;
    }

    private Map<Object, Object> map(long count) {
        Map<Object, Object> map = new LinkedHashMap<>();
        for (long i = 0; i < count; i++) {
            Object key = item();
            map.put(key, item());
        }
        return map;
    }

    private static Object simple(int initial) {
        if (initial == 0xF4 || initial == 0xF5) {
            return initial == 0xF5;
        }
        throw new IllegalArgumentException("unsupported initial byte " + initial);
    }

    private long argument(int info) {
        if (info < ONE_BYTE) {
            return info;
        }
        int bytes = switch (info) {
            case 24 -> 1;
            case 25 -> 2;
            case 26 -> 4;
            case 27 -> 8;
            default -> throw new IllegalArgumentException("indefinite or reserved length");
        };
        long value = 0;
        for (int i = 0; i < bytes; i++) {
            value = (value << 8) | (in[pos++] & 0xFF);
        }
        return value;
    }

    private byte[] take(int length) {
        byte[] out = Arrays.copyOfRange(in, pos, pos + length);
        pos += length;
        return out;
    }
}
