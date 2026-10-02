package pm.vault.cbor;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public final class CborWriter {
    private CborWriter() {}

    public static byte[] encode(CborValue value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeValue(out, value);
        return out.toByteArray();
    }

    private static void writeValue(ByteArrayOutputStream out, CborValue value) {
        if (value instanceof CborValue.UInt u) {
            writeUnsigned(out, 0, u.value());
        } else if (value instanceof CborValue.Bytes b) {
            writeByteString(out, b.value());
        } else if (value instanceof CborValue.Text t) {
            byte[] textBytes = t.value().getBytes(StandardCharsets.UTF_8);
            writeUnsigned(out, 3, textBytes.length);
            out.writeBytes(textBytes);
        } else if (value instanceof CborValue.Array a) {
            writeUnsigned(out, 4, a.items().size());
            for (CborValue item : a.items()) {
                writeValue(out, item);
            }
        } else if (value instanceof CborValue.MapV m) {
            List<Map.Entry<String, CborValue>> entries = new ArrayList<>(m.entries().entrySet());
            entries.sort(Comparator.comparing(
                entry -> CborWriter.encode(new CborValue.Text(entry.getKey())),
                (left, right) -> Arrays.compareUnsigned(left, right)
            ));
            writeUnsigned(out, 5, entries.size());
            for (Map.Entry<String, CborValue> entry : entries) {
                writeValue(out, new CborValue.Text(entry.getKey()));
                writeValue(out, entry.getValue());
            }
        } else if (value instanceof CborValue.Bool b) {
            out.write(b.value() ? 0xF5 : 0xF4);
        } else {
            throw new IllegalArgumentException("Unsupported CBOR value: " + value);
        }
    }

    private static void writeByteString(ByteArrayOutputStream out, byte[] value) {
        writeUnsigned(out, 2, value.length);
        out.writeBytes(value);
    }

    private static void writeUnsigned(ByteArrayOutputStream out, int majorType, long value) {
        long encoded = value;
        if (encoded < 24) {
            out.write((majorType << 5) | (int) encoded);
            return;
        }
        if (encoded < 1 << 8) {
            out.write((majorType << 5) | 24);
            out.write((int) encoded);
            return;
        }
        if (encoded < 1 << 16) {
            out.write((majorType << 5) | 25);
            out.write((int) (encoded >>> 8));
            out.write((int) encoded);
            return;
        }
        if (encoded < (1L << 32)) {
            out.write((majorType << 5) | 26);
            out.write((int) (encoded >>> 24));
            out.write((int) (encoded >>> 16));
            out.write((int) (encoded >>> 8));
            out.write((int) encoded);
            return;
        }
        out.write((majorType << 5) | 27);
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.write((int) ((encoded >>> shift) & 0xFF));
        }
    }
}
