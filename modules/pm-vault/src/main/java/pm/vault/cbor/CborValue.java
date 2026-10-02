package pm.vault.cbor;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * SCAFFOLDING by Lane E for §2 contract; Lane D replaces this file.
 *
 * <p>Value tree of the deterministic CBOR subset (ADR 0006 amendment): unsigned ints, byte
 * strings, text strings, arrays, text-keyed maps and booleans only.
 */
public sealed interface CborValue permits CborValue.UInt, CborValue.Bytes, CborValue.Text,
        CborValue.Array, CborValue.MapV, CborValue.Bool {

    /** Unsigned integer; {@code value >= 0}. */
    record UInt(long value) implements CborValue {
    }

    /**
     * Byte string. §2 declares this as a record; Error Prone's {@code ArrayRecordComponent}
     * rejects array record components under {@code -Werror}, so it is a final class with the
     * same constructor and accessor. The array is copied in and out (OBJ06-J, OBJ05-J).
     * Equality is identity, as for a record with an array component.
     */
    final class Bytes implements CborValue {
        private final byte[] content;

        /**
         * Creates a byte string.
         *
         * @param value contents; copied
         */
        public Bytes(byte[] value) {
            this.content = Objects.requireNonNull(value, "value").clone();
        }

        /** Returns a copy of the contents. */
        public byte[] value() {
            return content.clone();
        }

        @Override
        public String toString() {
            return "Bytes[length=" + content.length + "]";
        }
    }

    /** UTF-8 text string. */
    record Text(String value) implements CborValue {
    }

    /** Array of values. */
    record Array(List<CborValue> items) implements CborValue {
        /** Defensive copy (OBJ06-J). */
        public Array {
            items = List.copyOf(items);
        }
    }

    /** Map with text keys only. */
    record MapV(Map<String, CborValue> entries) implements CborValue {
        /** Defensive copy (OBJ06-J). */
        public MapV {
            entries = Map.copyOf(entries);
        }
    }

    /** Boolean. */
    record Bool(boolean value) implements CborValue {
    }
}
