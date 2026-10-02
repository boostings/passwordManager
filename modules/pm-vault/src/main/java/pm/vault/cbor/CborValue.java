package pm.vault.cbor;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import pm.crypto.ConstantTime;

/**
 * Value tree of the deterministic CBOR subset (ADR 0006 amendment): unsigned ints, byte
 * strings, text strings, arrays, text-keyed maps and booleans only.
 */
public sealed interface CborValue permits CborValue.UInt, CborValue.Bytes, CborValue.Text,
        CborValue.Array, CborValue.MapV, CborValue.Bool {

    /**
     * Unsigned integer.
     *
     * @param value non-negative value
     */
    record UInt(long value) implements CborValue {
        /** Rejects negative values (negative ints are outside the subset). */
        public UInt {
            if (value < 0) {
                throw new IllegalArgumentException("NEGATIVE");
            }
        }
    }

    /**
     * Byte string. §2 declares this as a record; Error Prone's {@code ArrayRecordComponent}
     * rejects array record components under {@code -Werror}, so it is a final class with the
     * same constructor and accessor. The array is copied in and out (OBJ06-J, OBJ05-J).
     * Equality compares content in constant time (SR-016).
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

        /**
         * Returns a copy of the contents.
         *
         * @return a fresh copy owned by the caller
         */
        public byte[] value() {
            return content.clone();
        }

        /** Number of bytes, without copying. */
        int length() {
            return content.length;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Bytes other && ConstantTime.equals(content, other.content);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(content);
        }

        @Override
        public String toString() {
            return "Bytes[length=" + content.length + "]";
        }
    }

    /**
     * UTF-8 text string.
     *
     * @param value text
     */
    record Text(String value) implements CborValue {
        /** Null check. */
        public Text {
            Objects.requireNonNull(value, "value");
        }
    }

    /**
     * Array of values.
     *
     * @param items elements; defensively copied (OBJ06-J)
     */
    record Array(List<CborValue> items) implements CborValue {
        /** Defensive copy (OBJ06-J). */
        public Array {
            items = List.copyOf(items);
        }
    }

    /**
     * Map with text keys only.
     *
     * @param entries entries; defensively copied (OBJ06-J)
     */
    record MapV(Map<String, CborValue> entries) implements CborValue {
        /** Defensive copy (OBJ06-J). */
        public MapV {
            entries = Map.copyOf(entries);
        }
    }

    /**
     * Boolean.
     *
     * @param value truth value
     */
    record Bool(boolean value) implements CborValue {
    }
}
