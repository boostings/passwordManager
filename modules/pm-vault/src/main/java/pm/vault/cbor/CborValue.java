package pm.vault.cbor;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import pm.crypto.ConstantTime;

/**
 * A data item of the deterministic CBOR subset the vault uses (ADR 0006 Amendment 1): unsigned
 * integers, byte strings, text strings, arrays, maps with text keys, and booleans.
 *
 * <p>Every value is validated when it is built (MET00-J) and holds defensive, unmodifiable copies
 * of what it was given (OBJ06-J, OBJ13-J). So {@link CborWriter} can encode any {@code CborValue},
 * and {@link CborReader} decodes that encoding to an equal value.
 */
public sealed interface CborValue permits CborValue.UInt, CborValue.Bytes, CborValue.Text,
        CborValue.Array, CborValue.MapV, CborValue.Bool {

    /**
     * Zero-fills every byte string reachable from this value. Byte strings may carry secrets, so
     * codecs call this once a tree has been written or read. Best effort only: the JVM may already
     * have copied the arrays (ADR 0008, risk R-003).
     */
    default void wipe() {
        // Scalars other than byte strings hold nothing to clear.
    }

    /**
     * Unsigned integer, major type 0.
     *
     * @param value the number, 0 to {@link Long#MAX_VALUE}
     */
    record UInt(long value) implements CborValue {
        /**
         * Validates the range.
         *
         * @throws IllegalArgumentException if {@code value} is negative
         */
        public UInt {
            if (value < 0) {
                throw new IllegalArgumentException("uint must not be negative");
            }
        }
    }

    /**
     * Byte string, major type 2. Copies the array on the way in and on the way out. Equality
     * compares content through {@link ConstantTime#equals} (SR-016), and neither {@link #hashCode}
     * nor {@link #toString} depends on the content, because the bytes may be a secret.
     *
     * @param value the bytes
     */
    @SuppressWarnings("ArrayRecordComponent") // frozen contract (sprint plan section 2 D); copied in and out below
    record Bytes(byte[] value) implements CborValue {
        /** Stores a copy of {@code value}. */
        public Bytes {
            value = Objects.requireNonNull(value, "value").clone();
        }

        /** Returns a copy of the bytes; the caller owns it and should zero it after use. */
        @Override
        public byte[] value() {
            return value.clone();
        }

        /** Returns the number of bytes. */
        public int length() {
            return value.length;
        }

        /**
         * Copies the bytes into {@code target} starting at {@code offset}, without an intermediate
         * array.
         */
        public void copyInto(byte[] target, int offset) {
            System.arraycopy(value, 0, target, offset, value.length);
        }

        @Override
        public void wipe() {
            Arrays.fill(value, (byte) 0);
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Bytes other && ConstantTime.equals(value, other.value);
        }

        @Override
        public int hashCode() {
            return value.length;
        }

        @Override
        public String toString() {
            return "Bytes[" + value.length + " bytes]";
        }
    }

    /**
     * Text string, major type 3.
     *
     * @param value well-formed UTF-16 text
     */
    record Text(String value) implements CborValue {
        /**
         * Validates the text.
         *
         * @throws IllegalArgumentException if {@code value} holds an unpaired surrogate, which has
         *     no UTF-8 encoding
         */
        public Text {
            Objects.requireNonNull(value, "value");
            if (!isWellFormed(value)) {
                throw new IllegalArgumentException("text is not well-formed UTF-16");
            }
        }

        /**
         * Returns whether {@code text} can be encoded as UTF-8 without loss, that is, whether every
         * surrogate in it is part of a high-low pair.
         */
        public static boolean isWellFormed(String text) {
            int length = text.length();
            int i = 0;
            while (i < length) {
                char c = text.charAt(i);
                if (Character.isHighSurrogate(c)) {
                    if (i + 1 >= length || !Character.isLowSurrogate(text.charAt(i + 1))) {
                        return false;
                    }
                    i += 2;
                } else if (Character.isLowSurrogate(c)) {
                    return false;
                } else {
                    i++;
                }
            }
            return true;
        }
    }

    /**
     * Array, major type 4.
     *
     * @param items the elements, in order
     */
    record Array(List<CborValue> items) implements CborValue {
        /** Stores an unmodifiable copy of {@code items}; null elements are refused. */
        public Array {
            items = List.copyOf(items);
        }

        @Override
        public void wipe() {
            items.forEach(CborValue::wipe);
        }
    }

    /**
     * Map with text keys, major type 5. The entry order is irrelevant: the writer sorts keys into
     * the deterministic order.
     *
     * @param entries the entries
     */
    record MapV(Map<String, CborValue> entries) implements CborValue {
        /**
         * Stores an unmodifiable copy of {@code entries}; null keys and values are refused.
         *
         * @throws IllegalArgumentException if a key is not well-formed UTF-16
         */
        public MapV {
            entries = Map.copyOf(entries);
            if (!entries.keySet().stream().allMatch(Text::isWellFormed)) {
                throw new IllegalArgumentException("map key is not well-formed UTF-16");
            }
        }

        @Override
        public void wipe() {
            entries.values().forEach(CborValue::wipe);
        }
    }

    /**
     * Boolean, simple values 20 and 21.
     *
     * @param value the boolean
     */
    record Bool(boolean value) implements CborValue {}
}
