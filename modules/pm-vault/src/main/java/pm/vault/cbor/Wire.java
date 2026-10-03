package pm.vault.cbor;

/**
 * Wire-format constants of RFC 8949 section 3 shared by {@link CborWriter} and {@link CborReader}
 * (ADR 0006 Amendment 1). An initial byte is {@code major << 5 | additionalInformation}.
 */
final class Wire {
    /** Unsigned integer. */
    static final int MAJOR_UINT = 0;
    /** Negative integer; outside the supported subset. */
    static final int MAJOR_NEGATIVE = 1;
    /** Byte string. */
    static final int MAJOR_BYTES = 2;
    /** Text string. */
    static final int MAJOR_TEXT = 3;
    /** Array. */
    static final int MAJOR_ARRAY = 4;
    /** Map. */
    static final int MAJOR_MAP = 5;
    /** Simple values and floats; only the booleans are in the supported subset. */
    static final int MAJOR_SIMPLE = 7;
    /** Bits of additional information below the major type. */
    static final int MAJOR_SHIFT = 5;
    /** Mask for the additional information. */
    static final int INFO_MASK = 0x1F;
    /** Additional information 24: the argument follows in one byte. */
    static final int INFO_ONE_BYTE = 24;
    /** Additional information 25: the argument follows in two bytes. */
    static final int INFO_TWO_BYTES = 25;
    /** Additional information 26: the argument follows in four bytes. */
    static final int INFO_FOUR_BYTES = 26;
    /** Additional information 27: the argument follows in eight bytes. */
    static final int INFO_EIGHT_BYTES = 27;
    /** Additional information 31: indefinite length, or the break stop code. */
    static final int INFO_INDEFINITE = 31;
    /** Simple value {@code false}. */
    static final int SIMPLE_FALSE = 20;
    /** Simple value {@code true}. */
    static final int SIMPLE_TRUE = 21;
    /** Mask that reads a byte as an unsigned value. */
    static final int BYTE_MASK = 0xFF;

    private Wire() {
    }
}
