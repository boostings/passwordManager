package pm.vault.cbor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class CborWriterReaderTest {
    private static final HexFormat HEX = HexFormat.of();
    private static final int MAX_DEPTH = 16;

    @Test
    void roundTripsSimpleValues() throws CborException {
        CborValue value = new CborValue.MapV(Map.of(
            "a", new CborValue.UInt(10L),
            "b", new CborValue.Array(List.of(new CborValue.Text("x"), new CborValue.Bool(true))),
            "c", new CborValue.Bytes(new byte[] {1, 2, 3})
        ));

        byte[] encoded = CborWriter.encode(value);
        CborValue decoded = CborReader.decode(encoded, CborLimits.HEADER);

        assertEquals(value, decoded);
    }

    /** RFC 8949 Appendix A vectors within the supported subset. */
    @ParameterizedTest
    @CsvSource({
        "00, 0", "17, 23", "1818, 24", "1903e8, 1000", "1a000f4240, 1000000",
        "1b000000e8d4a51000, 1000000000000"
    })
    void encodesRfcUnsignedVectors(String hex, long value) throws CborException {
        assertArrayEquals(HEX.parseHex(hex), CborWriter.encode(new CborValue.UInt(value)));
        assertEquals(new CborValue.UInt(value), CborReader.decode(HEX.parseHex(hex), CborLimits.HEADER));
    }

    @Test
    void encodesRfcStructuredVectors() {
        assertArrayEquals(HEX.parseHex("6449455446"), CborWriter.encode(new CborValue.Text("IETF")));
        assertArrayEquals(HEX.parseHex("4401020304"),
                CborWriter.encode(new CborValue.Bytes(new byte[] {1, 2, 3, 4})));
        assertArrayEquals(HEX.parseHex("f5"), CborWriter.encode(new CborValue.Bool(true)));
        assertArrayEquals(HEX.parseHex("a26161016162820203"), CborWriter.encode(new CborValue.MapV(Map.of(
                "b", new CborValue.Array(List.of(new CborValue.UInt(2), new CborValue.UInt(3))),
                "a", new CborValue.UInt(1)))));
    }

    @Test
    void sortsKeysByEncodedForm() {
        // Shorter encoded keys sort first (RFC 8949 §4.2.1), so "z" precedes "aa".
        assertArrayEquals(HEX.parseHex("a2617a0062616101"), CborWriter.encode(new CborValue.MapV(Map.of(
                "aa", new CborValue.UInt(1), "z", new CborValue.UInt(0)))));
    }

    @ParameterizedTest
    @CsvSource({
        "5f, MALFORMED",                  // indefinite length
        "c000, MALFORMED",                // tag
        "f93c00, MALFORMED",              // half float
        "20, MALFORMED",                  // negative int
        "1805, NON_CANONICAL",            // non-shortest int
        "5801ff, NON_CANONICAL",          // non-shortest length
        "a2616201616101, NON_CANONICAL",  // unsorted keys
        "a2616101616102, NON_CANONICAL",  // duplicate key
        "5a7fffffff, LIMIT",              // overlong length
        "0000, MALFORMED",                // trailing byte
        "62c328, MALFORMED",              // invalid UTF-8
        "a10101, MALFORMED"               // non-text key
    })
    void rejectsOutsideTheSubset(String hex, CborException.Code code) {
        CborException e = assertThrows(CborException.class,
                () -> CborReader.decode(HEX.parseHex(hex), CborLimits.HEADER));
        assertEquals(code, e.code());
        assertEquals(code.name(), e.getMessage());
    }

    @Test
    void rejectsDepthBeyondTheLimit() {
        byte[] nested = new byte[MAX_DEPTH + 2];
        java.util.Arrays.fill(nested, (byte) 0x81); // [[[...
        nested[nested.length - 1] = 0x00;
        CborException e = assertThrows(CborException.class,
                () -> CborReader.decode(nested, CborLimits.HEADER));
        assertEquals(CborException.Code.LIMIT, e.code());
    }

    @Test
    void rejectsMoreItemsThanTheLimit() {
        CborLimits tiny = new CborLimits(MAX_DEPTH, 2, 16, 64);
        CborException e = assertThrows(CborException.class,
                () -> CborReader.decode(HEX.parseHex("83000000"), tiny));
        assertEquals(CborException.Code.LIMIT, e.code());
    }
}
