package pm.vault.cbor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.Tuple;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.Size;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Deterministic CBOR subset (ADR 0006 Amendment 1, SR-021): RFC 8949 Appendix A vectors, one
 * rejection per case with its code, model validation, limit symmetry and round-trip properties.
 */
class CborWriterReaderTest {
    private static final HexFormat HEX = HexFormat.of();
    private static final CborLimits HEADER = CborLimits.HEADER;
    private static final int MAX_TREE_DEPTH = 3;
    private static final int MAX_CHILDREN = 4;
    private static final int FIRST_SURROGATE = 0xD800;
    private static final int LAST_SURROGATE = 0xDFFF;

    // ---- RFC 8949 Appendix A, limited to the supported subset ---------------------------------

    static Stream<Arguments> appendixA() {
        return Stream.of(
                arguments("00", uint(0)),
                arguments("01", uint(1)),
                arguments("0a", uint(10)),
                arguments("17", uint(23)),
                arguments("1818", uint(24)),
                arguments("1819", uint(25)),
                arguments("1864", uint(100)),
                arguments("1903e8", uint(1000)),
                arguments("1a000f4240", uint(1_000_000)),
                arguments("1b000000e8d4a51000", uint(1_000_000_000_000L)),
                arguments("f4", new CborValue.Bool(false)),
                arguments("f5", new CborValue.Bool(true)),
                arguments("40", new CborValue.Bytes(new byte[0])),
                arguments("4401020304", new CborValue.Bytes(new byte[] {1, 2, 3, 4})),
                arguments("60", text("")),
                arguments("6161", text("a")),
                arguments("6449455446", text("IETF")),
                arguments("62225c", text("\"\\")),
                arguments("62c3bc", text("ü")),
                arguments("63e6b0b4", text("水")),
                arguments("64f0908591", text("𐅑")),
                arguments("80", array()),
                arguments("83010203", array(uint(1), uint(2), uint(3))),
                arguments("8301820203820405",
                        array(uint(1), array(uint(2), uint(3)), array(uint(4), uint(5)))),
                arguments("98190102030405060708090a0b0c0d0e0f101112131415161718181819", oneToTwentyFive()),
                arguments("a0", new CborValue.MapV(Map.of())),
                arguments("a26161016162820203",
                        new CborValue.MapV(Map.of("a", uint(1), "b", array(uint(2), uint(3))))),
                arguments("826161a161626163", array(text("a"), new CborValue.MapV(Map.of("b", text("c"))))),
                arguments("a56161614161626142616361436164614461656145", new CborValue.MapV(Map.of(
                        "a", text("A"), "b", text("B"), "c", text("C"), "d", text("D"), "e", text("E")))));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("appendixA")
    void encodesAndDecodesRfc8949AppendixAVectors(String hex, CborValue value) throws CborException {
        assertEquals(hex, HEX.formatHex(CborWriter.encode(value)));
        assertEquals(value, CborReader.decode(HEX.parseHex(hex), HEADER));
    }

    // ---- rejections: one case each, asserting the code -----------------------------------------

    static Stream<Arguments> rejected() {
        CborException.Code malformed = CborException.Code.MALFORMED;
        CborException.Code nonCanonical = CborException.Code.NON_CANONICAL;
        CborException.Code limit = CborException.Code.LIMIT;
        return Stream.of(
                arguments("empty input", "", malformed),
                arguments("indefinite byte string with a well-formed body", "5f 41 61 ff", malformed),
                arguments("indefinite text string", "7f 61 61 ff", malformed),
                arguments("indefinite array", "9f 01 ff", malformed),
                arguments("indefinite map", "bf 61 61 01 ff", malformed),
                arguments("break outside a container", "ff", malformed),
                arguments("tag 0", "c0 01", malformed),
                arguments("tag 32 in two bytes", "d8 20 01", malformed),
                arguments("half-precision float", "f9 3c 00", malformed),
                arguments("single-precision float", "fa 3f 80 00 00", malformed),
                arguments("double-precision float", "fb 3f f0 00 00 00 00 00 00", malformed),
                arguments("null", "f6", malformed),
                arguments("undefined", "f7", malformed),
                arguments("simple value 16", "f0", malformed),
                arguments("simple value in two bytes", "f8 20", malformed),
                arguments("negative int -1", "20", malformed),
                arguments("negative int -25", "38 18", malformed),
                arguments("reserved additional information 28", "1c", malformed),
                arguments("integer map key", "a1 01 01", malformed),
                arguments("byte string map key", "a1 41 61 01", malformed),
                arguments("invalid UTF-8", "61 ff", malformed),
                arguments("overlong UTF-8", "62 c0 80", malformed),
                arguments("UTF-8 encoded surrogate", "63 ed a0 80", malformed),
                arguments("truncated UTF-8 sequence", "62 e2 82", malformed),
                arguments("trailing byte", "01 00", malformed),
                arguments("truncated argument", "19 01", malformed),
                arguments("byte string longer than the input", "58 ff 00", malformed),
                arguments("text string longer than the input", "62 61", malformed),
                arguments("array longer than the input", "99 04 00", malformed),
                arguments("map longer than the input", "a2 61 61 01", malformed),

                arguments("non-shortest integer 18 05", "18 05", nonCanonical),
                arguments("non-shortest integer in two bytes", "19 00 ff", nonCanonical),
                arguments("non-shortest integer in four bytes", "1a 00 00 ff ff", nonCanonical),
                arguments("non-shortest integer in eight bytes", "1b 00 00 00 00 ff ff ff ff", nonCanonical),
                arguments("non-shortest byte string length", "58 01 41", nonCanonical),
                arguments("non-shortest text string length", "78 01 61", nonCanonical),
                arguments("non-shortest array length", "98 01 01", nonCanonical),
                arguments("eight-byte array length of zero", "9b 00 00 00 00 00 00 00 00", nonCanonical),
                arguments("non-shortest map length", "b8 01 61 61 01", nonCanonical),
                arguments("non-shortest map key length", "a1 78 01 61 01", nonCanonical),
                arguments("unsorted map", "a2 61 62 01 61 61 02", nonCanonical),
                arguments("map sorted as text, not as encoded bytes", "a2 62 61 61 01 61 62 02", nonCanonical),
                arguments("duplicate key", "a2 61 61 01 61 61 02", nonCanonical),

                arguments("depth 17: integer inside 17 arrays", "81".repeat(17) + "01", limit),
                arguments("depth 17: empty array inside 16 arrays", "81".repeat(16) + "80", limit),
                arguments("depth 17: empty map inside 16 arrays", "81".repeat(16) + "a0", limit),
                arguments("byte string above maxStringBytes", "59 10 01", limit),
                arguments("text string above maxStringBytes", "79 10 01", limit),
                arguments("array above maxItems", "99 04 01", limit),
                arguments("map above maxItems", "b9 04 01", limit),
                arguments("array length 2^64-1", "9b ff ff ff ff ff ff ff ff", limit),
                arguments("array length 2^63 + 2^31-1", "9b 80 00 00 00 7f ff ff ff", limit),
                arguments("array length 2^63 + 2^26", "9b 80 00 00 00 04 00 00 00", limit),
                arguments("array length 2^63", "9b 80 00 00 00 00 00 00 00", limit),
                arguments("map length 2^64-1", "bb ff ff ff ff ff ff ff ff", limit),
                arguments("map length 2^63", "bb 80 00 00 00 00 00 00 00", limit),
                arguments("byte string length 2^64-1", "5b ff ff ff ff ff ff ff ff", limit),
                arguments("text string length 2^63", "7b 80 00 00 00 00 00 00 00", limit),
                arguments("integer 2^64-1", "1b ff ff ff ff ff ff ff ff", limit),
                arguments("integer 2^63", "1b 80 00 00 00 00 00 00 00", limit));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("rejected")
    void rejectsWithCode(String name, String hex, CborException.Code expected) {
        byte[] input = bytes(hex);
        CborException e = assertThrows(CborException.class, () -> CborReader.decode(input, HEADER), name);
        assertEquals(expected, e.code(), name);
    }

    @Test
    void acceptsSixteenNestedContainersAndTheLargestInteger() throws CborException {
        CborValue nested = CborReader.decode(bytes("81".repeat(16) + "01"), HEADER);
        assertEquals(bytes("81".repeat(16) + "01").length, CborWriter.encode(nested, HEADER).length);
        assertEquals(uint(Long.MAX_VALUE), CborReader.decode(bytes("1b 7f ff ff ff ff ff ff ff"), HEADER));
    }

    @Test
    void itemLimitIsARunningTotalAcrossContainers() throws CborException {
        // 1 outer array + 31 inner arrays + 31 * 32 integers = 1024 items: exactly the limit.
        CborValue atLimit = grid(31, 32);
        byte[] encoded = CborWriter.encode(atLimit, HEADER);
        assertEquals(atLimit, CborReader.decode(encoded, HEADER));

        // 1 + 32 + 32 * 31 = 1025 items, although no single container holds more than 32.
        CborValue overLimit = grid(32, 31);
        byte[] unbounded = CborWriter.encode(overLimit);
        CborException e = assertThrows(CborException.class, () -> CborReader.decode(unbounded, HEADER));
        assertEquals(CborException.Code.LIMIT, e.code());
        assertThrows(IllegalArgumentException.class, () -> CborWriter.encode(overLimit, HEADER));
    }

    @Test
    void mapKeysCountTowardsTheItemLimit() throws CborException {
        CborLimits three = new CborLimits(16, 3, 4_096, 4_096);
        CborLimits two = new CborLimits(16, 2, 4_096, 4_096);
        CborValue map = new CborValue.MapV(Map.of("a", uint(1)));
        byte[] encoded = CborWriter.encode(map, three);
        assertEquals(map, CborReader.decode(encoded, three));
        assertEquals(CborException.Code.LIMIT,
                assertThrows(CborException.class, () -> CborReader.decode(encoded, two)).code());
        assertThrows(IllegalArgumentException.class, () -> CborWriter.encode(map, two));
    }

    @Test
    void rejectsInputLongerThanMaxTotalBytes() {
        CborLimits four = new CborLimits(16, 1_024, 4_096, 4);
        CborException e = assertThrows(CborException.class, () -> CborReader.decode(bytes("84 01 02 03 04"), four));
        assertEquals(CborException.Code.LIMIT, e.code());
        assertThrows(IllegalArgumentException.class,
                () -> CborWriter.encode(array(uint(1), uint(2), uint(3), uint(4)), four));
    }

    @Test
    void acceptsStringsOfExactlyMaxStringBytes() throws CborException {
        CborValue.Bytes atLimit = new CborValue.Bytes(new byte[HEADER.maxStringBytes()]);
        assertEquals(atLimit, CborReader.decode(CborWriter.encode(atLimit, HEADER), HEADER));
        CborValue.Bytes over = new CborValue.Bytes(new byte[HEADER.maxStringBytes() + 1]);
        assertThrows(IllegalArgumentException.class, () -> CborWriter.encode(over, HEADER));
        CborValue longKey = new CborValue.MapV(Map.of("k".repeat(HEADER.maxStringBytes() + 1), uint(1)));
        assertThrows(IllegalArgumentException.class, () -> CborWriter.encode(longKey, HEADER));
    }

    @Test
    void writerRefusesASeventeenthContainerLevel() {
        CborValue sixteen = nest(uint(1), 16);
        assertEquals("81".repeat(16) + "01", HEX.formatHex(CborWriter.encode(sixteen, HEADER)));
        assertThrows(IllegalArgumentException.class, () -> CborWriter.encode(nest(uint(1), 17), HEADER));
        assertThrows(IllegalArgumentException.class, () -> CborWriter.encode(nest(array(), 16), HEADER));
    }

    @Test
    void limitsMustBePositive() {
        assertThrows(IllegalArgumentException.class, () -> new CborLimits(0, 1, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new CborLimits(1, 0, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> new CborLimits(1, 1, -1, 1));
        assertThrows(IllegalArgumentException.class, () -> new CborLimits(1, 1, 1, 0));
        assertEquals(0, new CborLimits(1, 1, 0, 1).maxStringBytes());
    }

    // ---- writer --------------------------------------------------------------------------------

    @Test
    void writerSortsKeysByEncodedBytesNotByText() throws CborException {
        Map<String, CborValue> entries = new LinkedHashMap<>();
        entries.put("a".repeat(24), uint(5));
        entries.put("😀", uint(2));
        entries.put("z".repeat(23), uint(6));
        entries.put("￿", uint(1));
        entries.put("aa", uint(4));
        entries.put("b", uint(3));
        String expected = "a6"
                + "6162" + "03"
                + "626161" + "04"
                + "63efbfbf" + "01"
                + "64f09f9880" + "02"
                + "77" + "7a".repeat(23) + "06"
                + "7818" + "61".repeat(24) + "05";

        byte[] encoded = CborWriter.encode(new CborValue.MapV(entries));

        assertEquals(expected, HEX.formatHex(encoded));
        assertEquals(new CborValue.MapV(entries), CborReader.decode(encoded, HEADER));
    }

    @Test
    void writerUsesTheShortestHeadAtEveryWidthBoundary() {
        assertEquals("17", HEX.formatHex(CborWriter.encode(uint(23))));
        assertEquals("1818", HEX.formatHex(CborWriter.encode(uint(24))));
        assertEquals("18ff", HEX.formatHex(CborWriter.encode(uint(255))));
        assertEquals("190100", HEX.formatHex(CborWriter.encode(uint(256))));
        assertEquals("19ffff", HEX.formatHex(CborWriter.encode(uint(65_535))));
        assertEquals("1a00010000", HEX.formatHex(CborWriter.encode(uint(65_536))));
        assertEquals("1affffffff", HEX.formatHex(CborWriter.encode(uint(4_294_967_295L))));
        assertEquals("1b0000000100000000", HEX.formatHex(CborWriter.encode(uint(4_294_967_296L))));
        assertEquals("1b7fffffffffffffff", HEX.formatHex(CborWriter.encode(uint(Long.MAX_VALUE))));
        assertEquals("7818" + "61".repeat(24), HEX.formatHex(CborWriter.encode(text("a".repeat(24)))));
        assertEquals("590100", HEX.formatHex(CborWriter.encode(new CborValue.Bytes(new byte[256]))).substring(0, 6));
    }

    @Test
    void encodedKeyOrderComparesBytesAsUnsigned() {
        assertTrue(CborWriter.compareEncodedKeys(new byte[] {0x7f}, new byte[] {(byte) 0x80}) < 0);
        assertTrue(CborWriter.compareEncodedKeys(new byte[] {(byte) 0xff}, new byte[] {0x00}) > 0);
        assertTrue(CborWriter.compareEncodedKeys(new byte[] {1}, new byte[] {1, 0}) < 0);
        assertEquals(0, CborWriter.compareEncodedKeys(new byte[] {1, 2}, new byte[] {1, 2}));
    }

    // ---- model ---------------------------------------------------------------------------------

    @Test
    void uintRejectsNegativeValues() {
        assertThrows(IllegalArgumentException.class, () -> new CborValue.UInt(-1));
        assertThrows(IllegalArgumentException.class, () -> new CborValue.UInt(Long.MIN_VALUE));
    }

    @Test
    void textAndMapKeysRejectUnpairedSurrogates() {
        assertThrows(IllegalArgumentException.class, () -> new CborValue.Text("a\uD800b"));
        assertThrows(IllegalArgumentException.class, () -> new CborValue.Text("\uDC00"));
        assertThrows(IllegalArgumentException.class, () -> new CborValue.Text("\uD83D"));
        assertThrows(IllegalArgumentException.class, () -> new CborValue.MapV(Map.of("\uD800", uint(1))));
        assertEquals("😀", new CborValue.Text("😀").value());
    }

    @Test
    void valuesRejectNulls() {
        assertThrows(NullPointerException.class, () -> new CborValue.Text(null));
        assertThrows(NullPointerException.class, () -> new CborValue.Bytes(null));
        assertThrows(NullPointerException.class, () -> new CborValue.Array(null));
        assertThrows(NullPointerException.class, () -> new CborValue.MapV(null));
        assertThrows(NullPointerException.class, () -> new CborValue.Array(Arrays.asList(uint(1), null)));
        assertThrows(NullPointerException.class, () -> CborWriter.encode(null));
        assertThrows(NullPointerException.class, () -> CborReader.decode(null, HEADER));
    }

    @Test
    void bytesCopiesItsArrayInAndOut() {
        byte[] source = {1, 2, 3};
        CborValue.Bytes value = new CborValue.Bytes(source);
        source[0] = 9;
        value.value()[1] = 9;
        assertArrayEquals(new byte[] {1, 2, 3}, value.value());
        assertEquals(3, value.length());
    }

    @Test
    void bytesComparesByContentAndHidesItFromToStringAndHashCode() {
        CborValue.Bytes left = new CborValue.Bytes(new byte[] {1, 2, 3});
        CborValue.Bytes same = new CborValue.Bytes(new byte[] {1, 2, 3});
        CborValue.Bytes other = new CborValue.Bytes(new byte[] {1, 2, 4});
        assertEquals(left, same);
        assertEquals(left.hashCode(), same.hashCode());
        assertNotEquals(left, other);
        assertNotEquals(left, new CborValue.Bytes(new byte[] {1, 2}));
        assertNotEquals(left, text("abc"));
        assertEquals(left.hashCode(), other.hashCode());
        assertEquals("Bytes[3 bytes]", left.toString());
    }

    @Test
    void wipeZeroFillsEveryByteStringInATree() {
        CborValue.Bytes inArray = new CborValue.Bytes(new byte[] {1, 2});
        CborValue.Bytes inMap = new CborValue.Bytes(new byte[] {3});
        CborValue tree = array(uint(7), inArray, new CborValue.MapV(Map.of("k", inMap)), text("t"));

        tree.wipe();

        assertArrayEquals(new byte[2], inArray.value());
        assertArrayEquals(new byte[1], inMap.value());
    }

    @Test
    void containersAreUnmodifiableCopies() {
        List<CborValue> items = new ArrayList<>(List.of(uint(1)));
        Map<String, CborValue> entries = new LinkedHashMap<>(Map.of("a", uint(1)));
        CborValue.Array array = new CborValue.Array(items);
        CborValue.MapV map = new CborValue.MapV(entries);
        items.add(uint(2));
        entries.put("b", uint(2));

        assertEquals(1, array.items().size());
        assertEquals(1, map.entries().size());
        assertThrows(UnsupportedOperationException.class, () -> array.items().add(uint(3)));
        assertThrows(UnsupportedOperationException.class, () -> map.entries().put("c", uint(3)));
    }

    @Test
    void wellFormednessCheckAcceptsPairsOnly() {
        assertTrue(CborValue.Text.isWellFormed(""));
        assertTrue(CborValue.Text.isWellFormed("a😀b"));
        assertFalse(CborValue.Text.isWellFormed("\uDE00\uD83D"));
        assertFalse(CborValue.Text.isWellFormed("a\uD83D"));
    }

    // ---- properties ----------------------------------------------------------------------------

    @Property(tries = 500)
    void decodeInvertsEncode(@ForAll("trees") CborValue value) throws CborException {
        byte[] encoded = CborWriter.encode(value);

        CborValue decoded = CborReader.decode(encoded, CborLimits.PAYLOAD);

        assertEquals(value, decoded);
        assertArrayEquals(encoded, CborWriter.encode(decoded, CborLimits.PAYLOAD));
    }

    @Property(tries = 300)
    void everyStrictPrefixOfAnEncodingIsRejected(@ForAll("trees") CborValue value,
                                                 @ForAll @IntRange(min = 0, max = 100_000) int seed) {
        byte[] encoded = CborWriter.encode(value);
        byte[] prefix = Arrays.copyOf(encoded, seed % encoded.length);

        assertThrows(CborException.class, () -> CborReader.decode(prefix, CborLimits.PAYLOAD));
    }

    @Property(tries = 2000)
    void arbitraryBytesAreDecodedOrRejectedWithCborException(@ForAll @Size(max = 48) byte[] input) {
        try {
            CborValue decoded = CborReader.decode(input, HEADER);
            assertArrayEquals(input, CborWriter.encode(decoded, HEADER));
        } catch (CborException expected) {
            assertTrue(expected.code() != null);
        }
    }

    @Property(tries = 1000)
    void aCorruptedEncodingIsDecodedCanonicallyOrRejectedWithCborException(
            @ForAll("trees") CborValue value,
            @ForAll @IntRange(min = 0, max = 100_000) int seed,
            @ForAll byte replacement) {
        byte[] mutated = CborWriter.encode(value);
        mutated[seed % mutated.length] = replacement;
        try {
            CborValue decoded = CborReader.decode(mutated, CborLimits.PAYLOAD);
            assertArrayEquals(mutated, CborWriter.encode(decoded, CborLimits.PAYLOAD));
        } catch (CborException expected) {
            assertTrue(expected.code() != null);
        }
    }

    @Provide
    Arbitrary<CborValue> trees() {
        return tree(MAX_TREE_DEPTH);
    }

    private static Arbitrary<CborValue> tree(int depth) {
        Arbitrary<CborValue> leaf = Arbitraries.oneOf(List.of(uints(), byteStrings(), texts(), bools()));
        if (depth == 0) {
            return leaf;
        }
        Arbitrary<CborValue> child = Arbitraries.lazy(() -> tree(depth - 1));
        Arbitrary<CborValue> arrays = child.list().ofMaxSize(MAX_CHILDREN).map(CborValue.Array::new);
        Arbitrary<CborValue> maps =
                Arbitraries.maps(strings(), child).ofMaxSize(MAX_CHILDREN).map(CborValue.MapV::new);
        return Arbitraries.frequencyOf(List.of(Tuple.of(4, leaf), Tuple.of(1, arrays), Tuple.of(1, maps)));
    }

    private static Arbitrary<CborValue> uints() {
        Arbitrary<Long> boundaries = Arbitraries.of(
                0L, 23L, 24L, 255L, 256L, 65_535L, 65_536L, 4_294_967_295L, 4_294_967_296L, Long.MAX_VALUE);
        Arbitrary<Long> any = Arbitraries.longs().between(0, Long.MAX_VALUE);
        return Arbitraries.oneOf(List.of(boundaries, any)).map(CborValue.UInt::new);
    }

    private static Arbitrary<CborValue> byteStrings() {
        return Arbitraries.bytes().array(byte[].class).ofMaxSize(300).map(CborValue.Bytes::new);
    }

    private static Arbitrary<CborValue> texts() {
        return strings().map(CborValue.Text::new);
    }

    private static Arbitrary<CborValue> bools() {
        return Arbitraries.of(true, false).map(CborValue.Bool::new);
    }

    /** Well-formed strings over all of Unicode, including supplementary characters. */
    private static Arbitrary<String> strings() {
        return Arbitraries.integers().between(0, Character.MAX_CODE_POINT)
                .filter(codePoint -> codePoint < FIRST_SURROGATE || codePoint > LAST_SURROGATE)
                .list().ofMaxSize(30)
                .map(codePoints -> {
                    StringBuilder text = new StringBuilder();
                    codePoints.forEach(text::appendCodePoint);
                    return text.toString();
                });
    }

    // ---- helpers -------------------------------------------------------------------------------

    private static byte[] bytes(String hex) {
        return HEX.parseHex(hex.replace(" ", ""));
    }

    private static CborValue uint(long value) {
        return new CborValue.UInt(value);
    }

    private static CborValue text(String value) {
        return new CborValue.Text(value);
    }

    private static CborValue array(CborValue... items) {
        return new CborValue.Array(List.of(items));
    }

    private static CborValue oneToTwentyFive() {
        List<CborValue> items = new ArrayList<>();
        for (int i = 1; i <= 25; i++) {
            items.add(uint(i));
        }
        return new CborValue.Array(items);
    }

    /** {@code outer} arrays of {@code inner} integers each, inside one array. */
    private static CborValue grid(int outer, int inner) {
        List<CborValue> rows = new ArrayList<>();
        for (int i = 0; i < outer; i++) {
            List<CborValue> row = new ArrayList<>();
            for (int j = 0; j < inner; j++) {
                row.add(uint(j));
            }
            rows.add(new CborValue.Array(row));
        }
        return new CborValue.Array(rows);
    }

    /** Wraps {@code value} in {@code levels} single-element arrays. */
    private static CborValue nest(CborValue value, int levels) {
        CborValue nested = value;
        for (int i = 0; i < levels; i++) {
            nested = new CborValue.Array(List.of(nested));
        }
        return nested;
    }
}
