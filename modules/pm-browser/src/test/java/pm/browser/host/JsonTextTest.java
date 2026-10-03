package pm.browser.host;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;

/** The strict, bounded JSON codec (SR-303, MSC05-J). */
@Tag("T-FUZZ-NM")
class JsonTextTest {

    @Test
    void parsesEveryValueKindWithAllWhitespace() throws HostException {
        Json v = parse(" \t\r\n{\"o\":{},\"a\":[],\"s\":\"x\",\"t\":true,\"f\":false,\"n\":null,"
                + "\"i\":-12,\"z\":0,\"m\":-0,\"l\":[1, 2 ,3]} \n");
        Json.Obj o = assertInstanceOf(Json.Obj.class, v);
        assertEquals(List.of("o", "a", "s", "t", "f", "n", "i", "z", "m", "l"), List.copyOf(o.names()));
        assertEquals(new Json.Obj(Map.of()), o.get("o"));
        assertEquals(new Json.Arr(List.of()), o.get("a"));
        assertEquals("x", ((Json.Str) o.get("s")).text());
        assertEquals(new Json.Bool(true), o.get("t"));
        assertEquals(new Json.Bool(false), o.get("f"));
        assertSame(Json.Null.NULL, o.get("n"));
        assertEquals(new Json.Num(-12), o.get("i"));
        assertEquals(new Json.Num(0), o.get("z"));
        assertEquals(new Json.Num(0), o.get("m"));
        assertEquals(new Json.Arr(List.of(new Json.Num(1), new Json.Num(2), new Json.Num(3))), o.get("l"));
    }

    @Test
    void decodesEveryEscape() throws HostException {
        Json.Str s = (Json.Str) parse("\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041\\u00e9\\u00E9\\ud83d\\ude00\"");
        assertEquals("\"\\/\b\f\n\r\tA\u00e9\u00e9\ud83d\ude00", s.text());
    }

    @Test
    void refusesMalformedSyntax() {
        for (String bad : List.of(
                "", " ", "x", "{", "[", "{\"a\"}", "{\"a\" 1}", "{\"a\":1;}", "{\"a\":1,}", "{1:2}",
                "[1;2]", "[1,]", "tru", "trux", "nul", "fals", "truex", "1 2", "{} x", "\"abc", "\"a\u0001\"",
                "\"\\x\"", "\"\\u12\"", "\"\\u12g4\"", "\"\\u\u0663\u0663\u0663\u0663\"",
                "\"\\ud83d\"", "\"\\ud83dx\"", "\"\\ud83d\\x\"", "\"\\ud83d\\u0041\"", "\"\\ude00\"",
                "01", "-", "-01", "1.5", "1e3", "+1", "1234567890123456", "\uFEFF{}", "/*c*/{}")) {
            assertMalformed(bad);
        }
        assertMalformed("{\"a\":1,\"a\":2}"); // duplicate names
    }

    @Test
    void acceptsTheLargestValuesAndRefusesOneMore() throws HostException {
        assertEquals(new Json.Num(999_999_999_999_999L), parse("999999999999999"));
        assertEquals(new Json.Num(-999_999_999_999_999L), parse("-999999999999999"));

        String deep = "[".repeat(JsonText.MAX_DEPTH) + "]".repeat(JsonText.MAX_DEPTH);
        assertInstanceOf(Json.Arr.class, parse(deep));
        assertMalformed("[".repeat(JsonText.MAX_DEPTH + 1) + "]".repeat(JsonText.MAX_DEPTH + 1));
        assertMalformed("{\"a\":".repeat(JsonText.MAX_DEPTH + 1) + "1" + "}".repeat(JsonText.MAX_DEPTH + 1));

        assertEquals(JsonText.MAX_MEMBERS, ((Json.Arr) parse(array(JsonText.MAX_MEMBERS))).items().size());
        assertMalformed(array(JsonText.MAX_MEMBERS + 1));
        assertEquals(JsonText.MAX_MEMBERS, ((Json.Obj) parse(object(JsonText.MAX_MEMBERS))).names().size());
        assertMalformed(object(JsonText.MAX_MEMBERS + 1));

        assertEquals(JsonText.MAX_STRING, ((Json.Str) parse("\"" + "a".repeat(JsonText.MAX_STRING) + "\"")).length());
        assertMalformed("\"" + "a".repeat(JsonText.MAX_STRING + 1) + "\"");
        assertMalformed("\"" + "a".repeat(JsonText.MAX_STRING) + "\\n\"");
    }

    @Test
    void writesCompactJsonWithEscapes() {
        Map<String, Json> m = new LinkedHashMap<>();
        m.put("s", Json.Str.of("q\"b\\c\u0001\u001fé"));
        m.put("a", new Json.Arr(List.of(new Json.Num(-5), new Json.Bool(true), new Json.Bool(false), Json.Null.NULL)));
        m.put("e", new Json.Arr(List.of()));
        m.put("o", new Json.Obj(Map.of()));
        m.put("long", Json.Str.of("x".repeat(500)));
        try (SecretBytes out = JsonText.toUtf8(new Json.Obj(m))) {
            String text = out.apply(b -> new String(b, StandardCharsets.UTF_8));
            assertEquals("{\"s\":\"q\\\"b\\\\c\\u0001\\u001fé\",\"a\":[-5,true,false,null],\"e\":[],\"o\":{},"
                    + "\"long\":\"" + "x".repeat(500) + "\"}", text);
        }
    }

    @Test
    void outputParsesBackToTheSameTree() throws HostException {
        Json tree = parse("{\"k\":[\"\\u0000\\u001f\\\"\",{\"n\":[null,1]}]}");
        try (SecretBytes out = JsonText.toUtf8(tree)) {
            assertEquals(tree.toString(), parse(out.apply(b -> new String(b, StandardCharsets.UTF_8))).toString());
        }
    }

    @Test
    void anUnpairedSurrogateInASecretCannotBeWritten() {
        assertThrows(IllegalArgumentException.class, () -> JsonText.toUtf8(
                Json.Str.of(SecretChars.takeOwnership(new char[] {'\ud800'}))));
    }

    @Test
    void anUnpairedSurrogateInPlainTextIsReplaced() throws HostException {
        try (SecretBytes out = JsonText.toUtf8(Json.Str.of("\ud800x\udc00\ud83d\ude00\ud83d"))) {
            out.withBytes(b -> assertEquals("\"\ufffdx\ufffd\ud83d\ude00\ufffd\"",
                    new String(b, java.nio.charset.StandardCharsets.UTF_8)));
        }
    }

    @Test
    void stringsAreWipedAndNeverPrinted() throws HostException {
        Json.Obj o = (Json.Obj) parse("{\"p\":\"hunter2\",\"l\":[\"x\",1,true,null]}");
        Json.Str p = (Json.Str) o.get("p");
        assertEquals("Str[7 chars]", p.toString());
        assertFalse(o.toString().contains("hunter2"));
        o.wipe();
        assertEquals("\0".repeat(7), p.text());
    }

    @Test
    void stringsConvertToAndFromSecrets() throws HostException {
        try (SecretChars in = SecretChars.takeOwnership("pässword".toCharArray());
                SecretBytes utf8 = SecretBytes.copyOf("pässword".getBytes(StandardCharsets.UTF_8));
                SecretBytes bad = SecretBytes.copyOf(new byte[] {(byte) 0xff})) {
            Json.Str a = Json.Str.of(in);
            assertFalse(in.isClosed());
            assertEquals("pässword", a.text());
            assertEquals("pässword", Json.Str.ofUtf8(utf8).text());
            assertEquals(HostException.Code.BAD_UTF8,
                    assertThrows(HostException.class, () -> Json.Str.ofUtf8(bad)).code());
            try (SecretChars back = a.secret()) {
                assertEquals(8, back.length());
            }
        }
    }

    @Test
    void controlCharactersAreDetected() {
        assertFalse(Json.Str.of("plain é").hasControl());
        assertTrue(Json.Str.of("a\u0000").hasControl());
        assertTrue(Json.Str.of("a\u001f").hasControl());
        assertTrue(Json.Str.of("a\u007f").hasControl());
    }

    private static String array(int n) {
        return "[" + "1,".repeat(n - 1) + "1]";
    }

    private static String object(int n) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < n; i++) {
            sb.append(i == 0 ? "" : ",").append("\"k").append(i).append("\":").append(i);
        }
        return sb.append('}').toString();
    }

    static Json parse(String text) throws HostException {
        return JsonText.parse(text.toCharArray());
    }

    private static void assertMalformed(String text) {
        assertEquals(HostException.Code.MALFORMED,
                assertThrows(HostException.class, () -> parse(text), text).code(), text);
    }
}
