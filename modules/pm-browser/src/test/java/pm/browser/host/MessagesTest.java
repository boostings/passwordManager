package pm.browser.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** The message schema: exact key sets, exact types, bounded values (SR-303). */
@Tag("T-EXT-05")
class MessagesTest {
    private static final String ENTRY = "0f8b6c1e-2a3d-4e5f-8a9b-0c1d2e3f4a5b";
    private static final String POLICY = "{\"length\":20,\"lower\":true,\"upper\":true,\"digits\":true,\"symbols\":false}";

    @Test
    void decodesEveryRequestType() throws HostException {
        assertEquals(new Request.Hello("h1"), decode("{\"type\":\"hello\",\"id\":\"h1\",\"version\":1}"));
        assertEquals(new Request.Lookup("a-B_9", "https://example.com"),
                decode("{\"id\":\"a-B_9\",\"type\":\"lookup\",\"origin\":\"https://example.com\"}"));
        assertEquals(new Request.Fill("f", "https://example.com", UUID.fromString(ENTRY)),
                decode("{\"type\":\"fill\",\"id\":\"f\",\"origin\":\"https://example.com\",\"entry\":\"" + ENTRY + "\"}"));
        assertEquals(new Request.Generate("g", "https://example.com", "", new Request.Policy(20, true, true, true, false)),
                decode("{\"type\":\"generate\",\"id\":\"g\",\"origin\":\"https://example.com\",\"username\":\"\",\"policy\":"
                        + POLICY + "}"));
        Request.Save save = (Request.Save) decode(
                "{\"type\":\"save\",\"id\":\"s\",\"origin\":\"https://example.com\",\"username\":\"\",\"password\":\"pa\\u0000ss\"}");
        try (save) {
            assertEquals("", save.username());
            assertEquals(5, save.password().length());
        }
        assertTrue(save.password().isClosed());
    }

    @Test
    void theFrameBodyIsZeroedAfterDecoding() throws HostException {
        byte[] body = "{\"type\":\"hello\",\"id\":\"h\",\"version\":1}".getBytes(StandardCharsets.UTF_8);
        Messages.decode(body);
        assertArrayEquals(new byte[body.length], body);
        byte[] bad = {(byte) 0xff};
        assertEquals(HostException.Code.BAD_UTF8, assertThrows(HostException.class, () -> Messages.decode(bad)).code());
        assertArrayEquals(new byte[1], bad);
    }

    @Test
    void unknownExtraAndMissingKeysAreRefused() {
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"hello\",\"id\":\"h\",\"version\":1,\"x\":1}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"hello\",\"id\":\"h\"}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"lookup\",\"id\":\"h\"}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"lookup\",\"id\":\"h\",\"origin\":\"o\",\"entry\":\"" + ENTRY + "\"}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"fill\",\"id\":\"h\",\"origin\":\"o\"}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"save\",\"id\":\"h\",\"origin\":\"o\",\"password\":\"p\"}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"generate\",\"id\":\"h\",\"origin\":\"o\"}");
        // generate stores what it fills, so the username member is required (it may be empty)
        assertCode(HostException.Code.BAD_FIELD,
                "{\"type\":\"generate\",\"id\":\"g\",\"origin\":\"https://example.com\",\"policy\":" + POLICY + "}");
        assertCode(HostException.Code.BAD_FIELD, generate(POLICY).replace("\"username\":\"\"", "\"username\":5"));
        assertCode(HostException.Code.BAD_FIELD, generate(POLICY).replace("\"username\":\"\"", "\"username\":\"a\\u0007\""));
        assertCode(HostException.Code.BAD_FIELD, generate("{\"length\":20,\"lower\":true,\"upper\":true,\"digits\":true}"));
        assertCode(HostException.Code.BAD_FIELD, generate(POLICY.replace("}", ",\"extra\":true}")));
        assertCode(HostException.Code.BAD_FIELD, "{\"id\":\"h\",\"version\":1}");
    }

    @Test
    void wrongTypesAreRefused() {
        assertCode(HostException.Code.BAD_FIELD, "[]");
        assertCode(HostException.Code.BAD_FIELD, "\"hello\"");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":1,\"id\":\"h\",\"version\":1}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"hello\",\"id\":7,\"version\":1}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"hello\",\"id\":\"h\",\"version\":\"1\"}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"lookup\",\"id\":\"h\",\"origin\":null}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"fill\",\"id\":\"h\",\"origin\":\"o\",\"entry\":1}");
        assertCode(HostException.Code.BAD_FIELD,
                "{\"type\":\"save\",\"id\":\"h\",\"origin\":\"o\",\"username\":false,\"password\":\"p\"}");
        assertCode(HostException.Code.BAD_FIELD,
                "{\"type\":\"save\",\"id\":\"h\",\"origin\":\"o\",\"username\":\"u\",\"password\":[]}");
        assertCode(HostException.Code.BAD_FIELD, generate("[]"));
        assertCode(HostException.Code.BAD_FIELD, generate(POLICY.replace("20", "\"20\"")));
        assertCode(HostException.Code.BAD_FIELD, generate(POLICY.replace("\"lower\":true", "\"lower\":1")));
    }

    @Test
    void outOfRangeValuesAreRefused() {
        assertCode(HostException.Code.VERSION, "{\"type\":\"hello\",\"id\":\"h\",\"version\":2}");
        assertCode(HostException.Code.UNKNOWN_TYPE, "{\"type\":\"reveal\",\"id\":\"h\"}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"\",\"id\":\"h\"}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"hello-hello-hello-x\",\"id\":\"h\"}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"hel\\nlo\",\"id\":\"h\"}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"hello\",\"id\":\"\",\"version\":1}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"hello\",\"id\":\"a b\",\"version\":1}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"hello\",\"id\":\"" + "i".repeat(65) + "\",\"version\":1}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"lookup\",\"id\":\"h\",\"origin\":\"https://a b\"}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"lookup\",\"id\":\"h\",\"origin\":\"\"}");
        assertCode(HostException.Code.BAD_FIELD,
                "{\"type\":\"lookup\",\"id\":\"h\",\"origin\":\"" + "o".repeat(Messages.MAX_ORIGIN + 1) + "\"}");
        assertCode(HostException.Code.BAD_FIELD,
                "{\"type\":\"fill\",\"id\":\"h\",\"origin\":\"o\",\"entry\":\"" + ENTRY.toUpperCase(java.util.Locale.ROOT) + "\"}");
        assertCode(HostException.Code.BAD_FIELD,
                "{\"type\":\"save\",\"id\":\"h\",\"origin\":\"o\",\"username\":\"u\\u0007\",\"password\":\"p\"}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"save\",\"id\":\"h\",\"origin\":\"o\",\"username\":\""
                + "u".repeat(Messages.MAX_USERNAME + 1) + "\",\"password\":\"p\"}");
        assertCode(HostException.Code.BAD_FIELD,
                "{\"type\":\"save\",\"id\":\"h\",\"origin\":\"o\",\"username\":\"u\",\"password\":\"\"}");
        assertCode(HostException.Code.BAD_FIELD, "{\"type\":\"save\",\"id\":\"h\",\"origin\":\"o\",\"username\":\"u\",\"password\":\""
                + "p".repeat(Messages.MAX_PASSWORD + 1) + "\"}");
        assertCode(HostException.Code.BAD_FIELD, generate(POLICY.replace("20", "7")));
        assertCode(HostException.Code.BAD_FIELD, generate(POLICY.replace("20", "129")));
        assertCode(HostException.Code.BAD_FIELD,
                generate("{\"length\":20,\"lower\":false,\"upper\":false,\"digits\":false,\"symbols\":false}"));
    }

    @Test
    void anySingleCharacterClassIsEnough() throws HostException {
        for (String only : List.of("lower", "upper", "digits", "symbols")) {
            String p = "{\"length\":8,\"lower\":false,\"upper\":false,\"digits\":false,\"symbols\":false}"
                    .replace("\"" + only + "\":false", "\"" + only + "\":true");
            assertInstanceOf(Request.Generate.class, decode(generate(p)));
        }
        assertEquals(128, ((Request.Generate) decode(generate(POLICY.replace("20", "128")))).policy().length());
    }

    @Test
    void thePolicyRecordValidatesItself() {
        assertThrows(IllegalArgumentException.class, () -> new Request.Policy(7, true, true, true, true));
        assertThrows(IllegalArgumentException.class, () -> new Request.Policy(129, true, true, true, true));
        assertThrows(IllegalArgumentException.class, () -> new Request.Policy(12, false, false, false, false));
        assertEquals(12, new Request.Policy(12, false, false, false, true).length());
        assertEquals(12, new Request.Policy(12, false, false, true, false).length());
        assertEquals(12, new Request.Policy(12, false, true, false, false).length());
        assertEquals(12, new Request.Policy(12, true, false, false, false).length());
    }

    @Test
    void repliesCarryTypeIdAndCode() {
        assertEquals("{\"type\":\"error\",\"id\":null,\"code\":\"MALFORMED\"}", text(Messages.error(null, "MALFORMED")));
        assertEquals("{\"type\":\"error\",\"id\":\"x\",\"code\":\"DENIED\"}", text(Messages.error("x", "DENIED")));
        assertEquals("{\"type\":\"hello\",\"id\":\"h\",\"version\":1}", text(Messages.hello(new Request.Hello("h"))));
    }

    static String text(Json value) {
        try (pm.crypto.SecretBytes b = JsonText.toUtf8(value)) {
            return b.apply(x -> new String(x, StandardCharsets.UTF_8));
        }
    }

    private static String generate(String policy) {
        return "{\"type\":\"generate\",\"id\":\"g\",\"origin\":\"https://example.com\",\"username\":\"\",\"policy\":"
                + policy + "}";
    }

    private static Request decode(String json) throws HostException {
        return Messages.decode(json.getBytes(StandardCharsets.UTF_8));
    }

    private static void assertCode(HostException.Code code, String json) {
        assertEquals(code, assertThrows(HostException.class, () -> decode(json), json).code(), json);
    }
}
