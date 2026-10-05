package pm.browser.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * The {@code webauthn.create} and {@code webauthn.get} schema (docs/schemas, SR-115): exact key
 * sets, exact types, canonical base64url, bounded sizes; and the base64url codec itself.
 */
@Tag("T-PK-04")
final class WebauthnMessagesTest {
    private static final String CDJ = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0";
    private static final String CRED = "AQID";

    private static String create(String user, String algorithms, String exclude, String uv) {
        return "{\"type\":\"webauthn.create\",\"id\":\"c1\",\"origin\":\"https://example.com\",\"rpId\":\"example.com\","
                + "\"clientDataJSON\":\"" + CDJ + "\",\"user\":" + user + ",\"algorithms\":" + algorithms
                + ",\"excludeCredentials\":" + exclude + ",\"userVerification\":" + uv + "}";
    }

    private static String create() {
        return create(user("\"dXNlcg\"", "\"alice\"", "\"Alice\""), "[-7,-257]", "[\"" + CRED + "\"]", "\"preferred\"");
    }

    private static String user(String id, String name, String displayName) {
        return "{\"id\":" + id + ",\"name\":" + name + ",\"displayName\":" + displayName + "}";
    }

    private static String get(String allow, String credential, String uv) {
        return "{\"type\":\"webauthn.get\",\"id\":\"g1\",\"origin\":\"https://example.com\",\"rpId\":\"example.com\","
                + "\"clientDataJSON\":\"" + CDJ + "\",\"allowCredentials\":" + allow + ",\"credential\":" + credential
                + ",\"userVerification\":" + uv + "}";
    }

    private static Request decode(String json) throws HostException {
        return Messages.decode(json.getBytes(StandardCharsets.UTF_8));
    }

    private static void assertBad(String json) {
        assertEquals(HostException.Code.BAD_FIELD, assertThrows(HostException.class, () -> decode(json)).code(), json);
    }

    @Test
    void decodesBothRequests() throws HostException {
        assertEquals(new Request.WebauthnCreate("c1", "https://example.com", "example.com", CDJ,
                new Request.User("dXNlcg", "alice", "Alice"), List.of(-7L, -257L), List.of(CRED),
                Request.UserVerification.PREFERRED), decode(create()));
        assertEquals(new Request.WebauthnCreate("c1", "https://example.com", "example.com", CDJ,
                new Request.User("dXNlcg", "alice", ""), List.of(), List.of(), Request.UserVerification.REQUIRED),
                decode(create(user("\"dXNlcg\"", "\"alice\"", "\"\""), "[]", "[]", "\"required\"")));
        assertEquals(new Request.WebauthnGet("g1", "https://example.com", "example.com", CDJ, List.of(CRED),
                Optional.of(CRED), Request.UserVerification.DISCOURAGED),
                decode(get("[\"" + CRED + "\"]", "\"" + CRED + "\"", "\"discouraged\"")));
        assertEquals(new Request.WebauthnGet("g1", "https://example.com", "example.com", CDJ, List.of(),
                Optional.empty(), Request.UserVerification.PREFERRED), decode(get("[]", "null", "\"preferred\"")));
    }

    @Test
    void createIsCheckedFieldByField() {
        String okUser = user("\"dXNlcg\"", "\"alice\"", "\"Alice\"");
        assertBad(create().replace("\"rpId\":\"example.com\"", "\"rpId\":\"exa mple.com\""));
        assertBad(create().replace("\"rpId\":\"example.com\"", "\"rpId\":\"\""));
        assertBad(create().replace("\"rpId\":\"example.com\",", ""));
        assertBad(create().replace("}", ",\"extra\":1}"));
        assertBad(create().replace(CDJ, "eyJ0=="));
        assertBad(create().replace(CDJ, ""));
        assertBad(create().replace(CDJ, "A".repeat(Messages.MAX_CLIENT_DATA / 3 * 4 + 4)));
        assertBad(create("[]", "[]", "[]", "\"preferred\""));
        assertBad(create(user("\"dXNlcg\"", "\"alice\"", "\"Alice\"").replace("}", ",\"x\":1}"), "[]", "[]",
                "\"preferred\""));
        assertBad(create(user("\"\"", "\"alice\"", "\"Alice\""), "[]", "[]", "\"preferred\""));
        assertBad(create(user("\"" + "A".repeat(88) + "\"", "\"alice\"", "\"Alice\""), "[]", "[]", "\"preferred\""));
        assertBad(create(user("1", "\"alice\"", "\"Alice\""), "[]", "[]", "\"preferred\""));
        assertBad(create(user("\"dXNlcg\"", "\"\"", "\"Alice\""), "[]", "[]", "\"preferred\""));
        assertBad(create(user("\"dXNlcg\"", "\"alice\"", "null"), "[]", "[]", "\"preferred\""));
        assertBad(create(okUser, "{}", "[]", "\"preferred\""));
        assertBad(create(okUser, "[\"-7\"]", "[]", "\"preferred\""));
        assertBad(create(okUser, "[" + "-7,".repeat(Messages.MAX_ALGORITHMS) + "-7]", "[]", "\"preferred\""));
        assertBad(create(okUser, "[-7]", "\"" + CRED + "\"", "\"preferred\""));
        assertBad(create(okUser, "[-7]", "[1]", "\"preferred\""));
        assertBad(create(okUser, "[-7]", "[\"\"]", "\"preferred\""));
        assertBad(create(okUser, "[-7]", "[\"" + "A".repeat(1366) + "\"]", "\"preferred\""));
        assertBad(create(okUser, "[-7]", "[" + ("\"" + CRED + "\",").repeat(Messages.MAX_CREDENTIALS) + "\"" + CRED
                + "\"]", "\"preferred\""));
        assertBad(create(okUser, "[-7]", "[]", "\"Preferred\""));
        assertBad(create(okUser, "[-7]", "[]", "\"\""));
        assertBad(create(okUser, "[-7]", "[]", "true"));
    }

    @Test
    void getIsCheckedFieldByField() {
        assertBad(get("[]", "\"" + CRED + "\"", "\"preferred\"").replace("\"credential\":\"" + CRED + "\",", ""));
        assertBad(get("[]", "\"\"", "\"preferred\""));
        assertBad(get("[]", "1", "\"preferred\""));
        assertBad(get("[]", "\"AQID=\"", "\"preferred\""));
        assertBad(get("null", "null", "\"preferred\""));
        assertBad(get("[]", "null", "\"always\""));
        assertBad(get("[]", "null", "\"preferred\"").replace("\"rpId\":\"example.com\"", "\"rpId\":1"));
    }

    @Test
    void base64UrlIsCanonicalAndUnpadded() throws HostException {
        assertEquals("", Base64Url.encode(new byte[0]));
        assertEquals("-_8", Base64Url.encode(new byte[] {(byte) 0xfb, (byte) 0xff}));
        assertArrayEquals(new byte[] {(byte) 0xfb, (byte) 0xff}, Base64Url.decode("-_8"));
        assertArrayEquals(new byte[0], Base64Url.decode(""));
        assertArrayEquals(new byte[] {1, 2, 3}, Base64Url.decode(CRED));
        for (String bad : List.of("AQ==", "+/8", "A", "AQI=", "AR", "A B", "AQ\n")) {
            assertEquals(HostException.Code.BAD_FIELD,
                    assertThrows(HostException.class, () -> Base64Url.decode(bad)).code(), bad);
        }
    }
}
