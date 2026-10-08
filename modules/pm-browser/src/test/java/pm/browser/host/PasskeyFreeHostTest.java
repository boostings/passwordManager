package pm.browser.host;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * A host that serves no passkeys answers {@code webauthn.create} and {@code webauthn.get} exactly
 * as it answers a type it does not know: the reply is decided from the {@code type} member alone,
 * so a valid, a partial and an empty body all get the bytes {@code {"type":"nosuch"}} gets.
 */
@Tag("T-EXT-08")
class PasskeyFreeHostTest {
    private static final ExtensionAllowlist ALLOW = ExtensionAllowlist.of(List.of(ExtensionAllowlistTest.ID));
    private static final List<String> ARGS = List.of(ExtensionAllowlistTest.ORIGIN);
    private static final String ORIGIN = "https://example.com";
    private static final String CDJ = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0";
    private static final String UNKNOWN = "{\"type\":\"nosuch\"}";
    private static final List<String> PASSKEY_BODIES = List.of(
            "{\"type\":\"webauthn.get\",\"id\":\"g1\",\"origin\":\"" + ORIGIN + "\",\"rpId\":\"example.com\","
                    + "\"clientDataJSON\":\"" + CDJ + "\",\"allowCredentials\":[],\"credential\":null,"
                    + "\"userVerification\":\"preferred\"}",
            "{\"type\":\"webauthn.get\",\"id\":\"g2\"}",
            "{\"type\":\"webauthn.get\"}",
            "{\"type\":\"webauthn.get\",\"id\":7,\"rpId\":[],\"extra\":true}",
            "{\"type\":\"webauthn.create\",\"id\":\"c1\",\"origin\":\"" + ORIGIN + "\",\"rpId\":\"example.com\","
                    + "\"clientDataJSON\":\"" + CDJ + "\",\"user\":{\"id\":\"dXNlcg\",\"name\":\"alice\","
                    + "\"displayName\":\"Alice\"},\"algorithms\":[-7],\"excludeCredentials\":[],"
                    + "\"userVerification\":\"preferred\"}",
            "{\"type\":\"webauthn.create\",\"id\":\"c2\"}",
            "{\"type\":\"webauthn.create\"}");
    private static final String LOOKUP = "{\"type\":\"lookup\",\"id\":\"l1\",\"origin\":\"" + ORIGIN + "\"}";

    private final List<Request> handled = new ArrayList<>();

    @Test
    void passkeyRequestsGetTheUnknownTypeReplyByteForByte() throws IOException {
        List<byte[]> frames = new ArrayList<>();
        frames.add(Frames.frame(UNKNOWN));
        PASSKEY_BODIES.forEach(b -> frames.add(Frames.frame(b)));
        frames.add(Frames.frame(LOOKUP));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int exit = NativeHost.runWithoutPasskeys(ARGS, ALLOW,
                new ByteArrayInputStream(Frames.concat(frames.toArray(byte[][]::new))), out, id -> this::handle);
        assertEquals(NativeHost.EXIT_OK, exit);
        List<String> replies = Frames.replies(out.toByteArray());
        String unknown = "{\"type\":\"error\",\"id\":null,\"code\":\"UNKNOWN_TYPE\"}";
        List<String> expected = new ArrayList<>();
        expected.add(unknown);
        PASSKEY_BODIES.forEach(b -> expected.add(unknown));
        expected.add("{\"type\":\"lookup\",\"id\":\"l1\",\"entries\":[]}");
        assertEquals(expected, replies);
        assertEquals(1, handled.size()); // only the lookup reached the handler
        assertInstanceOf(Request.Lookup.class, handled.get(0));
    }

    @Test
    void decodingWithoutPasskeysRefusesThemLikeAnUnknownTypeAndKeepsEverythingElse() throws HostException {
        for (String body : PASSKEY_BODIES) {
            HostException e = assertThrows(HostException.class, () -> Messages.decodeWithoutPasskeys(utf8(body)));
            assertEquals(HostException.Code.UNKNOWN_TYPE, e.code());
        }
        HostException unknown = assertThrows(HostException.class, () -> Messages.decodeWithoutPasskeys(utf8(UNKNOWN)));
        assertEquals(HostException.Code.UNKNOWN_TYPE, unknown.code());
        try (Request lookup = Messages.decodeWithoutPasskeys(utf8(LOOKUP))) {
            assertInstanceOf(Request.Lookup.class, lookup);
        }
        // The full decoder still reads them, so this is the passkey-free path and not a broken schema.
        try (Request get = Messages.decode(utf8(PASSKEY_BODIES.get(0)))) {
            assertInstanceOf(Request.WebauthnGet.class, get);
        }
    }

    private Json.Obj handle(Request request) {
        handled.add(request);
        Map<String, Json> reply = Messages.reply("lookup", request.id());
        reply.put("entries", new Json.Arr(List.of()));
        return new Json.Obj(reply);
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
