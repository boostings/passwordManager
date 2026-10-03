package pm.browser.host;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretChars;

/** The host loop: allowlist first, then one reply per frame (SR-301, SR-303). */
@Tag("T-EXT-02")
class NativeHostTest {
    private static final ExtensionAllowlist ALLOW = ExtensionAllowlist.of(List.of(ExtensionAllowlistTest.ID));
    private static final List<String> ARGS = List.of(ExtensionAllowlistTest.ORIGIN);
    private static final String LOOKUP = "{\"type\":\"lookup\",\"id\":\"l1\",\"origin\":\"https://example.com\"}";

    private final List<Request> seen = new ArrayList<>();
    private final List<String> callers = new ArrayList<>();

    @Test
    void aRefusedCallerIsNotReadFromOrAnswered() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        List<String> other = List.of("chrome-extension://" + ExtensionAllowlistTest.OTHER + "/");
        try (InputStream explode = Frames.explode()) {
            assertEquals(NativeHost.EXIT_REFUSED, NativeHost.run(other, ALLOW, explode, out, this::handler));
            assertEquals(NativeHost.EXIT_REFUSED, NativeHost.run(List.of(), ALLOW, explode, out, this::handler));
        }
        assertEquals(0, out.size());
        assertTrue(callers.isEmpty());
    }

    @Test
    void helloIsAnsweredByTheHostAndTheRestByTheHandler() throws IOException {
        List<String> replies = run(Frames.concat(
                Frames.frame("{\"type\":\"hello\",\"id\":\"h\",\"version\":1}"),
                Frames.frame(LOOKUP)), NativeHost.EXIT_OK);
        assertEquals(List.of("{\"type\":\"hello\",\"id\":\"h\",\"version\":1}",
                "{\"type\":\"lookup\",\"id\":\"l1\",\"n\":1}"), replies);
        assertEquals(List.of(ExtensionAllowlistTest.ID), callers);
        assertEquals(1, seen.size());
    }

    @Test
    void schemaErrorsAreAnsweredAndTheSessionContinues() throws IOException {
        List<String> replies = run(Frames.concat(
                Frames.frame("{\"type\":\"lookup\",\"id\":\"l1\",\"origin\":\"o\",\"x\":1}"),
                Frames.frame("{\"type\":"),
                Frames.frame(new byte[] {(byte) 0xc0, (byte) 0x80}),
                Frames.frame("{\"type\":\"hello\",\"id\":\"h\",\"version\":9}"),
                Frames.frame(LOOKUP)), NativeHost.EXIT_OK);
        assertEquals(List.of(error(null, "BAD_FIELD"), error(null, "MALFORMED"), error(null, "BAD_UTF8"),
                error(null, "VERSION"), "{\"type\":\"lookup\",\"id\":\"l1\",\"n\":1}"), replies);
    }

    @Test
    void handlerRefusalsCarryTheRequestId() throws IOException {
        List<String> replies = run(Frames.frame(
                "{\"type\":\"fill\",\"id\":\"f9\",\"origin\":\"o\",\"entry\":\"0f8b6c1e-2a3d-4e5f-8a9b-0c1d2e3f4a5b\"}"),
                NativeHost.EXIT_OK);
        assertEquals(List.of(error("f9", "BAD_FIELD")), replies);
    }

    @Test
    void framingErrorsEndTheSession() throws IOException {
        assertEquals(List.of(error(null, "FRAME_SIZE")),
                run(Frames.concat(Frames.header(NativeFrames.MAX_INBOUND + 1), Frames.frame(LOOKUP)), NativeHost.EXIT_PROTOCOL));
        assertEquals(List.of("{\"type\":\"lookup\",\"id\":\"l1\",\"n\":1}", error(null, "TRUNCATED")),
                run(Frames.concat(Frames.frame(LOOKUP), new byte[] {1, 0}), NativeHost.EXIT_PROTOCOL));
    }

    @Test
    void aReplyTooLargeForChromeBecomesAnError() throws IOException {
        Handler.Factory big = id -> request -> {
            Map<String, Json> m = Messages.reply("lookup", request.id());
            m.put("pad", Json.Str.of("x".repeat(NativeFrames.MAX_OUTBOUND)));
            return new Json.Obj(m);
        };
        Handler.Factory bigNoId = id -> request -> new Json.Obj(Map.of("pad", Json.Str.of("x".repeat(NativeFrames.MAX_OUTBOUND))));
        assertEquals(List.of(error("l1", "FRAME_SIZE")), run(Frames.frame(LOOKUP), big, NativeHost.EXIT_OK));
        assertEquals(List.of(error(null, "FRAME_SIZE")), run(Frames.frame(LOOKUP), bigNoId, NativeHost.EXIT_OK));
    }

    @Test
    void aRuntimeFailureInTheHandlerIsAnsweredAsInternalAndTheSessionContinues() throws IOException {
        Handler.Factory faulty = id -> request -> {
            boolean first = seen.isEmpty();
            seen.add(request);
            if (first) {
                throw new IllegalArgumentException("MALFORMED_CHARS: detail that must not reach the browser");
            }
            return new Json.Obj(Messages.reply("lookup", request.id()));
        };
        List<String> replies = run(Frames.concat(Frames.frame(LOOKUP), Frames.frame(LOOKUP)), faulty, NativeHost.EXIT_OK);
        assertEquals(List.of(error("l1", "INTERNAL"), "{\"type\":\"lookup\",\"id\":\"l1\"}"), replies);
    }

    @Test
    void anUnencodableReplyIsAnsweredAsInternal() throws IOException {
        Handler.Factory lone = id -> request -> {
            Map<String, Json> m = Messages.reply("fill", request.id());
            m.put("password", Json.Str.of(SecretChars.takeOwnership(new char[] {'a', '\uD800'})));
            return new Json.Obj(m);
        };
        Handler.Factory loneNoId = id -> request ->
                new Json.Obj(Map.of("password", Json.Str.of(SecretChars.takeOwnership(new char[] {'\uDC00'}))));
        assertEquals(List.of(error("l1", "INTERNAL"), error("l1", "INTERNAL")),
                run(Frames.concat(Frames.frame(LOOKUP), Frames.frame(LOOKUP)), lone, NativeHost.EXIT_OK));
        assertEquals(List.of(error(null, "INTERNAL")), run(Frames.frame(LOOKUP), loneNoId, NativeHost.EXIT_OK));
    }

    @Test
    void aLoneSurrogateInAPlainStringIsReplacedNotFatal() throws IOException {
        Handler.Factory titled = id -> request -> {
            Map<String, Json> m = Messages.reply("lookup", request.id());
            m.put("title", Json.Str.of("a\uD800b\uDC00\uD83D\uDE00\uD83D"));
            return new Json.Obj(m);
        };
        assertEquals(List.of("{\"type\":\"lookup\",\"id\":\"l1\",\"title\":\"a\uFFFDb\uFFFD\uD83D\uDE00\uFFFD\"}"),
                run(Frames.frame(LOOKUP), titled, NativeHost.EXIT_OK));
    }

    @Test
    void repliesAreWipedAndSecretRequestsClosedAfterSending() throws IOException {
        List<Json.Str> sent = new ArrayList<>();
        Handler.Factory keep = id -> request -> {
            seen.add(request);
            Json.Str s = Json.Str.of("secret-ish");
            sent.add(s);
            return new Json.Obj(Map.of("v", s));
        };
        run(Frames.frame("{\"type\":\"save\",\"id\":\"s\",\"origin\":\"o\",\"username\":\"u\",\"password\":\"pw\"}"),
                keep, NativeHost.EXIT_OK);
        assertEquals("\0".repeat(10), sent.get(0).text());
        assertTrue(((Request.Save) seen.get(0)).password().isClosed());
    }

    private Handler handler(String extensionId) {
        callers.add(extensionId);
        return request -> {
            seen.add(request);
            if (request instanceof Request.Fill) {
                throw new HostException(HostException.Code.BAD_FIELD);
            }
            Map<String, Json> m = Messages.reply("lookup", request.id());
            m.put("n", new Json.Num(seen.size()));
            return new Json.Obj(m);
        };
    }

    private List<String> run(byte[] input, int expectedExit) throws IOException {
        return run(input, this::handler, expectedExit);
    }

    private static List<String> run(byte[] input, Handler.Factory handlers, int expectedExit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertEquals(expectedExit, NativeHost.run(ARGS, ALLOW, new ByteArrayInputStream(input), out, handlers));
        return Frames.replies(out.toByteArray());
    }

    private static String error(String id, String code) {
        return "{\"type\":\"error\",\"id\":" + (id == null ? "null" : "\"" + id + "\"") + ",\"code\":\"" + code + "\"}";
    }
}
