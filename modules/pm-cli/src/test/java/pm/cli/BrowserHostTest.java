package pm.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.browser.host.ExtensionAllowlist;
import pm.browser.host.HostException;
import pm.browser.host.Json;
import pm.browser.host.JsonText;
import pm.browser.host.NativeFrames;
import pm.browser.host.NativeHost;
import pm.crypto.SecretBytes;
import pm.tui.BrowserRelay;

/**
 * ADR 0014 §8, SR-113/SR-114: {@code pm} started by the browser serves native messaging only for
 * an extension in the default vault's allowlist, reads nothing before that check, and with no TUI
 * open answers every vault request {@code DENIED_LOCKED}: nothing is approved in this process.
 */
@Tag("T-EXT-08")
class BrowserHostTest {
    private static final String ID = "abcdefghijklmnopabcdefghijklmnop";
    private static final String CALLER = "chrome-extension://" + ID + "/";

    @TempDir
    Path home;
    private Path vaultDir;

    @BeforeEach
    void setUp() throws IOException {
        vaultDir = Files.createDirectories(home.resolve(".local/share/pm"));
    }

    private int serve(String[] args, InputStream in, ByteArrayOutputStream out) {
        Map<String, String> props = Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, home.toString());
        return BrowserHost.serve(args, in, out, props::get);
    }

    /** stdin that fails the test if anything reads it. */
    private static final class Untouched extends InputStream {
        @Override
        public int read() {
            throw new AssertionError("stdin was read before the caller was checked");
        }

        @Override
        public int read(byte[] b, int off, int len) {
            throw new AssertionError("stdin was read before the caller was checked");
        }
    }

    private static byte[] frames(String... messages) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        for (String m : messages) {
            try (SecretBytes body = SecretBytes.copyOf(m.getBytes(StandardCharsets.UTF_8))) {
                NativeFrames.write(buf, body);
            } catch (HostException e) {
                throw new AssertionError(e);
            }
        }
        return buf.toByteArray();
    }

    private static Json.Obj reply(InputStream in) throws IOException, HostException {
        byte[] frame = NativeFrames.read(in);
        return (Json.Obj) JsonText.parse(NativeFrames.utf8(frame));
    }

    private static String text(Json.Obj o, String member) {
        return ((Json.Str) o.get(member)).text();
    }

    @Test
    void theBrowsersCallerArgumentSelectsHostMode() {
        assertTrue(BrowserHost.isHostInvocation(new String[] {CALLER}));
        assertTrue(BrowserHost.isHostInvocation(new String[] {CALLER, "--parent-window=0"}));
        assertFalse(BrowserHost.isHostInvocation(new String[] {"browser", "status"}));
        assertFalse(BrowserHost.isHostInvocation(new String[0]));
    }

    @Test
    void withNoAllowlistNothingIsReadOrWritten() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertEquals(NativeHost.EXIT_REFUSED, serve(new String[] {CALLER}, new Untouched(), out));
        assertEquals(0, out.size());
    }

    @Test
    void anExtensionNotInTheAllowlistIsRefusedBeforeReading() throws IOException {
        Files.writeString(vaultDir.resolve(ExtensionAllowlist.FILE_NAME), "ponmlkjihgfedcbaponmlkjihgfedcba\n",
                StandardCharsets.US_ASCII);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertEquals(NativeHost.EXIT_REFUSED, serve(new String[] {CALLER}, new Untouched(), out));
        assertEquals(0, out.size());
    }

    /**
     * Passkeys are not served in this version: the production host answers a WebAuthn request from
     * its {@code type} member alone, with the very bytes a type nobody knows gets, whether the rest
     * of the body is valid, partial or missing, and relays nothing to the TUI.
     */
    @Test
    void theProductionHostAnswersPasskeyRequestsLikeAnUnknownType() throws IOException, HostException {
        Files.writeString(vaultDir.resolve(ExtensionAllowlist.FILE_NAME), ID + "\n", StandardCharsets.US_ASCII);
        String[] bodies = {
            "{\"type\":\"nosuch\"}",
            "{\"type\":\"webauthn.get\",\"id\":\"a1\",\"origin\":\"https://example.org\","
                + "\"rpId\":\"example.org\",\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0\","
                + "\"allowCredentials\":[],\"credential\":null,\"userVerification\":\"preferred\"}",
            "{\"type\":\"webauthn.get\",\"id\":\"a2\"}",
            "{\"type\":\"webauthn.get\"}",
            "{\"type\":\"webauthn.create\",\"id\":\"c1\",\"origin\":\"https://example.org\","
                + "\"rpId\":\"example.org\",\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0\","
                + "\"user\":{\"id\":\"dXNlcg\",\"name\":\"alice\",\"displayName\":\"Alice\"},"
                + "\"algorithms\":[-7],\"excludeCredentials\":[],\"userVerification\":\"preferred\"}",
            "{\"type\":\"webauthn.create\",\"id\":\"c2\"}",
            "{\"type\":\"webauthn.create\"}",
        };
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertEquals(NativeHost.EXIT_OK, serve(new String[] {CALLER}, new ByteArrayInputStream(frames(bodies)), out));
        InputStream replies = new ByteArrayInputStream(out.toByteArray());
        byte[] unknown = NativeFrames.read(replies);
        assertEquals("{\"type\":\"error\",\"id\":null,\"code\":\"UNKNOWN_TYPE\"}",
                new String(unknown, StandardCharsets.UTF_8));
        for (int i = 1; i < bodies.length; i++) {
            assertArrayEquals(unknown, NativeFrames.read(replies), bodies[i]);
        }
        assertEquals(0, replies.available());
    }

    @Test
    void withNoTuiOpenEveryVaultRequestIsLocked() throws IOException, HostException {
        Files.writeString(vaultDir.resolve(ExtensionAllowlist.FILE_NAME), ID + "\n", StandardCharsets.US_ASCII);
        byte[] in = frames("{\"type\":\"hello\",\"id\":\"h1\",\"version\":1}",
                "{\"type\":\"lookup\",\"id\":\"l1\",\"origin\":\"https://example.org\"}",
                "{\"type\":\"fill\",\"id\":\"f1\",\"origin\":\"https://example.org\","
                        + "\"entry\":\"00000000-0000-4000-8000-000000000001\"}");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertEquals(NativeHost.EXIT_OK, serve(new String[] {CALLER}, new ByteArrayInputStream(in), out));
        InputStream replies = new ByteArrayInputStream(out.toByteArray());
        Json.Obj hello = reply(replies);
        assertEquals("hello", text(hello, "type"));
        for (String id : new String[] {"l1", "f1"}) {
            Json.Obj r = reply(replies);
            assertEquals("error", text(r, "type"));
            assertEquals(id, text(r, "id"));
            assertEquals("DENIED_LOCKED", text(r, "code"));
        }
        assertEquals(0, replies.available(), "one reply per request, nothing else on stdout");
        try (Stream<Path> made = Files.list(vaultDir)) {
            assertTrue(made.noneMatch(p -> String.valueOf(p.getFileName()).endsWith(BrowserRelay.DIR_SUFFIX)),
                    "the host only looks for the relay folder next to the default vault; it creates nothing");
        }
    }
}
