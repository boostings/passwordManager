package pm.browser.host;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import pm.crypto.SecretBytes;

/**
 * The native messaging host loop (ADR 0014 §2). It checks the caller against the allowlist before
 * reading anything, then answers one framed request at a time until the browser closes stdin.
 * A request that fails the schema gets an {@code error} reply and the loop continues; a framing
 * error cannot be resynchronised, so it gets an {@code error} reply and the host exits. An
 * unexpected runtime failure while answering one request (a bug or a port fault) becomes an
 * {@code INTERNAL} error reply to that request, and the loop continues: the extension always gets
 * an answer, and no exception text reaches it.
 */
public final class NativeHost {
    /** The browser closed the connection. */
    public static final int EXIT_OK = 0;
    /** The caller is not an allowlisted extension; nothing was read or written. */
    public static final int EXIT_REFUSED = 2;
    /** A framing error ended the session. */
    public static final int EXIT_PROTOCOL = 3;

    private NativeHost() {
    }

    /**
     * Serves one browser connection.
     *
     * @param args the host's command-line arguments, as Chrome passed them
     * @param allowlist the extensions allowed to connect
     * @param in the browser's end of stdin
     * @param out the browser's end of stdout
     * @param handlers creates the handler for the verified caller
     * @return one of the {@code EXIT_} codes
     * @throws IOException if stdout fails
     */
    public static int run(List<String> args, ExtensionAllowlist allowlist, InputStream in, OutputStream out,
            Handler.Factory handlers) throws IOException {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(out, "out");
        Optional<String> caller = allowlist.caller(args);
        if (caller.isEmpty()) {
            return EXIT_REFUSED;
        }
        Handler handler = handlers.forCaller(caller.get());
        while (true) {
            byte[] body;
            try {
                body = NativeFrames.read(in);
            } catch (HostException e) {
                if (e.code() == HostException.Code.CLOSED) {
                    return EXIT_OK;
                }
                send(out, Messages.error(null, e.getMessage()));
                return EXIT_PROTOCOL;
            }
            send(out, answer(body, handler));
        }
    }

    private static Json.Obj answer(byte[] body, Handler handler) {
        Request request;
        try {
            request = Messages.decode(body);
        } catch (HostException e) {
            return Messages.error(null, e.getMessage());
        }
        try (request) {
            return request instanceof Request.Hello hello ? Messages.hello(hello) : handler.handle(request);
        } catch (HostException e) {
            return Messages.error(request.id(), e.getMessage());
        } catch (RuntimeException e) { // fault barrier: one reply per request, no exception text leaves the host
            return Messages.error(request.id(), HostException.Code.INTERNAL.name());
        }
    }

    /**
     * Writes {@code reply} and wipes it. A reply too large for Chrome is replaced by an error, and
     * so is one that cannot be encoded (an unpaired surrogate in a secret string).
     */
    private static void send(OutputStream out, Json.Obj reply) throws IOException {
        String id = reply.get("id") instanceof Json.Str s ? s.text() : null;
        try (SecretBytes bytes = JsonText.toUtf8(reply)) {
            NativeFrames.write(out, bytes);
        } catch (HostException e) {
            send(out, Messages.error(id, e.getMessage()));
        } catch (IllegalArgumentException e) {
            send(out, Messages.error(id, HostException.Code.INTERNAL.name()));
        } finally {
            reply.wipe();
        }
    }
}
