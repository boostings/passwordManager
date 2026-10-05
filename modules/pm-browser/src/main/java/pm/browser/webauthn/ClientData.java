package pm.browser.webauthn;

import java.util.Arrays;
import java.util.Objects;
import pm.browser.bridge.Origin;
import pm.browser.host.HostException;
import pm.browser.host.Json;
import pm.browser.host.JsonText;
import pm.browser.host.Messages;
import pm.browser.host.NativeFrames;
import pm.crypto.Hash;

/**
 * The client data the extension sends with a WebAuthn request (WebAuthn Level 3 §5.8.1
 * {@code CollectedClientData}, ADR 0016 M6.3 addendum, SR-117). pm signs only its SHA-256, the
 * {@code clientDataHash}, exactly as an authenticator does, but first checks the JSON the page
 * will receive names the request's own type and origin, so a client that lies about the origin to
 * pm cannot have pm sign client data for another origin.
 *
 * <p>Accepted: strict UTF-8 JSON (the host's {@link JsonText} limits), one object with
 * {@code type} equal to the expected value, a non-empty string {@code challenge}, an
 * {@code origin} that is exactly the request's canonical origin as a browser serialises it,
 * {@code crossOrigin} absent or {@code false}, and no {@code topOrigin}; other members (such as the §16 vectors'
 * {@code extraData}) are allowed and hashed as they are. Cross-origin iframes are not supported.
 */
public final class ClientData {
    /** Longest client data accepted, in bytes. */
    public static final int MAX_BYTES = Messages.MAX_CLIENT_DATA;
    /** The {@code type} of a create request. */
    public static final String CREATE = "webauthn.create";
    /** The {@code type} of a get request. */
    public static final String GET = "webauthn.get";

    private ClientData() {
    }

    /**
     * Checks {@code json} and returns its SHA-256.
     *
     * @param json the exact {@code clientDataJSON} bytes; not modified
     * @param type {@link #CREATE} or {@link #GET}
     * @param origin the request's canonical origin
     * @return the 32-byte {@code clientDataHash}
     * @throws HostException {@code BAD_CLIENT_DATA} if any rule above is broken
     */
    public static byte[] hash(byte[] json, String type, Origin origin) throws HostException {
        Objects.requireNonNull(json, "json");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(origin, "origin");
        if (json.length == 0 || json.length > MAX_BYTES) {
            throw bad();
        }
        Json root;
        try {
            char[] text = NativeFrames.utf8(json);
            try {
                root = JsonText.parse(text);
            } finally {
                Arrays.fill(text, '\0');
            }
        } catch (HostException e) {
            throw bad();
        }
        if (!(root instanceof Json.Obj o)
                || !(o.get("type") instanceof Json.Str t) || !type.equals(t.text())
                || !(o.get("challenge") instanceof Json.Str c) || c.length() == 0
                || !(o.get("origin") instanceof Json.Str from) || !origin.text().equals(from.text())
                || !notCrossOrigin(o.get("crossOrigin")) || o.get("topOrigin") != null) {
            throw bad();
        }
        return Hash.sha256(json);
    }

    private static boolean notCrossOrigin(Json value) {
        return value == null || (value instanceof Json.Bool b && !b.value());
    }

    private static HostException bad() {
        return new HostException(HostException.Code.BAD_CLIENT_DATA);
    }
}
