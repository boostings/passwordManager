package pm.browser.host;

import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Unpadded base64url (RFC 4648 §5), the encoding of every binary WebAuthn field in the protocol
 * (ADR 0016 M6.3 addendum). Decoding is canonical only: no padding, no whitespace, no other
 * alphabet, and unused trailing bits zero, so each byte string has exactly one accepted text.
 */
public final class Base64Url {
    private static final Pattern ALPHABET = Pattern.compile("[A-Za-z0-9_-]*");
    private static final int QUANTUM = 4;
    private static final int IMPOSSIBLE_REMAINDER = 1;

    private Base64Url() {
    }

    /** The unpadded base64url text of {@code bytes}. */
    public static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Decodes canonical unpadded base64url.
     *
     * @throws HostException {@code BAD_FIELD} for any other text
     */
    public static byte[] decode(String text) throws HostException {
        Objects.requireNonNull(text, "text");
        if (!ALPHABET.matcher(text).matches() || text.length() % QUANTUM == IMPOSSIBLE_REMAINDER) {
            throw new HostException(HostException.Code.BAD_FIELD);
        }
        byte[] bytes = Base64.getUrlDecoder().decode(text);
        if (!encode(bytes).equals(text)) {
            throw new HostException(HostException.Code.BAD_FIELD);
        }
        return bytes;
    }
}
