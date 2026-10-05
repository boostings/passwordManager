package pm.browser.webauthn;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;

/**
 * The WebAuthn Level 3 §16 test vectors (resource {@code webauthn3-section16.txt}: §16.2 ES256
 * none, §16.4 crossOrigin, §16.5 topOrigin, §16.6 a 1023-byte credential ID), public values only.
 * RP ID {@code example.org}, origin {@code https://example.org} (§16).
 */
final class Vectors {
    static final String RP_ID = "example.org";
    static final String ORIGIN = "https://example.org";

    private static final Map<String, byte[]> VALUES = load();

    private Vectors() {
    }

    /** The value {@code section.ceremony.name}, such as {@code 16.2.get.signature}. */
    static byte[] get(String key) {
        return Objects.requireNonNull(VALUES.get(key), key).clone();
    }

    private static Map<String, byte[]> load() {
        try (InputStream in = Objects.requireNonNull(Vectors.class.getResourceAsStream("webauthn3-section16.txt"))) {
            Map<String, byte[]> out = new HashMap<>();
            for (String line : new String(in.readAllBytes(), StandardCharsets.US_ASCII).lines().toList()) {
                if (!line.isBlank() && !line.startsWith("#")) {
                    int eq = line.indexOf('=');
                    out.put(line.substring(0, eq), HexFormat.of().parseHex(line.substring(eq + 1).strip()));
                }
            }
            return out;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
