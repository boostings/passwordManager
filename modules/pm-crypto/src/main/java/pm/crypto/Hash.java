package pm.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/** SHA-256 for integrity chains over public data (audit log, transcripts). Not for secrets or passwords. */
public final class Hash {
    /** SHA-256 output length in bytes. */
    public static final int SHA256_BYTES = 32;

    private Hash() {
    }

    /** SHA-256 of {@code data}. */
    public static byte[] sha256(byte[] data) {
        Objects.requireNonNull(data, "data");
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e); // mandated by the Java SE spec
        }
    }
}
