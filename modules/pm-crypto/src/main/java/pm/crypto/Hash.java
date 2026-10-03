package pm.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * SHA-256 for integrity chains over public data (audit log, transcripts), and SHA-1 solely as the
 * lookup key of the breach range protocol (ADR 0012). Neither is a password hash.
 */
public final class Hash {
    /** SHA-256 output length in bytes. */
    public static final int SHA256_BYTES = 32;
    /** SHA-1 output length in bytes. */
    public static final int SHA1_BYTES = 20;

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

    /**
     * SHA-1 of a secret, for the k-anonymity breach range query only (ADR 0012, CE-015). The
     * Pwned Passwords corpus is indexed by SHA-1, so no other digest can look a password up; SHA-1's
     * collision weakness does not matter for that lookup, and only a five-hex-character prefix of the
     * result ever leaves the process. The result is itself secret: anyone with a SHA-1 dictionary can
     * map it back to a common password.
     *
     * @throws CryptoException {@code INTERNAL} if the JCA has no SHA-1 (mandatory in Java SE)
     */
    public static SecretBytes sha1ForBreachRange(SecretBytes data) throws CryptoException {
        Objects.requireNonNull(data, "data");
        return SecretBytes.takeOwnership(data.applyCrypto(d -> MessageDigest.getInstance("SHA-1").digest(d)));
    }
}
