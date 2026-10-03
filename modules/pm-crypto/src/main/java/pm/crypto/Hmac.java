package pm.crypto;

import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HMAC-SHA256 (RFC 2104) with constant-time verification (SR-016). */
public final class Hmac {
    /** Tag length in bytes. */
    public static final int TAG_BYTES = 32;
    /** Keys must carry at least 256 bits; anything shorter is a caller passing the wrong thing. */
    static final int MIN_KEY_BYTES = 32;
    private static final String ALGORITHM = "HmacSHA256";

    private Hmac() {
    }

    /**
     * HMAC-SHA256 of {@code data} under {@code key}.
     *
     * @throws CryptoException {@code BAD_INPUT} if the key is shorter than 32 bytes
     */
    public static byte[] sha256(SecretBytes key, byte[] data) throws CryptoException {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(data, "data");
        if (key.length() < MIN_KEY_BYTES) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        return anyKey(key, data);
    }

    /** The core without the key-length floor, so the RFC 4231 vectors (short keys) can be checked. */
    static byte[] anyKey(SecretBytes key, byte[] data) throws CryptoException {
        return key.applyCrypto(k -> {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(k, ALGORITHM));
            return mac.doFinal(data);
        });
    }

    /**
     * Whether {@code tag} is the HMAC-SHA256 of {@code data} under {@code key}, compared in constant
     * time.
     *
     * @throws CryptoException {@code BAD_INPUT} if the key is shorter than 32 bytes
     */
    public static boolean verify(SecretBytes key, byte[] data, byte[] tag) throws CryptoException {
        Objects.requireNonNull(tag, "tag");
        return ConstantTime.equals(sha256(key, data), tag);
    }
}
