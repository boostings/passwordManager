package pm.crypto;

import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM with a zero nonce (ADR 0005). Safe ONLY because every key passed here is a fresh
 * per-save HKDF output that encrypts exactly one message; {@link #sealWithFreshKey} enforces that
 * by closing the key.
 *
 * <p>Copies outside our control: {@code SecretKeySpec} clones the key bytes and the JCA AES
 * provider keeps an expanded key schedule inside the {@code Cipher}. Neither can be zeroed from
 * here; both become garbage when the cipher goes out of scope (ADR 0008 residual risk).
 */
public final class Aead {
    /** ADR 0005: AES-256 keys only. */
    static final int KEY_LEN = 32;
    /** ADR 0005: 128-bit tag. */
    static final int TAG_BITS = 128;
    /** ADR 0005: 96-bit nonce, all zero (each key encrypts exactly one message). */
    static final int NONCE_LEN = 12;
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String AES = "AES";

    private Aead() {
    }

    /**
     * Encrypts {@code plaintext}; returns ciphertext followed by the 16-byte tag.
     *
     * <p>CONSUMES {@code freshKey}: it is closed when this method returns or throws, so the same
     * key can never seal a second message. That is the structural guarantee behind the zero nonce
     * (ADR 0005); reusing the key throws {@link IllegalStateException} {@code SECRET_CLOSED}.
     */
    public static byte[] sealWithFreshKey(SecretBytes freshKey, SecretBytes plaintext, byte[] aad) throws CryptoException {
        try (SecretBytes consumed = freshKey) {
            Objects.requireNonNull(aad, "aad");
            Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, consumed, aad);
            // Encrypt-side provider failures map to INTERNAL inside applyCrypto (SR-501).
            return plaintext.applyCrypto(cipher::doFinal);
        }
    }

    /**
     * Decrypts and verifies; any tampering yields {@link CryptoException.Code#AUTH_FAILED}.
     *
     * <p>Does NOT consume {@code key}: decrypting is safe to repeat, and the caller may need the key
     * to retry or re-derive. The caller still owns and must close it.
     */
    public static SecretBytes openWithFreshKey(SecretBytes key, byte[] ciphertextAndTag, byte[] aad) throws CryptoException {
        Objects.requireNonNull(ciphertextAndTag, "ciphertextAndTag");
        Objects.requireNonNull(aad, "aad");
        Cipher cipher = initCipher(Cipher.DECRYPT_MODE, key, aad);
        byte[] out;
        try {
            out = cipher.doFinal(ciphertextAndTag);
        } catch (GeneralSecurityException e) {
            // AEADBadTagException and any other provider failure: no cause text reaches the caller (SR-501).
            throw new CryptoException(CryptoException.Code.AUTH_FAILED);
        }
        return SecretBytes.takeOwnership(out);
    }

    /** A new cipher per call (ADR 0005): JDK GCM refuses key+IV reuse on one instance anyway. */
    private static Cipher initCipher(int mode, SecretBytes key, byte[] aad) throws CryptoException {
        if (key.length() != KEY_LEN) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        Cipher cipher = key.applyCrypto(kb -> {
            Cipher c = Cipher.getInstance(TRANSFORMATION);
            c.init(mode, new SecretKeySpec(kb, AES), new GCMParameterSpec(TAG_BITS, new byte[NONCE_LEN]));
            return c;
        });
        cipher.updateAAD(aad);
        return cipher;
    }
}
