package pm.crypto;

import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM with a zero nonce (ADR 0005). Safe ONLY because every key passed here is a fresh
 * per-save HKDF output that encrypts exactly one message.
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

    /** Encrypts {@code plaintext}; returns ciphertext followed by the 16-byte tag. */
    public static byte[] sealWithFreshKey(SecretBytes freshKey, SecretBytes plaintext, byte[] aad) throws CryptoException {
        Objects.requireNonNull(aad, "aad");
        Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, freshKey, aad);
        // Encrypt-side provider failures map to INTERNAL inside applyCrypto (SR-501).
        return plaintext.applyCrypto(cipher::doFinal);
    }

    /** Decrypts and verifies; any tampering yields {@link CryptoException.Code#AUTH_FAILED}. */
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
