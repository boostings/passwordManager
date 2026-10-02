package pm.crypto;

import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256 Key Wrap with Padding (RFC 5649) via the JDK; a wrong KEK fails integrity (ADR 0004).
 *
 * <p>Copies outside our control: {@code SecretKeySpec} clones the KEK and the JCA AES provider
 * keeps an expanded key schedule inside the {@code Cipher}; neither can be zeroed from here
 * (ADR 0008 residual risk).
 */
public final class KeyWrap {
    /** ADR 0004: KEKs are AES-256. */
    static final int KEK_LEN = 32;
    private static final int SEMIBLOCK_LEN = 8;
    private static final int MIN_WRAPPED_LEN = 2 * SEMIBLOCK_LEN;
    private static final String TRANSFORMATION = "AES/KWP/NoPadding";
    private static final String AES = "AES";

    private KeyWrap() {
    }

    /** Wraps {@code key} under {@code kek}. */
    public static byte[] wrap(SecretBytes kek, SecretBytes key) throws CryptoException {
        requireKek(kek);
        if (key.length() == 0) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, kek);
        // Wrap-side provider failures map to INTERNAL inside applyCrypto (SR-501).
        return key.applyCrypto(cipher::doFinal);
    }

    /** Unwraps; a wrong KEK or tampered input yields {@link CryptoException.Code#AUTH_FAILED}. */
    public static SecretBytes unwrap(SecretBytes kek, byte[] wrapped) throws CryptoException {
        Objects.requireNonNull(wrapped, "wrapped");
        requireKek(kek);
        // RFC 5649 output is n+1 >= 2 semiblocks. Checked here because the JDK throws unchecked
        // exceptions (e.g. NegativeArraySizeException) on some short inputs instead of a GeneralSecurityException.
        if (wrapped.length < MIN_WRAPPED_LEN || wrapped.length % SEMIBLOCK_LEN != 0) {
            throw new CryptoException(CryptoException.Code.AUTH_FAILED);
        }
        Cipher cipher = initCipher(Cipher.DECRYPT_MODE, kek);
        byte[] out;
        try {
            out = cipher.doFinal(wrapped);
        } catch (GeneralSecurityException e) {
            // Deliberately drops the cause: no provider text may reach the caller (SR-501, ERR01-J).
            throw new CryptoException(CryptoException.Code.AUTH_FAILED);
        }
        return SecretBytes.takeOwnership(out);
    }

    /** RFC 5649 cipher keyed with {@code kek}; package-private so tests can run the RFC vectors (192-bit KEK). */
    static Cipher initCipher(int mode, SecretBytes kek) throws CryptoException {
        return kek.applyCrypto(kb -> initCipher(mode, kb));
    }

    /** Named initCipher so the CE-001 SpotBugs exclusion (AES/KWP has its own integrity) still matches. */
    private static Cipher initCipher(int mode, byte[] kekBytes) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(mode, new SecretKeySpec(kekBytes, AES));
        return cipher;
    }

    private static void requireKek(SecretBytes kek) throws CryptoException {
        if (kek.length() != KEK_LEN) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
    }
}
