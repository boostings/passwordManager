package pm.crypto;

import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** AES-256 Key Wrap with Padding (RFC 5649) via the JDK; a wrong KEK fails integrity (ADR 0004). */
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
        byte[] wrapped = key.apply(in -> doFinalOrEmpty(cipher, in));
        if (wrapped.length == 0) {
            throw new CryptoException(CryptoException.Code.INTERNAL);
        }
        return wrapped;
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
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(TRANSFORMATION);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoException.Code.INTERNAL);
        }
        boolean ok = kek.apply(kb -> initOrFalse(cipher, mode, kb));
        if (!ok) {
            throw new CryptoException(CryptoException.Code.INTERNAL);
        }
        return cipher;
    }

    private static void requireKek(SecretBytes kek) throws CryptoException {
        if (kek.length() != KEK_LEN) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
    }

    private static boolean initOrFalse(Cipher cipher, int mode, byte[] kekBytes) {
        try {
            SecretKeySpec spec = new SecretKeySpec(kekBytes, AES);
            cipher.init(mode, spec);
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static byte[] doFinalOrEmpty(Cipher cipher, byte[] in) {
        try {
            return cipher.doFinal(in);
        } catch (GeneralSecurityException e) {
            return new byte[0];
        }
    }
}
