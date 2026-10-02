package pm.crypto;

/**
 * AES-256-GCM with a zero nonce (ADR 0005). Safe ONLY because every key passed here is a fresh
 * per-save HKDF output that encrypts exactly one message.
 */
@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)
public final class Aead {
    private Aead() {
    }

    /** Encrypts {@code plaintext}; returns ciphertext followed by the 16-byte tag. */
    public static byte[] sealWithFreshKey(SecretBytes freshKey, SecretBytes plaintext, byte[] aad) throws CryptoException {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Decrypts and verifies; any tampering yields {@link CryptoException.Code#AUTH_FAILED}. */
    public static SecretBytes openWithFreshKey(SecretBytes key, byte[] ciphertextAndTag, byte[] aad) throws CryptoException {
        throw new UnsupportedOperationException("M1 stub");
    }
}
