package pm.crypto;

/** AES-256 Key Wrap with Padding (RFC 5649) via the JDK; a wrong KEK fails integrity (ADR 0004). */
@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)
public final class KeyWrap {
    private KeyWrap() {
    }

    /** Wraps {@code key} under {@code kek}. */
    public static byte[] wrap(SecretBytes kek, SecretBytes key) throws CryptoException {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Unwraps; a wrong KEK or tampered input yields {@link CryptoException.Code#AUTH_FAILED}. */
    public static SecretBytes unwrap(SecretBytes kek, byte[] wrapped) throws CryptoException {
        throw new UnsupportedOperationException("M1 stub");
    }
}
