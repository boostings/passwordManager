package pm.crypto;

/**
 * Recovery key (ADR 0004): 32 random bytes plus a 3-byte SHA-256 checksum, shown as 56 base32
 * characters in 8 dash-separated groups of 7.
 */
@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)
public final class RecoveryKey {
    private RecoveryKey() {
    }

    /** Generates a new 32-byte recovery key. */
    public static SecretBytes generate() {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Formats {@code key} for one-time display. */
    public static SecretChars format(SecretBytes key) {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Parses typed input (case, space, and dash tolerant); a bad checksum yields BAD_INPUT. */
    public static SecretBytes parse(SecretChars typed) throws CryptoException {
        throw new UnsupportedOperationException("M1 stub");
    }
}
