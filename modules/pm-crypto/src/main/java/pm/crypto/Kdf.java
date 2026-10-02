package pm.crypto;

import java.time.Duration;

/** Key derivation: Argon2id for passphrases (ADR 0007), HKDF-SHA256 for high-entropy inputs (ADR 0004). */
@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)
public final class Kdf {
    private Kdf() {
    }

    /** Argon2id (RFC 9106) with a 32-byte salt and 32-byte output. */
    public static SecretBytes argon2id(SecretBytes password, byte[] salt32, Argon2Params params) throws CryptoException {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Benchmarks this machine and returns parameters near {@code target}, never below the floor. */
    public static Argon2Params tune(Duration target) {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** HKDF-SHA256 (RFC 5869); {@code salt} may be null; {@code outLen} in 1..8160. */
    public static SecretBytes hkdfSha256(SecretBytes ikm, byte[] salt, byte[] info, int outLen) throws CryptoException {
        throw new UnsupportedOperationException("M1 stub");
    }
}
