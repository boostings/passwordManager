package pm.crypto;

import java.security.SecureRandom;
import java.util.UUID;

/** The only {@link SecureRandom} in the codebase (SR-017, MSC02-J). Thread-safe. */
public final class Csprng {
    private static final SecureRandom RNG = new SecureRandom();
    private static final int MIN_BYTES = 1;
    private static final int MAX_BYTES = 1024;

    private Csprng() {
    }

    /** Returns {@code n} random bytes, {@code 1 <= n <= 1024}. */
    public static byte[] bytes(int n) {
        if (n < MIN_BYTES || n > MAX_BYTES) {
            throw new IllegalArgumentException("BAD_LENGTH");
        }
        byte[] out = new byte[n];
        RNG.nextBytes(out);
        return out;
    }

    /** Returns {@code n} random bytes as an owned secret. */
    public static SecretBytes secretBytes(int n) {
        return SecretBytes.takeOwnership(bytes(n));
    }

    /** Returns a version-4 UUID drawn from a {@link SecureRandom}. */
    public static UUID uuid() {
        return UUID.randomUUID();
    }
}
