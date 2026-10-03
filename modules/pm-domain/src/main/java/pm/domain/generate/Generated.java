package pm.domain.generate;

import java.util.Objects;
import pm.crypto.SecretChars;

/**
 * A generated password or passphrase and its entropy. Owns the secret: {@link #close()} zero-fills it
 * (ADR 0008).
 *
 * @param secret the generated characters
 * @param entropyBits base-2 logarithm of the number of outputs the policy can produce, each equally
 *     likely; this is the guessing cost for an attacker who knows the policy
 */
public record Generated(SecretChars secret, double entropyBits) implements AutoCloseable {
    /**
     * Checks the components.
     *
     * @throws NullPointerException if {@code secret} is null
     * @throws IllegalArgumentException if {@code entropyBits} is negative or not finite
     */
    public Generated {
        Objects.requireNonNull(secret, "secret");
        if (!Double.isFinite(entropyBits) || entropyBits < 0) {
            throw new IllegalArgumentException("entropyBits must be finite and non-negative");
        }
    }

    /** Zero-fills the secret. Idempotent. */
    @Override
    public void close() {
        secret.close();
    }
}
