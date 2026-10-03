package pm.domain.generate;

import java.util.Arrays;
import pm.crypto.Csprng;

/**
 * Source of uniformly random bytes for the generators (MSC02-J).
 *
 * <p>Production code uses {@link #secure()}, which reads {@code pm.crypto.Csprng}, the only
 * {@code SecureRandom} in the codebase (SR-017). Tests inject a fixed-seed deterministic generator so
 * statistical checks are reproducible. Implementations must fill the whole array with independent,
 * uniformly distributed bytes.
 */
@FunctionalInterface
public interface RandomSource {
    /** Fills {@code out} with random bytes. */
    void nextBytes(byte[] out);

    /** Returns the {@code SecureRandom}-backed source used in production. */
    static RandomSource secure() {
        return out -> {
            byte[] drawn = Csprng.bytes(out.length);
            System.arraycopy(drawn, 0, out, 0, out.length);
            Arrays.fill(drawn, (byte) 0);
        };
    }
}
