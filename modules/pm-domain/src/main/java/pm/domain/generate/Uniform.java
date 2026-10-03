package pm.domain.generate;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/** Unbiased index sampling and entropy arithmetic shared by the generators (ADR 0012). */
final class Uniform {
    /** Number of distinct 32-bit draws. */
    static final long SPACE = 1L << 32;
    private static final int DRAW_BYTES = 4;
    private static final int MIN_BOUND = 1;
    private static final int BYTE_MASK = 0xff;
    private static final int BITS_PER_BYTE = 8;
    /** Bits kept when converting a huge integer to a double for {@link #log2}. */
    private static final int MANTISSA_BITS = 62;

    private Uniform() {
    }

    /**
     * Returns an integer uniformly distributed in {@code [0, bound)}.
     *
     * <p>Rejection sampling: a 32-bit draw {@code x} is accepted only below the largest multiple of
     * {@code bound} that fits in 2^32, so every residue {@code x % bound} has exactly the same number
     * of preimages. Draws at or above that limit are discarded and redrawn; the probability of a
     * rejection is below one half for every bound, so the expected number of draws is below two.
     *
     * @throws IllegalArgumentException if {@code bound < 1}
     */
    static int below(RandomSource rng, int bound) {
        Objects.requireNonNull(rng, "rng");
        if (bound < MIN_BOUND) {
            throw new IllegalArgumentException("bound must be positive");
        }
        long limit = limit(bound);
        byte[] draw = new byte[DRAW_BYTES];
        long x;
        do {
            rng.nextBytes(draw);
            x = toUnsigned(draw);
        } while (x >= limit);
        Arrays.fill(draw, (byte) 0);
        return (int) (x % bound);
    }

    /** The exclusive upper limit of accepted draws for {@code bound}. */
    static long limit(int bound) {
        return SPACE - SPACE % bound;
    }

    /** Big-endian unsigned value of a four-byte draw. */
    static long toUnsigned(byte[] draw) {
        long x = 0;
        for (byte b : draw) {
            x = (x << BITS_PER_BYTE) | (b & BYTE_MASK);
        }
        return x;
    }

    /** Base-2 logarithm of a positive integer of any size. */
    static double log2(BigInteger n) {
        if (n.signum() <= 0) {
            throw new IllegalArgumentException("log2 of a non-positive number");
        }
        int shift = Math.max(0, n.bitLength() - MANTISSA_BITS);
        double head = n.shiftRight(shift).doubleValue();
        return shift + Math.log(head) / Math.log(2);
    }
}
