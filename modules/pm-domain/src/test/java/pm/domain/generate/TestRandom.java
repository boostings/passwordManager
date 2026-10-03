package pm.domain.generate;

import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import pm.crypto.CryptoException;
import pm.crypto.Hmac;
import pm.crypto.SecretBytes;

/** Deterministic {@link RandomSource}s for tests. */
final class TestRandom {
    private static final int SEED_BYTES = 32;
    private static final int BYTE_MASK = 0xff;

    private TestRandom() {
    }

    /**
     * A fixed-seed DRBG: HMAC-SHA256 in counter mode under a key derived from {@code seed}. Its
     * output is indistinguishable from uniform for any test, and identical on every run.
     */
    static RandomSource drbg(long seed) {
        byte[] key = new byte[SEED_BYTES];
        Arrays.fill(key, (byte) seed);
        ByteBuffer.wrap(key).putLong(seed);
        SecretBytes k = SecretBytes.takeOwnership(key);
        return new RandomSource() {
            private long counter;
            private byte[] block = new byte[0];
            private int used;

            @Override
            public void nextBytes(byte[] out) {
                for (int i = 0; i < out.length; i++) {
                    if (used == block.length) {
                        block = next();
                        used = 0;
                    }
                    out[i] = block[used++];
                }
            }

            private byte[] next() {
                try {
                    return Hmac.sha256(k, ByteBuffer.allocate(Long.BYTES).putLong(counter++).array());
                } catch (CryptoException e) {
                    throw new IllegalStateException(e);
                }
            }
        };
    }

    /** A source that returns the given 32-bit big-endian values in order, then fails. */
    static RandomSource scripted(long... values) {
        Deque<Long> queue = new ArrayDeque<>();
        for (long v : values) {
            queue.add(v);
        }
        return out -> {
            if (out.length != Integer.BYTES || queue.isEmpty()) {
                throw new IllegalStateException("script exhausted or unexpected draw size");
            }
            long v = queue.remove();
            for (int i = Integer.BYTES - 1; i >= 0; i--) {
                out[i] = (byte) (v & BYTE_MASK);
                v >>>= Byte.SIZE;
            }
        };
    }

    /** Chi-square statistic of {@code counts} against a uniform expectation. */
    static double chiSquare(long[] counts) {
        long total = Arrays.stream(counts).sum();
        double expected = (double) total / counts.length;
        double chi = 0;
        for (long c : counts) {
            double d = c - expected;
            chi += d * d / expected;
        }
        return chi;
    }

    /**
     * Upper critical value of the chi-square distribution with {@code df} degrees of freedom at
     * p = 0.0001 (Wilson-Hilferty approximation, accurate to well under 1% for df >= 9).
     */
    static double critical(int df) {
        double z = 3.719;
        double a = 2.0 / (9.0 * df);
        double t = 1 - a + z * Math.sqrt(a);
        return df * t * t * t;
    }
}
