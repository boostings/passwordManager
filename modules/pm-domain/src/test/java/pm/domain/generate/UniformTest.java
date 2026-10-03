package pm.domain.generate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class UniformTest {
    private static final long MAX = Uniform.SPACE - 1;

    @Test
    void limitIsTheLargestMultipleOfTheBound() {
        assertEquals(Uniform.SPACE, Uniform.limit(1));
        assertEquals(Uniform.SPACE, Uniform.limit(256));
        assertEquals(MAX, Uniform.limit(3)); // 2^32 = 1 (mod 3)
        for (int bound : new int[] {3, 10, 26, 85, 94, 8192, Integer.MAX_VALUE}) {
            long limit = Uniform.limit(bound);
            assertEquals(0, limit % bound);
            assertTrue(Uniform.SPACE - limit < bound);
        }
    }

    @Test
    void drawsAtOrAboveTheLimitAreRejectedAndRedrawn() {
        // bound 3: 0xFFFFFFFF is the one rejected value; plain modulo would map it to 0 and bias 0.
        assertEquals(2, Uniform.below(TestRandom.scripted(MAX, 5), 3));
        assertEquals(1, Uniform.below(TestRandom.scripted(MAX, MAX, MAX, 1), 3));
        // bound 2^31 - 1: 2^32 = 2 (mod bound), so the limit is 2^32 - 2 and the top two values are
        // rejected (limit + 1 is MAX).
        int bound = Integer.MAX_VALUE;
        long limit = Uniform.limit(bound);
        assertEquals(2L * bound, limit);
        assertEquals(7, Uniform.below(TestRandom.scripted(limit, limit + 1, MAX, 7), bound));
        // The last accepted value maps to bound - 1.
        assertEquals(bound - 1, Uniform.below(TestRandom.scripted(limit - 1), bound));
    }

    @Test
    void acceptedDrawsAreReducedModuloTheBound() {
        assertEquals(0, Uniform.below(TestRandom.scripted(0), 26));
        assertEquals(25, Uniform.below(TestRandom.scripted(25), 26));
        assertEquals(0, Uniform.below(TestRandom.scripted(26), 26));
        assertEquals(0, Uniform.below(TestRandom.scripted(MAX), 1));
    }

    @Test
    void rejectsBadArguments() {
        assertThrows(IllegalArgumentException.class, () -> Uniform.below(TestRandom.scripted(0), 0));
        assertThrows(IllegalArgumentException.class, () -> Uniform.below(TestRandom.scripted(0), -4));
        assertThrows(NullPointerException.class, () -> Uniform.below(null, 4));
        assertThrows(IllegalArgumentException.class, () -> Uniform.log2(BigInteger.ZERO));
    }

    @Test
    void log2IsExactOnPowersAndCloseOnHugeValues() {
        assertEquals(0.0, Uniform.log2(BigInteger.ONE), 1e-12);
        assertEquals(13.0, Uniform.log2(BigInteger.valueOf(8192)), 1e-12);
        assertEquals(1000.0, Uniform.log2(BigInteger.TWO.pow(1000)), 1e-9);
        assertEquals(1024 * Math.log(94) / Math.log(2), Uniform.log2(BigInteger.valueOf(94).pow(1024)), 1e-6);
    }

    @Test
    void secureSourceFillsTheWholeArray() {
        byte[] out = new byte[64];
        RandomSource.secure().nextBytes(out);
        int nonZero = 0;
        for (byte b : out) {
            nonZero += b == 0 ? 0 : 1;
        }
        assertTrue(nonZero > 32, "64 random bytes are almost never mostly zero");
    }
}
