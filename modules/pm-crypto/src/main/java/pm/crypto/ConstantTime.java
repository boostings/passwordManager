package pm.crypto;

import java.security.MessageDigest;
import java.util.Objects;

/**
 * Constant-time comparison for code outside pm-crypto (SR-016, MSC61-J). {@code java.security}
 * is reserved to pm-crypto (SR-017), and short-circuiting comparisons such as {@code Arrays.equals}
 * are banned on byte arrays by ArchUnit, so other modules compare tags, magic values and digests
 * here.
 */
public final class ConstantTime {
    private ConstantTime() {
    }

    /**
     * SR-016: whether {@code a} and {@code b} have the same length and content, via
     * {@link MessageDigest#isEqual}, whose running time depends only on the length of {@code a}
     * (the expected value), not on where the arrays differ.
     *
     * @throws NullPointerException if either argument is null
     */
    public static boolean equals(byte[] a, byte[] b) {
        Objects.requireNonNull(a, "a");
        Objects.requireNonNull(b, "b");
        return MessageDigest.isEqual(a, b);
    }
}
