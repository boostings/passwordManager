package pm.domain.generate;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import pm.crypto.SecretChars;

/**
 * Character-class password generator (MSC02-J, ADR 0012).
 *
 * <p>Each character is an independent uniform draw from the union of the chosen alphabets, by
 * rejection sampling ({@link Uniform#below}). A candidate that lacks one of the chosen classes is
 * zero-filled and discarded whole, and a fresh candidate is drawn. Discarding whole candidates keeps
 * the output uniform over exactly the set of passwords that satisfy the policy; forcing one character
 * per class into fixed or shuffled slots would not, and would make the reported entropy wrong.
 *
 * <p>Not thread-safe only in the sense that the injected {@link RandomSource} may not be; the
 * {@link RandomSource#secure()} source is thread-safe.
 */
public final class PasswordGenerator {
    private final RandomSource rng;

    /** Returns a generator on the injected source; tests pass a fixed-seed DRBG. */
    public PasswordGenerator(RandomSource rng) {
        this.rng = Objects.requireNonNull(rng, "rng");
    }

    /** Returns a generator on {@link RandomSource#secure()}. */
    public static PasswordGenerator secure() {
        return new PasswordGenerator(RandomSource.secure());
    }

    /** Generates one password; the caller owns and must close the result. */
    public Generated generate(PasswordPolicy policy) {
        Objects.requireNonNull(policy, "policy");
        List<String> alphabets = alphabets(policy);
        String union = String.join("", alphabets);
        int[] classOf = classIndex(alphabets);
        int required = (1 << alphabets.size()) - 1;
        char[] candidate = new char[policy.length()];
        int seen;
        do {
            seen = 0;
            for (int i = 0; i < candidate.length; i++) {
                int pick = Uniform.below(rng, union.length());
                candidate[i] = union.charAt(pick);
                seen |= 1 << classOf[pick];
            }
            if (seen != required) {
                Arrays.fill(candidate, '\0');
            }
        } while (seen != required);
        return new Generated(SecretChars.takeOwnership(candidate), entropyBits(policy));
    }

    /**
     * Entropy of {@code policy} in bits: log2 of the number of strings of the given length over the
     * union alphabet that contain at least one character of every chosen class, counted exactly by
     * inclusion-exclusion over the classes left out.
     */
    public static double entropyBits(PasswordPolicy policy) {
        return Uniform.log2(validCount(policy));
    }

    /** The exact number of passwords {@code policy} can produce. */
    static BigInteger validCount(PasswordPolicy policy) {
        List<String> alphabets = alphabets(policy);
        int k = alphabets.size();
        int total = alphabets.stream().mapToInt(String::length).sum();
        BigInteger count = BigInteger.ZERO;
        for (int missing = 0; missing < 1 << k; missing++) {
            int size = total;
            for (int c = 0; c < k; c++) {
                if ((missing & 1 << c) != 0) {
                    size -= alphabets.get(c).length();
                }
            }
            BigInteger term = BigInteger.valueOf(size).pow(policy.length());
            count = Integer.bitCount(missing) % 2 == 0 ? count.add(term) : count.subtract(term);
        }
        return count;
    }

    /** The chosen alphabets in {@link CharClass} declaration order, so output is reproducible. */
    private static List<String> alphabets(PasswordPolicy policy) {
        List<String> out = new ArrayList<>();
        for (CharClass c : CharClass.values()) {
            if (policy.classes().contains(c)) {
                out.add(c.alphabet(policy.excludeAmbiguous()));
            }
        }
        return out;
    }

    /** For each index into the concatenated alphabets, the position of its class in the list. */
    private static int[] classIndex(List<String> alphabets) {
        int[] out = new int[alphabets.stream().mapToInt(String::length).sum()];
        int at = 0;
        for (int c = 0; c < alphabets.size(); c++) {
            int end = at + alphabets.get(c).length();
            Arrays.fill(out, at, end, c);
            at = end;
        }
        return out;
    }
}
