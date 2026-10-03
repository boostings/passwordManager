package pm.domain.generate;

import java.util.Arrays;
import java.util.Objects;
import pm.crypto.SecretChars;

/**
 * Diceware-style passphrase generator (MSC02-J, ADR 0012): each word is an independent uniform draw
 * from the {@value Wordlist#SIZE}-word {@link Wordlist}, by rejection sampling, so a passphrase of
 * {@code n} words carries exactly {@code 13 n} bits. The separator is fixed by the policy and adds no
 * entropy.
 */
public final class PassphraseGenerator {
    private final RandomSource rng;

    /** Returns a generator on the injected source; tests pass a fixed-seed DRBG. */
    public PassphraseGenerator(RandomSource rng) {
        this.rng = Objects.requireNonNull(rng, "rng");
    }

    /** Returns a generator on {@link RandomSource#secure()}. */
    public static PassphraseGenerator secure() {
        return new PassphraseGenerator(RandomSource.secure());
    }

    /** Generates one passphrase; the caller owns and must close the result. */
    public Generated generate(PassphrasePolicy policy) {
        Objects.requireNonNull(policy, "policy");
        int[] picked = new int[policy.words()];
        int length = policy.words() - 1;
        for (int i = 0; i < picked.length; i++) {
            picked[i] = Uniform.below(rng, Wordlist.SIZE);
            length += Wordlist.word(picked[i]).length();
        }
        // Written straight into an exactly sized array: no growing builder leaves partial copies.
        char[] out = new char[length];
        int at = 0;
        for (int i = 0; i < picked.length; i++) {
            if (i > 0) {
                out[at++] = policy.separator();
            }
            String word = Wordlist.word(picked[i]);
            word.getChars(0, word.length(), out, at);
            at += word.length();
        }
        Arrays.fill(picked, 0);
        return new Generated(SecretChars.takeOwnership(out), entropyBits(policy));
    }

    /** Entropy of {@code policy} in bits: 13 per word. */
    public static double entropyBits(PassphrasePolicy policy) {
        return policy.words() * Wordlist.BITS_PER_WORD;
    }
}
