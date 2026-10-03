package pm.browser.bridge;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.IntFunction;
import pm.browser.host.Request;
import pm.crypto.Csprng;
import pm.crypto.SecretChars;

/**
 * Generates a password for a {@link Request.Policy}: each character uniform over the chosen
 * classes by rejection sampling, and every chosen class present at least once (a candidate
 * without one is discarded and drawn again, which keeps the distribution uniform over the valid
 * passwords).
 */
public final class PasswordGenerator {
    /** Lowercase letters. */
    public static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    /** Uppercase letters. */
    public static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    /** Digits. */
    public static final String DIGITS = "0123456789";
    /** ASCII punctuation accepted by common sites (no quote, backslash, backtick or space). */
    public static final String SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
    /** Candidates drawn before giving up; unreachable with a real random source. */
    static final int MAX_ATTEMPTS = 64;

    private static final int BYTE_VALUES = 256;

    private final IntFunction<byte[]> random;

    /**
     * Uses {@code random}, which returns that many fresh random bytes per call (tests pass a
     * fixed sequence).
     */
    public PasswordGenerator(IntFunction<byte[]> random) {
        this.random = Objects.requireNonNull(random, "random");
    }

    /** A generator over the platform CSPRNG. */
    public static PasswordGenerator secure() {
        return new PasswordGenerator(Csprng::bytes);
    }

    /**
     * A new password for {@code policy}.
     *
     * @throws IllegalStateException {@code GENERATOR_EXHAUSTED} if the random source never yields
     *     a password containing every chosen class
     */
    public SecretChars generate(Request.Policy policy) {
        List<String> classes = new ArrayList<>();
        addIf(classes, policy.lower(), LOWER);
        addIf(classes, policy.upper(), UPPER);
        addIf(classes, policy.digits(), DIGITS);
        addIf(classes, policy.symbols(), SYMBOLS);
        String alphabet = String.join("", classes);
        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
            char[] candidate = new char[policy.length()];
            for (int i = 0; i < candidate.length; i++) {
                candidate[i] = alphabet.charAt(uniform(alphabet.length()));
            }
            if (containsEach(candidate, classes)) {
                return SecretChars.takeOwnership(candidate);
            }
            Arrays.fill(candidate, '\0');
        }
        throw new IllegalStateException("GENERATOR_EXHAUSTED");
    }

    /** A uniform index below {@code n} (n ≤ 256): bytes at or above the last full multiple are redrawn. */
    private int uniform(int n) {
        int limit = BYTE_VALUES - BYTE_VALUES % n;
        while (true) {
            byte[] one = random.apply(1);
            int value = one[0] & 0xff;
            Arrays.fill(one, (byte) 0);
            if (value < limit) {
                return value % n;
            }
        }
    }

    private static boolean containsEach(char[] candidate, List<String> classes) {
        for (String cls : classes) {
            boolean found = false;
            for (char c : candidate) {
                found |= cls.indexOf(c) >= 0;
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }

    private static void addIf(List<String> classes, boolean wanted, String cls) {
        if (wanted) {
            classes.add(cls);
        }
    }
}
