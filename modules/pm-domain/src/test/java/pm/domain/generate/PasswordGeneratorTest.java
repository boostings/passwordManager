package pm.domain.generate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretChars;

class PasswordGeneratorTest {
    private static final int SAMPLES = 20_000;
    private static final Set<CharClass> ALL = EnumSet.allOf(CharClass.class);

    private static String reveal(Generated g) {
        StringBuilder sb = new StringBuilder();
        g.secret().withChars(sb::append);
        return sb.toString();
    }

    @Test
    void policyValidation() {
        assertThrows(IllegalArgumentException.class, () -> new PasswordPolicy(3, Set.of(CharClass.LOWER), false));
        assertThrows(IllegalArgumentException.class, () -> new PasswordPolicy(1025, Set.of(CharClass.LOWER), false));
        assertThrows(IllegalArgumentException.class, () -> new PasswordPolicy(16, Set.of(), false));
        assertThrows(NullPointerException.class, () -> new PasswordPolicy(16, null, false));
        assertThrows(IllegalArgumentException.class, () -> new PasswordPolicy(-1, ALL, false));
        PasswordPolicy min = new PasswordPolicy(4, ALL, true);
        assertEquals(4, min.length());
        PasswordPolicy max = new PasswordPolicy(1024, Set.of(CharClass.DIGIT), false);
        assertEquals(1024, max.length());
        Set<CharClass> mutable = EnumSet.of(CharClass.LOWER);
        PasswordPolicy copy = new PasswordPolicy(8, mutable, false);
        mutable.add(CharClass.UPPER);
        assertEquals(Set.of(CharClass.LOWER), copy.classes());
        assertThrows(UnsupportedOperationException.class, () -> copy.classes().add(CharClass.DIGIT));
        assertEquals(new PasswordPolicy(20, ALL, false), PasswordPolicy.defaults());
        assertThrows(NullPointerException.class, () -> new PasswordGenerator(null));
        assertThrows(NullPointerException.class, () -> PasswordGenerator.secure().generate(null));
    }

    @Test
    void ambiguousCharactersAreExcludedOnRequest() {
        int total = 0;
        for (CharClass c : CharClass.values()) {
            String a = c.alphabet(true);
            total += a.length();
            for (char x : CharClass.AMBIGUOUS.toCharArray()) {
                assertTrue(a.indexOf(x) < 0, c + " kept " + x);
            }
        }
        assertEquals(94 - CharClass.AMBIGUOUS.length(), total);
        assertEquals(94, CharClass.LOWER.alphabet(false).length() + CharClass.UPPER.alphabet(false).length()
                + CharClass.DIGIT.alphabet(false).length() + CharClass.SYMBOL.alphabet(false).length());
        PasswordGenerator gen = new PasswordGenerator(TestRandom.drbg(1));
        for (int i = 0; i < 2000; i++) {
            try (Generated g = gen.generate(new PasswordPolicy(16, ALL, true))) {
                String s = reveal(g);
                for (char x : CharClass.AMBIGUOUS.toCharArray()) {
                    assertTrue(s.indexOf(x) < 0);
                }
            }
        }
    }

    @Test
    void everyChosenClassAppearsAndNoOther() {
        PasswordGenerator gen = new PasswordGenerator(TestRandom.drbg(2));
        Set<CharClass> chosen = EnumSet.of(CharClass.UPPER, CharClass.DIGIT);
        for (int i = 0; i < 2000; i++) {
            try (Generated g = gen.generate(new PasswordPolicy(4, ALL, false))) {
                String s = reveal(g);
                assertEquals(4, s.length());
                for (CharClass c : CharClass.values()) {
                    assertTrue(s.chars().anyMatch(ch -> c.alphabet(false).indexOf(ch) >= 0), c::name);
                }
            }
            try (Generated g = gen.generate(new PasswordPolicy(6, chosen, false))) {
                String s = reveal(g);
                assertTrue(s.chars().allMatch(ch -> Character.isUpperCase(ch) || Character.isDigit(ch)));
                assertTrue(s.chars().anyMatch(Character::isDigit));
                assertTrue(s.chars().anyMatch(Character::isUpperCase));
            }
        }
    }

    @Test
    void aCandidateMissingAClassIsDiscardedWhole() {
        // LOWER + DIGIT, length 4: union "a..z0..9" (36). The first candidate is all letters
        // (indices 0,1,2,3), so it lacks a digit and must be redrawn in full, not patched.
        PasswordPolicy policy = new PasswordPolicy(4, EnumSet.of(CharClass.LOWER, CharClass.DIGIT), false);
        PasswordGenerator gen = new PasswordGenerator(TestRandom.scripted(0, 1, 2, 3, 26, 25, 35, 0));
        try (Generated g = gen.generate(policy)) {
            assertEquals("0z9a", reveal(g));
        }
    }

    @Test
    void sameSeedSameOutputDifferentSeedDifferentOutput() {
        PasswordPolicy p = PasswordPolicy.defaults();
        try (Generated a = new PasswordGenerator(TestRandom.drbg(7)).generate(p);
                Generated b = new PasswordGenerator(TestRandom.drbg(7)).generate(p);
                Generated c = new PasswordGenerator(TestRandom.drbg(8)).generate(p)) {
            assertEquals(reveal(a), reveal(b));
            assertNotEquals(reveal(a), reveal(c));
        }
    }

    @Test
    void resultIsOwnedAndZeroedOnClose() {
        try (SecretChars secret = SecretChars.takeOwnership(new char[] {'x'})) {
            new Generated(secret, 1).close();
            assertTrue(secret.isClosed());
            assertThrows(IllegalArgumentException.class, () -> new Generated(secret, -1));
            assertThrows(IllegalArgumentException.class, () -> new Generated(secret, Double.NaN));
            assertThrows(IllegalArgumentException.class, () -> new Generated(secret, Double.POSITIVE_INFINITY));
        }
        assertThrows(NullPointerException.class, () -> new Generated(null, 1));
    }

    @Test
    void entropyIsTheExactCountOfValidPasswords() {
        // One class: no constraint, so exactly L * log2(N).
        assertEquals(16 * Math.log(26) / Math.log(2),
                PasswordGenerator.entropyBits(new PasswordPolicy(16, Set.of(CharClass.LOWER), false)), 1e-9);
        // Two classes, inclusion-exclusion by hand: 36^4 - 26^4 - 10^4.
        PasswordPolicy two = new PasswordPolicy(4, EnumSet.of(CharClass.LOWER, CharClass.DIGIT), false);
        assertEquals(BigInteger.valueOf(36L * 36 * 36 * 36 - 26L * 26 * 26 * 26 - 10_000), PasswordGenerator.validCount(two));
        // Brute force for a small case with ambiguity removal: DIGIT + SYMBOL, length 4 (8 + 29).
        PasswordPolicy small = new PasswordPolicy(4, EnumSet.of(CharClass.DIGIT, CharClass.SYMBOL), true);
        String d = CharClass.DIGIT.alphabet(true);
        String u = d + CharClass.SYMBOL.alphabet(true);
        long brute = 0;
        int n = u.length();
        for (int i = 0; i < n * n * n * n; i++) {
            boolean digit = false;
            boolean symbol = false;
            for (int k = 0, v = i; k < 4; k++, v /= n) {
                boolean isDigit = v % n < d.length();
                digit |= isDigit;
                symbol |= !isDigit;
            }
            brute += digit && symbol ? 1 : 0;
        }
        assertEquals(BigInteger.valueOf(brute), PasswordGenerator.validCount(small));
        // Defaults: 20 characters over 94, a little under 20 * log2(94) = 131.1.
        double defaults = PasswordGenerator.entropyBits(PasswordPolicy.defaults());
        assertTrue(defaults > 130.5 && defaults < 131.1, () -> "defaults " + defaults);
        try (Generated g = new PasswordGenerator(TestRandom.drbg(3)).generate(PasswordPolicy.defaults())) {
            assertEquals(defaults, g.entropyBits(), 0.0);
        }
    }

    /** MSC02-J acceptance: per-position chi-square over a single class (no conditioning). */
    @Test
    void chiSquareUniformPerPosition() {
        int length = 12;
        PasswordPolicy policy = new PasswordPolicy(length, EnumSet.of(CharClass.LOWER), false);
        String alphabet = CharClass.LOWER.alphabet(false);
        long[][] counts = new long[length][alphabet.length()];
        long[] pooled = new long[alphabet.length()];
        PasswordGenerator gen = new PasswordGenerator(TestRandom.drbg(42));
        for (int i = 0; i < SAMPLES; i++) {
            try (Generated g = gen.generate(policy)) {
                String s = reveal(g);
                for (int p = 0; p < length; p++) {
                    int idx = alphabet.indexOf(s.charAt(p));
                    counts[p][idx]++;
                    pooled[idx]++;
                }
            }
        }
        double limit = TestRandom.critical(alphabet.length() - 1);
        for (int p = 0; p < length; p++) {
            double chi = TestRandom.chiSquare(counts[p]);
            int pos = p;
            assertTrue(chi < limit, () -> "position " + pos + " chi-square " + chi + " >= " + limit);
        }
        double chi = TestRandom.chiSquare(pooled);
        assertTrue(chi < limit, () -> "pooled chi-square " + chi);
    }

    /**
     * With all four classes the at-least-one rule shifts weight between classes, but by symmetry every
     * character within one class stays equally likely at every position. Checks that, per class.
     */
    @Test
    void chiSquareUniformWithinEachClass() {
        PasswordPolicy policy = new PasswordPolicy(10, ALL, true);
        PasswordGenerator gen = new PasswordGenerator(TestRandom.drbg(43));
        CharClass[] classes = CharClass.values();
        long[][] counts = new long[classes.length][];
        for (int c = 0; c < classes.length; c++) {
            counts[c] = new long[classes[c].alphabet(true).length()];
        }
        for (int i = 0; i < SAMPLES; i++) {
            try (Generated g = gen.generate(policy)) {
                for (char ch : reveal(g).toCharArray()) {
                    for (int c = 0; c < classes.length; c++) {
                        int idx = classes[c].alphabet(true).indexOf(ch);
                        if (idx >= 0) {
                            counts[c][idx]++;
                        }
                    }
                }
            }
        }
        for (int c = 0; c < classes.length; c++) {
            double chi = TestRandom.chiSquare(counts[c]);
            double limit = TestRandom.critical(counts[c].length - 1);
            CharClass cls = classes[c];
            assertTrue(chi < limit, () -> cls + " chi-square " + chi + " >= " + limit);
        }
    }

    /** The statistic must actually catch bias: plain modulo of a byte over 94 characters fails it. */
    @Test
    void chiSquareDetectsModuloBias() {
        RandomSource rng = TestRandom.drbg(44);
        long[] counts = new long[94];
        byte[] one = new byte[1];
        for (int i = 0; i < 200_000; i++) {
            rng.nextBytes(one);
            counts[(one[0] & 0xff) % 94]++;
        }
        assertTrue(TestRandom.chiSquare(counts) > TestRandom.critical(93));
    }

    @Test
    void secureRandomSmoke() {
        PasswordGenerator gen = PasswordGenerator.secure();
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            try (Generated g = gen.generate(PasswordPolicy.defaults())) {
                String s = reveal(g);
                assertEquals(20, s.length());
                assertTrue(seen.add(s), "a 131-bit password repeated");
            }
        }
    }
}
