package pm.domain.generate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class PassphraseGeneratorTest {
    private static final int SAMPLES = 30_000;

    private static String reveal(Generated g) {
        StringBuilder sb = new StringBuilder();
        g.secret().withChars(sb::append);
        return sb.toString();
    }

    private static int[] indices(String phrase, char separator, int words) {
        String[] parts = phrase.split(Pattern.quote(String.valueOf(separator)), -1);
        assertEquals(words, parts.length);
        int[] out = new int[words];
        for (int i = 0; i < words; i++) {
            out[i] = Collections.binarySearch(Wordlist.words(), parts[i]);
            assertTrue(out[i] >= 0, "not a list word");
        }
        return out;
    }

    @Test
    void policyValidation() {
        assertThrows(IllegalArgumentException.class, () -> new PassphrasePolicy(2, '-'));
        assertThrows(IllegalArgumentException.class, () -> new PassphrasePolicy(65, '-'));
        assertThrows(IllegalArgumentException.class, () -> new PassphrasePolicy(6, 'a'));
        assertThrows(IllegalArgumentException.class, () -> new PassphrasePolicy(6, 'z'));
        assertThrows(IllegalArgumentException.class, () -> new PassphrasePolicy(6, '\n'));
        assertThrows(IllegalArgumentException.class, () -> new PassphrasePolicy(6, '\u007f'));
        assertThrows(IllegalArgumentException.class, () -> new PassphrasePolicy(6, 'é'));
        for (char ok : new char[] {' ', '~', '-', '.', 'A', 'Z', '7'}) {
            assertEquals(ok, new PassphrasePolicy(3, ok).separator());
        }
        assertEquals(64, new PassphrasePolicy(64, ' ').words());
        assertEquals(new PassphrasePolicy(6, '-'), PassphrasePolicy.defaults());
        assertThrows(NullPointerException.class, () -> new PassphraseGenerator(null));
        assertThrows(NullPointerException.class, () -> PassphraseGenerator.secure().generate(null));
    }

    @Test
    void bundledWordlistHoldsItsInvariants() {
        List<String> words = Wordlist.words();
        assertEquals(Wordlist.SIZE, words.size());
        assertEquals(Wordlist.SIZE, new HashSet<>(words).size());
        assertEquals(Wordlist.BITS_PER_WORD, Math.log(Wordlist.SIZE) / Math.log(2), 1e-12);
        assertTrue(words.stream().allMatch(w -> w.matches("[a-z]{4,5}")));
        assertEquals(words.get(0), Wordlist.word(0));
        assertThrows(UnsupportedOperationException.class, () -> words.set(0, "aaaa"));
        assertThrows(IndexOutOfBoundsException.class, () -> Wordlist.word(Wordlist.SIZE));
    }

    @Test
    void wordlistValidationRejectsCorruptLists() {
        List<String> good = new ArrayList<>(Wordlist.words());
        assertEquals(good, Wordlist.validate(good));
        assertThrows(IllegalStateException.class, () -> Wordlist.validate(good.subList(1, good.size())));
        List<String> dup = new ArrayList<>(good);
        dup.set(1, dup.get(0));
        assertThrows(IllegalStateException.class, () -> Wordlist.validate(dup));
        List<String> unsorted = new ArrayList<>(good);
        Collections.swap(unsorted, 10, 20);
        assertThrows(IllegalStateException.class, () -> Wordlist.validate(unsorted));
        List<String> upper = new ArrayList<>(good);
        upper.set(0, "AAAA");
        assertThrows(IllegalStateException.class, () -> Wordlist.validate(upper));
        List<String> longWord = new ArrayList<>(good);
        longWord.set(good.size() - 1, "zzzzzzz");
        assertThrows(IllegalStateException.class, () -> Wordlist.validate(longWord));
    }

    @Test
    void wordsAreJoinedBySeparatorAndEntropyIsThirteenBitsPerWord() {
        PassphraseGenerator gen = new PassphraseGenerator(TestRandom.drbg(5));
        PassphrasePolicy policy = new PassphrasePolicy(7, '.');
        try (Generated g = gen.generate(policy)) {
            indices(reveal(g), '.', 7);
            assertEquals(91.0, g.entropyBits(), 0.0);
        }
        assertEquals(78.0, PassphraseGenerator.entropyBits(PassphrasePolicy.defaults()), 0.0);
        // Scripted indices pick known words: index 0 and SIZE - 1.
        PassphraseGenerator fixed = new PassphraseGenerator(TestRandom.scripted(0, Wordlist.SIZE - 1, 0));
        try (Generated g = fixed.generate(new PassphrasePolicy(3, ' '))) {
            String expected = Wordlist.word(0) + " " + Wordlist.word(Wordlist.SIZE - 1) + " " + Wordlist.word(0);
            assertEquals(expected, reveal(g));
        }
    }

    @Test
    void wordIndexDrawsUseRejectionSampling() {
        // 2^32 is a multiple of 8192, so no draw is ever rejected and the index is x mod 8192.
        assertEquals(Uniform.SPACE, Uniform.limit(Wordlist.SIZE));
        PassphraseGenerator gen = new PassphraseGenerator(TestRandom.scripted(Uniform.SPACE - 1, 8192, 8193));
        try (Generated g = gen.generate(new PassphrasePolicy(3, '-'))) {
            assertEquals(Wordlist.word(Wordlist.SIZE - 1) + "-" + Wordlist.word(0) + "-" + Wordlist.word(1), reveal(g));
        }
    }

    /** MSC02-J acceptance: chi-square over word indices, overall and per word position. */
    @Test
    void chiSquareUniformOverWords() {
        int words = 6;
        int buckets = 256;
        PassphrasePolicy policy = new PassphrasePolicy(words, '-');
        PassphraseGenerator gen = new PassphraseGenerator(TestRandom.drbg(99));
        long[] all = new long[Wordlist.SIZE];
        long[][] perPosition = new long[words][buckets];
        for (int i = 0; i < SAMPLES; i++) {
            try (Generated g = gen.generate(policy)) {
                int[] idx = indices(reveal(g), '-', words);
                for (int p = 0; p < words; p++) {
                    all[idx[p]]++;
                    perPosition[p][idx[p] * buckets / Wordlist.SIZE]++;
                }
            }
        }
        double chiAll = TestRandom.chiSquare(all);
        double limitAll = TestRandom.critical(Wordlist.SIZE - 1);
        assertTrue(chiAll < limitAll, () -> "word chi-square " + chiAll + " >= " + limitAll);
        double limit = TestRandom.critical(buckets - 1);
        for (int p = 0; p < words; p++) {
            double chi = TestRandom.chiSquare(perPosition[p]);
            int pos = p;
            assertTrue(chi < limit, () -> "position " + pos + " chi-square " + chi + " >= " + limit);
        }
    }

    @Test
    void secureRandomSmoke() {
        PassphraseGenerator gen = PassphraseGenerator.secure();
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            try (Generated g = gen.generate(PassphrasePolicy.defaults())) {
                String s = reveal(g);
                indices(s, '-', 6);
                assertTrue(seen.add(s), "a 78-bit passphrase repeated");
            }
        }
    }
}
