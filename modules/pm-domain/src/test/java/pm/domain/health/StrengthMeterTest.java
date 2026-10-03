package pm.domain.health;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.domain.generate.Generated;
import pm.domain.generate.PassphraseGenerator;
import pm.domain.generate.PassphrasePolicy;
import pm.domain.generate.PasswordGenerator;
import pm.domain.generate.PasswordPolicy;
import pm.domain.generate.RandomSource;

class StrengthMeterTest {

    private static StrengthEstimate of(String pw) {
        return StrengthMeter.estimate(pw.toCharArray());
    }

    @Test
    void commonPasswordsAreVeryWeakEvenWithSubstitutionsAndSuffixes() {
        for (String pw : new String[] {"password", "Password1", "P@ssw0rd!", "PASSWORD2024", "123456",
                "qwerty123", "iloveyou!!", "letmein", "dragon99", "abc123"}) {
            StrengthEstimate e = of(pw);
            assertTrue(e.weaknesses().contains(Weakness.COMMON), pw);
            assertEquals(Strength.VERY_WEAK, e.strength(), pw);
            assertTrue(e.isWeak());
        }
        assertTrue(StrengthMeter.commonListSize() > 150);
        assertEquals(-1, StrengthMeter.commonSuffixLength("xq7#Lm2pVv".toCharArray()));
        assertEquals(0, StrengthMeter.commonSuffixLength("Password".toCharArray()));
        assertEquals(0, StrengthMeter.commonSuffixLength("p@55w0rd".toCharArray()));
        assertEquals(3, StrengthMeter.commonSuffixLength("password!!1".toCharArray()));
    }

    @Test
    void repeatsSequencesAndKeyboardRunsAreFlagged() {
        StrengthEstimate repeated = of("aaaaaaaaaaaaaaaaaaaa");
        assertTrue(repeated.weaknesses().containsAll(Set.of(Weakness.REPEATED, Weakness.SINGLE_CLASS)), repeated::toString);
        assertEquals(Strength.VERY_WEAK, repeated.strength());
        assertTrue(of("abcdefghijklmnopqrst").weaknesses().contains(Weakness.SEQUENCE));
        assertTrue(of("Zyxwvutsrq98765").weaknesses().contains(Weakness.SEQUENCE));
        assertTrue(of("Qwertyuiop!").weaknesses().contains(Weakness.SEQUENCE));
        assertTrue(of("zxcvbnm,./").weaknesses().contains(Weakness.SEQUENCE));
        assertTrue(of("abcdefghijklmnopqrst").isWeak());
        assertTrue(StrengthMeter.continuesRun('a', 'b'));
        assertTrue(StrengthMeter.continuesRun('B', 'a'));
        assertTrue(StrengthMeter.continuesRun('5', '6'));
        assertTrue(StrengthMeter.continuesRun('q', 'w'));
        assertTrue(StrengthMeter.continuesRun('9', '0')); // adjacent on the number row
        assertTrue(StrengthMeter.continuesRun('1', 'q')); // keyboard column
        assertTrue(StrengthMeter.continuesRun('!', 'Q')); // shifted symbol counts as its key
        assertTrue(StrengthMeter.continuesRun('Z', 'a'));
        assertTrue(StrengthMeter.continuesRun(',', '.'));
        assertFalse(StrengthMeter.continuesRun('9', ':'));
        assertFalse(StrengthMeter.continuesRun('z', '{'));
        assertFalse(StrengthMeter.continuesRun('a', 'c'));
        assertFalse(StrengthMeter.continuesRun('p', 'a'));
    }

    @Test
    void shortPasswordsAreAtMostWeak() {
        StrengthEstimate e = of("Xk9#mQ2");
        assertTrue(e.weaknesses().contains(Weakness.TOO_SHORT));
        assertTrue(e.isWeak());
        StrengthEstimate empty = of("");
        assertEquals(Strength.VERY_WEAK, empty.strength());
        assertEquals(0.0, empty.bits());
        assertEquals(Set.of(Weakness.TOO_SHORT), empty.weaknesses());
    }

    @Test
    void ratingThresholds() {
        // 12 random-looking lowercase letters: 12 * 4.7 = 56 bits -> FAIR, single class.
        StrengthEstimate fair = of("kqzmtvrexnwd");
        assertEquals(Strength.FAIR, fair.strength(), () -> "bits " + fair.bits());
        assertTrue(fair.weaknesses().contains(Weakness.SINGLE_CLASS));
        assertFalse(fair.isWeak());
        // 10 characters over all four classes: 10 * 6.6 = 66 bits -> FAIR.
        assertEquals(Strength.FAIR, of("k#9Tq!vM2z").strength());
        // 16 characters over all four classes -> STRONG.
        assertEquals(Strength.STRONG, of("k#9Tq!vM2z&Rb7@x").strength());
        assertEquals(Strength.WEAK, of("kqzmtvrex").strength()); // 42 bits and short
    }

    /** SplitMix64: a fixed-seed, deterministic stand-in for the CSPRNG. */
    private static RandomSource seeded(long seed) {
        long[] state = {seed};
        return out -> {
            for (int i = 0; i < out.length; i++) {
                state[0] += 0x9E3779B97F4A7C15L;
                long z = state[0];
                z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
                z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
                out[i] = (byte) (z ^ (z >>> 31));
            }
        };
    }

    @Test
    void generatedSecretsRateStrong() {
        PasswordGenerator passwords = new PasswordGenerator(seeded(7));
        PassphraseGenerator phrases = new PassphraseGenerator(seeded(11));
        int strong = 0;
        for (int i = 0; i < 200; i++) {
            try (Generated pw = passwords.generate(PasswordPolicy.defaults());
                    Generated phrase = phrases.generate(PassphrasePolicy.defaults())) {
                strong += rating(pw.secret()) + rating(phrase.secret());
            }
        }
        assertEquals(400, strong);
    }

    private static int rating(SecretChars secret) {
        StrengthEstimate e = StrengthMeter.estimate(secret);
        assertEquals(Strength.STRONG, e.strength(), e::toString);
        return 1;
    }

    @Test
    void codePointsNotUtf16Units() {
        StrengthEstimate emoji = of("\uD83D\uDE00".repeat(6));
        assertTrue(emoji.weaknesses().containsAll(Set.of(Weakness.REPEATED, Weakness.TOO_SHORT)), emoji::toString);
        assertEquals(Strength.VERY_WEAK, emoji.strength());
        StrengthEstimate mixed = of("\uD83D\uDE00\uD83D\uDE01\uD83C\uDF89\uD83D\uDD11");
        assertTrue(mixed.weaknesses().contains(Weakness.TOO_SHORT), "4 code points, not 8 chars");
        assertTrue(mixed.isWeak());
        StrengthEstimate lone = of("\uD83Dabc\uDE00");
        assertTrue(lone.isWeak(), "unpaired surrogates are tolerated");
    }

    /** Patterns that defeated the first version; none may rate STRONG and each names its reason. */
    @Test
    void structuredPasswordsAreNeverStrong() {
        Object[][] table = {
            {"Password1!Password1!", Weakness.REPEATED},
            {"Monkey!Monkey!Monkey!", Weakness.REPEATED},
            {"PASSWORDpassword", Weakness.REPEATED},
            {"acacacacacacacacac", Weakness.REPEATED},
            {"1qaz2wsx3edc4rfv", Weakness.SEQUENCE},
            {"zaq1xsw2cde3vfr4", Weakness.SEQUENCE},
            {"!QAZ@WSX#EDC$RFV", Weakness.SEQUENCE},
        };
        for (Object[] row : table) {
            String sample = (String) row[0];
            StrengthEstimate e = of(sample);
            assertTrue(e.weaknesses().contains((Weakness) row[1]), () -> sample + " " + e);
            assertTrue(e.strength() != Strength.STRONG, () -> sample + " " + e);
        }
        assertTrue(of("Password1!Password1!").isWeak());
        assertTrue(of("PASSWORDpassword").isWeak());
        assertTrue(of("1qaz2wsx3edc4rfv").isWeak());
        assertTrue(of("!QAZ@WSX#EDC$RFV").isWeak());
        assertTrue(of("acacacacacacacacac").isWeak());
    }

    @Test
    void commonWordsInsideLongerPasswordsCostOnlyTheirListIndex() {
        for (String pw : new String[] {"xK9#trustno1-Qv7&mZ", "Jq8%P@ssw0rd-Lm3!zR", "abc-MONKEY-xyz"}) {
            StrengthEstimate e = of(pw);
            assertTrue(e.weaknesses().contains(Weakness.CONTAINS_COMMON), () -> pw + " " + e);
            assertFalse(e.weaknesses().contains(Weakness.COMMON), pw);
        }
        // Same length and classes, no list word: the common one must be cheaper.
        assertTrue(of("Jq8%P@ssw0rd-Lm3!zR").bits() < of("Jq8%K#vb9Tx-Lm3!zR").bits() - 20);
        assertFalse(of("Jq8%K#vb9Tx-Lm3!zR").weaknesses().contains(Weakness.CONTAINS_COMMON));
    }

    @Test
    void periodDetection() {
        assertEquals(2, StrengthMeter.period(new int[] {'a', 'c', 'a', 'c', 'a'}));
        assertEquals(1, StrengthMeter.period(new int[] {'x', 'x'}));
        assertEquals(0, StrengthMeter.period(new int[] {'a', 'b', 'c', 'a', 'b'}));
        assertEquals(0, StrengthMeter.period(new int[] {'a'}));
        assertEquals(0, StrengthMeter.period(new int[0]));
    }

    @Test
    void utf8InputIsDecodedAndMalformedBytesDoNotThrow() {
        try (SecretBytes common = SecretBytes.copyOf("Password1".getBytes(StandardCharsets.UTF_8));
                SecretBytes unicode = SecretBytes.copyOf("pässwörd-Ünïcødé-ünd-mehr".getBytes(StandardCharsets.UTF_8));
                SecretBytes malformed = SecretBytes.copyOf(new byte[] {(byte) 0xff, (byte) 0xc3, 'a', 'b', 'c'})) {
            assertTrue(StrengthMeter.estimate(common).weaknesses().contains(Weakness.COMMON));
            assertFalse(StrengthMeter.estimate(unicode).isWeak());
            assertTrue(StrengthMeter.estimate(malformed).isWeak());
            assertFalse(common.isClosed(), "the meter must not close the caller's secret");
        }
        try (SecretChars chars = SecretChars.takeOwnership("letmein".toCharArray())) {
            assertTrue(StrengthMeter.estimate(chars).weaknesses().contains(Weakness.COMMON));
        }
        assertThrows(NullPointerException.class, () -> StrengthMeter.estimate((SecretBytes) null));
        assertThrows(NullPointerException.class, () -> StrengthMeter.estimate((SecretChars) null));
    }

    @Test
    void estimateValidation() {
        assertThrows(IllegalArgumentException.class, () -> new StrengthEstimate(-1, Strength.WEAK, Set.of()));
        assertThrows(IllegalArgumentException.class, () -> new StrengthEstimate(Double.NaN, Strength.WEAK, Set.of()));
        assertThrows(NullPointerException.class, () -> new StrengthEstimate(1, null, Set.of()));
        assertThrows(NullPointerException.class, () -> new StrengthEstimate(1, Strength.WEAK, null));
        Set<Weakness> mutable = EnumSet.of(Weakness.COMMON);
        StrengthEstimate e = new StrengthEstimate(1, Strength.VERY_WEAK, mutable);
        mutable.add(Weakness.REPEATED);
        assertEquals(Set.of(Weakness.COMMON), e.weaknesses());
        assertFalse(Strength.FAIR.isWeak());
        assertFalse(Strength.STRONG.isWeak());
    }
}
