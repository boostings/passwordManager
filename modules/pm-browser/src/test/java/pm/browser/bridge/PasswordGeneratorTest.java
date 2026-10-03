package pm.browser.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.function.IntFunction;
import org.junit.jupiter.api.Test;
import pm.browser.host.Request;
import pm.crypto.SecretChars;

/** Uniform, class-complete password generation with a deterministic byte source. */
class PasswordGeneratorTest {

    /** Returns the queued byte values one at a time, then {@code fallback} forever. */
    static IntFunction<byte[]> bytes(int fallback, int... values) {
        Deque<Integer> queue = new ArrayDeque<>();
        for (int v : values) {
            queue.add(v);
        }
        return n -> {
            byte[] out = new byte[n];
            for (int i = 0; i < n; i++) {
                Integer next = queue.poll();
                out[i] = (byte) (next == null ? fallback : next);
            }
            return out;
        };
    }

    private static String text(SecretChars chars) {
        StringBuilder sb = new StringBuilder();
        chars.withChars(sb::append);
        return sb.toString();
    }

    @Test
    void indicesComeFromTheByteSource() {
        PasswordGenerator g = new PasswordGenerator(bytes(0, 1, 2, 25, 26, 51));
        try (SecretChars p = g.generate(new Request.Policy(8, true, false, false, false))) {
            assertEquals("bczaza" + "aa", text(p));
        }
    }

    @Test
    void bytesAboveTheLastFullMultipleAreRedrawn() {
        // 26 letters: 256 - 256 % 26 = 234, so 234..255 are rejected rather than biasing a..v.
        PasswordGenerator g = new PasswordGenerator(bytes(0, 255, 234, 233, 25));
        try (SecretChars p = g.generate(new Request.Policy(8, true, false, false, false))) {
            assertEquals("zz" + "a".repeat(6), text(p)); // 233 % 26 = 25 = 'z'
        }
    }

    @Test
    void aCandidateMissingAChosenClassIsDrawnAgain() {
        // lower+upper = 52 symbols; eight zeros give "aaaaaaaa" (no upper), then 26 = 'A'.
        PasswordGenerator g = new PasswordGenerator(bytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 26));
        try (SecretChars p = g.generate(new Request.Policy(8, true, true, false, false))) {
            assertEquals("Aaaaaaaa", text(p));
        }
    }

    @Test
    void aSourceThatNeverSatisfiesThePolicyIsReported() {
        PasswordGenerator g = new PasswordGenerator(bytes(0));
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> g.generate(new Request.Policy(8, true, false, true, false)));
        assertEquals("GENERATOR_EXHAUSTED", e.getMessage());
    }

    @Test
    void theSecureGeneratorHonoursEveryClass() {
        Request.Policy all = new Request.Policy(Request.Policy.MAX_LENGTH, true, true, true, true);
        try (SecretChars p = PasswordGenerator.secure().generate(all)) {
            String s = text(p);
            assertEquals(Request.Policy.MAX_LENGTH, s.length());
            String alphabet = PasswordGenerator.LOWER + PasswordGenerator.UPPER + PasswordGenerator.DIGITS
                    + PasswordGenerator.SYMBOLS;
            assertTrue(s.chars().allMatch(c -> alphabet.indexOf(c) >= 0));
            for (String cls : new String[] {PasswordGenerator.LOWER, PasswordGenerator.UPPER,
                PasswordGenerator.DIGITS, PasswordGenerator.SYMBOLS}) {
                assertTrue(s.chars().anyMatch(c -> cls.indexOf(c) >= 0), cls);
            }
        }
        try (SecretChars p = PasswordGenerator.secure().generate(new Request.Policy(8, false, false, true, false))) {
            assertTrue(text(p).chars().allMatch(Character::isDigit));
        }
        try (SecretChars p = PasswordGenerator.secure().generate(new Request.Policy(8, false, false, false, true))) {
            assertTrue(text(p).chars().allMatch(c -> PasswordGenerator.SYMBOLS.indexOf(c) >= 0));
        }
    }
}
