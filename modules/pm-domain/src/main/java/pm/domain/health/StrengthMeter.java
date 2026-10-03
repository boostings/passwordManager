package pm.domain.health;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;

/**
 * Offline password strength heuristic (ADR 0012 §5). No dependencies, no network.
 *
 * <p>The password is examined as Unicode code points, so an emoji or other supplementary
 * character counts once. The estimate starts from {@code log2(pool)} bits per code point, where the
 * pool is the sum of the classes present (26 lower, 26 upper, 10 digits, 33 ASCII symbols and space,
 * 100 for anything else). A code point that repeats the previous one, or continues an alphabet,
 * digit or keyboard run along a row or a column (shifted symbols count as their key) in either
 * direction, costs {@value #PREDICTABLE_BITS} bit instead. Then, ignoring ASCII case:
 * <ul>
 *   <li>every bundled common password of {@value #MIN_COMMON_SUBSTRING} or more characters found
 *       as a substring (also after undoing simple substitutions such as {@code @→a}, {@code 0→o})
 *       costs only log2 of the list size ({@link Weakness#CONTAINS_COMMON});
 *   <li>a password made of one shorter unit repeated costs the unit plus log2 of the repeat count
 *       ({@link Weakness#REPEATED});
 *   <li>a password that is a common password, possibly with a trailing run of digits and symbols,
 *       is capped at the cost of guessing from the list plus the dropped suffix and is always
 *       {@link Strength#VERY_WEAK} ({@link Weakness#COMMON}).
 * </ul>
 * A password that is a repeated unit, or that has a {@link Weakness#REPEATED} or
 * {@link Weakness#SEQUENCE} run with at least half of its code points predictable, is never
 * rated above {@link Strength#FAIR}. A short run that occurs by chance in a random password is
 * reported but only lowers the bits.
 *
 * <p>This is an upper bound on guessing cost for unstructured input, deliberately simple and
 * explainable; it is not zxcvbn. Dictionary words, names and dates outside the bundled list are not
 * recognised. Every working buffer is zero-filled before returning.
 */
public final class StrengthMeter {
    /** Below this many code points a password is at most {@link Strength#WEAK}. */
    public static final int MIN_LENGTH = 10;
    /** Bits credited to a code point that repeats or continues a run. */
    static final double PREDICTABLE_BITS = 1.0;
    static final double VERY_WEAK_BELOW = 30;
    static final double WEAK_BELOW = 50;
    static final double FAIR_BELOW = 70;
    /** Shortest common-list entry looked for inside a longer password. */
    static final int MIN_COMMON_SUBSTRING = 4;
    /** A password is patterned when at least 1/{@value} of its code points repeat or continue a run. */
    static final int PATTERN_SHARE = 2;
    private static final int POOL_LOWER = 26;
    private static final int POOL_UPPER = 26;
    private static final int POOL_DIGIT = 10;
    private static final int POOL_SYMBOL = 33;
    private static final int POOL_OTHER = 100;
    private static final int RUN = 3;
    private static final int ADJACENT = 1;
    private static final int SINGLE = 1;
    private static final int TWICE = 2;
    private static final int CLASS_COUNT = 5;
    private static final int FIRST_ASCII = ' ';
    private static final int LAST_ASCII = '~';
    private static final int ASCII_CASE = 'a' - 'A';
    private static final double DIGIT_BITS = log2(10);
    /** Keyboard rows and columns (US QWERTY, unshifted); a step along any line is predictable. */
    private static final String[] KEY_LINES = {
        "`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./",
        "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik,", "9ol.", "0p;/", "-['", "=]",
    };
    private static final String SHIFTED = "~!@#$%^&*()_+{}|:\"<>?";
    private static final String UNSHIFTED = "`1234567890-=[]\\;',./";
    private static final String LEET_FROM = "@4310$5!7+";
    private static final String LEET_TO = "aaeiossitt";
    private static final Pattern COMMON_SHAPE = Pattern.compile("[a-z0-9]+");
    private static final String[] COMMON = loadCommon();
    private static final double COMMON_BITS = log2(COMMON.length);
    private static final int LONGEST_COMMON = longestCommon();

    private StrengthMeter() {
    }

    /** Estimates a password held as UTF-8 (the vault's representation); malformed bytes count as other characters. */
    public static StrengthEstimate estimate(SecretBytes utf8) {
        Objects.requireNonNull(utf8, "utf8");
        char[] chars = utf8.apply(StrengthMeter::decode);
        try {
            return estimate(chars);
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /** Estimates a password held as characters. */
    public static StrengthEstimate estimate(SecretChars password) {
        Objects.requireNonNull(password, "password");
        StrengthEstimate[] out = new StrengthEstimate[1];
        password.withChars(chars -> out[0] = estimate(chars));
        return out[0];
    }

    static StrengthEstimate estimate(char[] pw) {
        int[] cps = codePoints(pw);
        int[] folded = new int[cps.length];
        try {
            for (int i = 0; i < cps.length; i++) {
                folded[i] = foldCase(cps[i]);
            }
            return estimate(cps, folded, commonSuffixLength(pw));
        } finally {
            Arrays.fill(cps, 0);
            Arrays.fill(folded, 0);
        }
    }

    private static StrengthEstimate estimate(int[] cps, int[] folded, int commonSuffix) {
        Set<Weakness> weaknesses = EnumSet.noneOf(Weakness.class);
        int n = cps.length;
        if (n == 0) {
            weaknesses.add(Weakness.TOO_SHORT);
            return new StrengthEstimate(0, Strength.VERY_WEAK, weaknesses);
        }
        int[] predictable = new int[1];
        double[] cost = runCosts(cps, weaknesses, predictable);
        boolean patterned = predictable[0] * PATTERN_SHARE >= n
                && (weaknesses.contains(Weakness.REPEATED) || weaknesses.contains(Weakness.SEQUENCE));
        if (classCount(cps) == SINGLE) {
            weaknesses.add(Weakness.SINGLE_CLASS);
        }
        boolean plain = discountCommon(folded, cost);
        boolean substituted = discountUnleet(folded, cost);
        if (plain || substituted) {
            weaknesses.add(Weakness.CONTAINS_COMMON);
        }
        double bits = sum(cost, n);
        int period = period(folded);
        if (period > 0) {
            patterned = true;
            weaknesses.add(Weakness.REPEATED);
            bits = Math.min(bits, sum(cost, period) + log2((n + period - 1) / period));
        }
        if (commonSuffix >= 0) {
            weaknesses.remove(Weakness.CONTAINS_COMMON);
            weaknesses.add(Weakness.COMMON);
            bits = Math.min(bits, COMMON_BITS + commonSuffix * DIGIT_BITS);
        }
        if (n < MIN_LENGTH) {
            weaknesses.add(Weakness.TOO_SHORT);
        }
        return new StrengthEstimate(bits, rate(bits, weaknesses, patterned), weaknesses);
    }

    /** Per-position bits: the full pool cost, or {@value #PREDICTABLE_BITS} for a repeat or run step. */
    private static double[] runCosts(int[] cps, Set<Weakness> weaknesses, int[] predictable) {
        double perChar = log2(pool(cps));
        double[] cost = new double[cps.length];
        cost[0] = perChar;
        int repeatRun = 1;
        int sequenceRun = 1;
        for (int i = 1; i < cps.length; i++) {
            boolean repeat = cps[i] == cps[i - 1];
            boolean sequence = !repeat && continuesRun(cps[i - 1], cps[i]);
            repeatRun = repeat ? repeatRun + 1 : 1;
            sequenceRun = sequence ? sequenceRun + 1 : 1;
            if (repeatRun >= RUN) {
                weaknesses.add(Weakness.REPEATED);
            }
            if (sequenceRun >= RUN) {
                weaknesses.add(Weakness.SEQUENCE);
            }
            cost[i] = repeat || sequence ? PREDICTABLE_BITS : perChar;
            predictable[0] += repeat || sequence ? 1 : 0;
        }
        return cost;
    }

    private static Strength rate(double bits, Set<Weakness> weaknesses, boolean patterned) {
        Strength byBits;
        if (bits < VERY_WEAK_BELOW || weaknesses.contains(Weakness.COMMON)) {
            byBits = Strength.VERY_WEAK;
        } else if (bits < WEAK_BELOW || weaknesses.contains(Weakness.TOO_SHORT)) {
            byBits = Strength.WEAK;
        } else if (bits < FAIR_BELOW || patterned) {
            byBits = Strength.FAIR;
        } else {
            byBits = Strength.STRONG;
        }
        return byBits;
    }

    /** {@link #discountCommon} on a copy with simple substitutions undone. */
    private static boolean discountUnleet(int[] folded, double[] cost) {
        int[] plain = folded.clone();
        try {
            for (int i = 0; i < plain.length; i++) {
                int k = plain[i] < Character.MIN_SUPPLEMENTARY_CODE_POINT ? LEET_FROM.indexOf(plain[i]) : -1;
                if (k >= 0) {
                    plain[i] = LEET_TO.charAt(k);
                }
            }
            return discountCommon(plain, cost);
        } finally {
            Arrays.fill(plain, 0);
        }
    }

    /**
     * Scans left to right for the longest common-list entry (at least {@value #MIN_COMMON_SUBSTRING}
     * long) starting at each position; each one found costs at most {@code log2(list size)} in total.
     */
    private static boolean discountCommon(int[] folded, double[] cost) {
        boolean found = false;
        int i = 0;
        while (i < folded.length) {
            int len = Math.min(LONGEST_COMMON, folded.length - i);
            while (len >= MIN_COMMON_SUBSTRING && !isCommon(folded, i, len)) {
                len--;
            }
            if (len >= MIN_COMMON_SUBSTRING) {
                found = true;
                double span = 0;
                for (int k = i; k < i + len; k++) {
                    span += cost[k];
                    cost[k] = 0;
                }
                cost[i] = Math.min(span, COMMON_BITS);
                i += len;
            } else {
                i++;
            }
        }
        return found;
    }

    /** Smallest period p with {@code 2p <= n} such that {@code a[i] == a[i - p]} for all i; 0 if none. */
    static int period(int[] a) {
        int n = a.length;
        if (n < TWICE) {
            return 0;
        }
        int[] border = new int[n];
        int k = 0;
        for (int i = 1; i < n; i++) {
            while (k > 0 && a[i] != a[k]) {
                k = border[k - 1];
            }
            if (a[i] == a[k]) {
                k++;
            }
            border[i] = k;
        }
        int p = n - border[n - 1];
        return TWICE * p <= n ? p : 0;
    }

    private static int[] codePoints(char[] pw) {
        int[] out = new int[Character.codePointCount(pw, 0, pw.length)];
        int i = 0;
        for (int k = 0; k < out.length; k++) {
            out[k] = Character.codePointAt(pw, i);
            i += Character.charCount(out[k]);
        }
        return out;
    }

    private static int foldCase(int cp) {
        return cp >= 'A' && cp <= 'Z' ? cp + ASCII_CASE : cp;
    }

    private static double sum(double[] cost, int upTo) {
        double total = 0;
        for (int i = 0; i < upTo; i++) {
            total += cost[i];
        }
        return total;
    }

    private static int pool(int[] cps) {
        boolean[] present = classesPresent(cps);
        int[] sizes = {POOL_LOWER, POOL_UPPER, POOL_DIGIT, POOL_SYMBOL, POOL_OTHER};
        int pool = 0;
        for (int c = 0; c < CLASS_COUNT; c++) {
            pool += present[c] ? sizes[c] : 0;
        }
        return pool;
    }

    private static int classCount(int[] cps) {
        int count = 0;
        for (boolean p : classesPresent(cps)) {
            count += p ? 1 : 0;
        }
        return count;
    }

    private static boolean[] classesPresent(int[] cps) {
        boolean[] present = new boolean[CLASS_COUNT];
        for (int c : cps) {
            present[classOf(c)] = true;
        }
        return present;
    }

    /** 0 lower, 1 upper, 2 digit, 3 ASCII symbol or space, 4 anything else. */
    private static int classOf(int c) {
        int cls;
        if (c >= 'a' && c <= 'z') {
            cls = 0;
        } else if (c >= 'A' && c <= 'Z') {
            cls = 1;
        } else if (c >= '0' && c <= '9') {
            cls = 2;
        } else if (c >= FIRST_ASCII && c <= LAST_ASCII) {
            cls = 3;
        } else {
            cls = CLASS_COUNT - 1;
        }
        return cls;
    }

    /**
     * Whether {@code b} follows {@code a} in the alphabet or the digits, or is next to it along a
     * keyboard row or column (shifted symbols count as their key), in either direction.
     */
    static boolean continuesRun(int a, int b) {
        int x = foldCase(a);
        int y = foldCase(b);
        boolean letters = x >= 'a' && x <= 'z' && y >= 'a' && y <= 'z';
        boolean digits = x >= '0' && x <= '9' && y >= '0' && y <= '9';
        if ((letters || digits) && Math.abs(x - y) == ADJACENT) {
            return true;
        }
        int kx = key(x);
        int ky = key(y);
        for (String line : KEY_LINES) {
            int i = line.indexOf(kx);
            int j = line.indexOf(ky);
            if (i >= 0 && j >= 0 && Math.abs(i - j) == ADJACENT) {
                return true;
            }
        }
        return false;
    }

    /** The unshifted key that produces {@code c}, or {@code c} itself. */
    private static int key(int c) {
        int k = c < Character.MIN_SUPPLEMENTARY_CODE_POINT ? SHIFTED.indexOf(c) : -1;
        return k >= 0 ? UNSHIFTED.charAt(k) : c;
    }

    /**
     * If {@code pw} is a common password, the length of the trailing digit/symbol run that was dropped
     * to match it (0 for an exact match); otherwise -1.
     */
    static int commonSuffixLength(char[] pw) {
        int[] lower = new int[pw.length];
        try {
            for (int i = 0; i < pw.length; i++) {
                lower[i] = Character.toLowerCase(pw[i]);
            }
            if (isCommon(lower, 0, lower.length)) {
                return 0;
            }
            int stem = lower.length;
            while (stem > 0 && !Character.isLetter(lower[stem - 1])) {
                stem--;
            }
            for (int i = 0; i < lower.length; i++) {
                int k = LEET_FROM.indexOf(lower[i]);
                if (k >= 0) {
                    lower[i] = LEET_TO.charAt(k);
                }
            }
            if (isCommon(lower, 0, lower.length)) {
                return 0;
            }
            return stem > 0 && isCommon(lower, 0, stem) ? pw.length - stem : -1;
        } finally {
            Arrays.fill(lower, 0);
        }
    }

    /** Binary search of {@code pw[from, from + len)} in the sorted list without building a String. */
    private static boolean isCommon(int[] pw, int from, int len) {
        int lo = 0;
        int hi = COMMON.length - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            int cmp = compare(COMMON[mid], pw, from, len);
            if (cmp == 0) {
                return true;
            }
            if (cmp < 0) {
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        return false;
    }

    private static int compare(String word, int[] pw, int from, int len) {
        int n = Math.min(word.length(), len);
        for (int i = 0; i < n; i++) {
            int d = Integer.compare(word.charAt(i), pw[from + i]);
            if (d != 0) {
                return d;
            }
        }
        return Integer.compare(word.length(), len);
    }

    private static char[] decode(byte[] bytes) {
        CharBuffer decoded;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPLACE)
                    .onUnmappableCharacter(CodingErrorAction.REPLACE)
                    .decode(ByteBuffer.wrap(bytes));
        } catch (CharacterCodingException e) {
            // REPLACE never reports; kept total so a JDK change cannot leak the bytes in a message.
            throw new IllegalStateException("UTF-8 decoding failed", e);
        }
        char[] out = new char[decoded.remaining()];
        decoded.get(out);
        Arrays.fill(decoded.array(), '\0');
        return out;
    }

    /** Number of entries in the bundled common-password list. */
    static int commonListSize() {
        return COMMON.length;
    }

    private static String[] loadCommon() {
        try (InputStream in = Objects.requireNonNull(
                        StrengthMeter.class.getResourceAsStream("common-passwords.txt"), "common-passwords");
                BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            List<String> words = new ArrayList<>();
            String previous = "";
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                String w = line;
                if (!COMMON_SHAPE.matcher(w).matches() || w.compareTo(previous) <= 0) {
                    throw new IllegalStateException("common-password list is malformed, unsorted or repeated");
                }
                words.add(w);
                previous = w;
            }
            return words.toArray(new String[0]);
        } catch (IOException e) {
            throw new UncheckedIOException("common-password list unreadable", e);
        }
    }

    private static int longestCommon() {
        int longest = 0;
        for (String w : COMMON) {
            longest = Math.max(longest, w.length());
        }
        return longest;
    }

    /** Base-2 logarithm of a pool or list size. */
    private static double log2(int n) {
        return Math.log(n) / Math.log(2);
    }
}
