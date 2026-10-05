package pm.browser.webauthn;

/**
 * The RFC 3492 Punycode encoder, used only to turn the Unicode rules of the vendored Public
 * Suffix List into the {@code xn--} A-labels that canonical origins carry. No IDNA mapping is
 * done (see {@link pm.browser.bridge.Origin}): the list's labels are already lower-case NFC, so
 * encoding them is all UTS #46 would do to them.
 */
final class Punycode {
    private static final int BASE = 36;
    private static final int T_MIN = 1;
    private static final int T_MAX = 26;
    private static final int SKEW = 38;
    private static final int DAMP = 700;
    private static final int INITIAL_BIAS = 72;
    private static final int INITIAL_N = 0x80;
    private static final int DIGIT_LETTERS = 26;
    private static final int ADAPT_LIMIT = ((BASE - T_MIN) * T_MAX) / 2;
    private static final char DELIMITER = '-';

    private Punycode() {
    }

    /**
     * The Punycode form of one label (without the {@code xn--} prefix). Labels of the list are
     * short, so the RFC's overflow checks cannot trigger; arithmetic is exact (ints, no wrap).
     */
    static String encode(String label) {
        int[] input = label.codePoints().toArray();
        StringBuilder out = new StringBuilder();
        for (int c : input) {
            if (c < INITIAL_N) {
                out.append((char) c);
            }
        }
        int basic = out.length();
        int handled = basic;
        if (basic > 0) {
            out.append(DELIMITER);
        }
        int n = INITIAL_N;
        int delta = 0;
        int bias = INITIAL_BIAS;
        while (handled < input.length) {
            int next = Integer.MAX_VALUE;
            for (int c : input) {
                if (c >= n && c < next) {
                    next = c;
                }
            }
            delta = Math.addExact(delta, Math.multiplyExact(next - n, handled + 1));
            n = next;
            for (int c : input) {
                if (c < n) {
                    delta++;
                }
                if (c == n) {
                    appendNumber(out, delta, bias);
                    bias = adapt(delta, handled + 1, handled == basic);
                    delta = 0;
                    handled++;
                }
            }
            delta++;
            n++;
        }
        return out.toString();
    }

    /** One generalized variable-length integer (RFC 3492 section 3.3). */
    private static void appendNumber(StringBuilder out, int value, int bias) {
        int q = value;
        for (int k = BASE;; k += BASE) {
            int t = threshold(k, bias);
            if (q < t) {
                out.append(digit(q));
                return;
            }
            out.append(digit(t + (q - t) % (BASE - t)));
            q = (q - t) / (BASE - t);
        }
    }

    private static int threshold(int k, int bias) {
        if (k <= bias) {
            return T_MIN;
        }
        return Math.min(k - bias, T_MAX);
    }

    /** Bias adaptation (RFC 3492 section 6.1). */
    private static int adapt(int delta, int points, boolean first) {
        int d = first ? delta / DAMP : delta / 2;
        d += d / points;
        int k = 0;
        while (d > ADAPT_LIMIT) {
            d /= BASE - T_MIN;
            k += BASE;
        }
        return k + (BASE - T_MIN + 1) * d / (d + SKEW);
    }

    private static char digit(int d) {
        return (char) (d < DIGIT_LETTERS ? 'a' + d : '0' + d - DIGIT_LETTERS);
    }
}
