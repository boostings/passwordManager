package pm.domain.generate;

/**
 * What a generated passphrase looks like (MET00-J: validated on construction).
 *
 * @param words number of words, {@value #MIN_WORDS} to {@value #MAX_WORDS}
 * @param separator the character between words: printable ASCII ({@code 0x20..0x7e}) that is not a
 *     lowercase letter, so the words stay separable
 */
public record PassphrasePolicy(int words, char separator) {
    /** Fewest accepted words. */
    public static final int MIN_WORDS = 3;
    /** Most accepted words. */
    public static final int MAX_WORDS = 64;
    /** Word count of {@link #defaults()}: 6 words of 13 bits each is 78 bits. */
    public static final int DEFAULT_WORDS = 6;
    /** Separator of {@link #defaults()}. */
    public static final char DEFAULT_SEPARATOR = '-';
    private static final char FIRST_PRINTABLE = ' ';
    private static final char LAST_PRINTABLE = '~';
    private static final char FIRST_LOWER = 'a';
    private static final char LAST_LOWER = 'z';

    /**
     * Validates the parameters.
     *
     * @throws IllegalArgumentException if {@code words} is out of range or {@code separator} is not an
     *     allowed character
     */
    public PassphrasePolicy {
        if (words < MIN_WORDS || words > MAX_WORDS) {
            throw new IllegalArgumentException("words must be between " + MIN_WORDS + " and " + MAX_WORDS);
        }
        if (separator < FIRST_PRINTABLE || separator > LAST_PRINTABLE
                || (separator >= FIRST_LOWER && separator <= LAST_LOWER)) {
            throw new IllegalArgumentException("separator must be printable ASCII and not a lowercase letter");
        }
    }

    /** {@value #DEFAULT_WORDS} words separated by {@code '-'}. */
    public static PassphrasePolicy defaults() {
        return new PassphrasePolicy(DEFAULT_WORDS, DEFAULT_SEPARATOR);
    }
}
