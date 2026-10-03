package pm.domain.health;

/** A reason {@link StrengthMeter} lowered its estimate. */
public enum Weakness {
    /** Fewer than {@value StrengthMeter#MIN_LENGTH} characters. */
    TOO_SHORT,
    /** Matches a bundled common password, ignoring case, simple character substitutions and a trailing run of digits or symbols. */
    COMMON,
    /** Contains a bundled common password of four or more characters, ignoring case and simple substitutions. */
    CONTAINS_COMMON,
    /**
     * Three or more identical characters in a row, or the whole password is a shorter unit repeated
     * ({@code abab}, {@code Monkey!Monkey!}), ignoring case.
     */
    REPEATED,
    /**
     * Three or more consecutive alphabet, digit or keyboard characters along a row or a column
     * ({@code abc}, {@code 321}, {@code qwe}, {@code 1qaz}, {@code !QAZ}).
     */
    SEQUENCE,
    /** Uses only one character class. */
    SINGLE_CLASS
}
