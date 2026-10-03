package pm.domain.generate;

import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * What a generated password looks like (MET00-J: validated on construction).
 *
 * @param length number of characters, {@value #MIN_LENGTH} to {@value #MAX_LENGTH}, and at least the
 *     number of classes
 * @param classes the character classes to draw from; the password holds at least one character of
 *     each
 * @param excludeAmbiguous whether to drop {@link CharClass#AMBIGUOUS} characters
 */
public record PasswordPolicy(int length, Set<CharClass> classes, boolean excludeAmbiguous) {
    /** Shortest accepted length. */
    public static final int MIN_LENGTH = 4;
    /** Longest accepted length. */
    public static final int MAX_LENGTH = 1024;
    /** Length of {@link #defaults()}. */
    public static final int DEFAULT_LENGTH = 20;

    /**
     * Validates the parameters and takes an unmodifiable copy of {@code classes}.
     *
     * @throws NullPointerException if {@code classes} or one of its elements is null
     * @throws IllegalArgumentException if {@code classes} is empty, or {@code length} is out of range
     *     or shorter than the number of classes
     */
    public PasswordPolicy {
        Objects.requireNonNull(classes, "classes");
        if (classes.isEmpty()) {
            throw new IllegalArgumentException("at least one character class is required");
        }
        classes = Set.copyOf(EnumSet.copyOf(classes));
        if (length < MIN_LENGTH || length > MAX_LENGTH) {
            throw new IllegalArgumentException("length must be between " + MIN_LENGTH + " and " + MAX_LENGTH);
        }
        if (length < classes.size()) {
            throw new IllegalArgumentException("length is shorter than the number of classes");
        }
    }

    /** {@value #DEFAULT_LENGTH} characters from all four classes, ambiguous characters allowed. */
    public static PasswordPolicy defaults() {
        return new PasswordPolicy(DEFAULT_LENGTH, EnumSet.allOf(CharClass.class), false);
    }
}
