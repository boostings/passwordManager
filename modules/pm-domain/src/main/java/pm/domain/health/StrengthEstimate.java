package pm.domain.health;

import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * The result of {@link StrengthMeter#estimate}. Holds no part of the password.
 *
 * @param bits estimated guessing entropy in bits (a heuristic, see ADR 0012)
 * @param strength the rating derived from {@code bits} and {@code weaknesses}
 * @param weaknesses why the estimate was lowered, possibly empty
 */
public record StrengthEstimate(double bits, Strength strength, Set<Weakness> weaknesses) {
    /**
     * Checks the components and takes an unmodifiable copy of {@code weaknesses}.
     *
     * @throws NullPointerException if a component is null
     * @throws IllegalArgumentException if {@code bits} is negative or not finite
     */
    public StrengthEstimate {
        Objects.requireNonNull(strength, "strength");
        Objects.requireNonNull(weaknesses, "weaknesses");
        if (!Double.isFinite(bits) || bits < 0) {
            throw new IllegalArgumentException("bits must be finite and non-negative");
        }
        weaknesses = weaknesses.isEmpty() ? Set.of() : Set.copyOf(EnumSet.copyOf(weaknesses));
    }

    /** Whether the health report flags this password as weak. */
    public boolean isWeak() {
        return strength.isWeak();
    }
}
