package pm.domain.health;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * The offline findings of {@link HealthCheck#run}. Holds ids and ratings, never a password.
 *
 * @param checked number of records with a password that were examined
 * @param weak records whose password rates weak
 * @param reused groups of records sharing a password
 * @param old records not changed within the maximum age
 */
public record HealthReport(int checked, List<Weak> weak, List<ReuseGroup> reused, List<Old> old) {
    /**
     * Checks the components and takes unmodifiable copies.
     *
     * @throws NullPointerException if a component is null
     * @throws IllegalArgumentException if {@code checked} is negative
     */
    public HealthReport {
        if (checked < 0) {
            throw new IllegalArgumentException("checked must not be negative");
        }
        weak = List.copyOf(weak);
        reused = List.copyOf(reused);
        old = List.copyOf(old);
    }

    /** Whether nothing was flagged. */
    public boolean isClean() {
        return weak.isEmpty() && reused.isEmpty() && old.isEmpty();
    }

    /**
     * A weak password.
     *
     * @param id the record
     * @param estimate the meter's result
     */
    public record Weak(UUID id, StrengthEstimate estimate) {
        /**
         * Checks the components.
         *
         * @throws NullPointerException if a component is null
         */
        public Weak {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(estimate, "estimate");
        }
    }

    /**
     * An old password.
     *
     * @param id the record
     * @param age time since the record last changed
     */
    public record Old(UUID id, Duration age) {
        /**
         * Checks the components.
         *
         * @throws NullPointerException if a component is null
         */
        public Old {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(age, "age");
        }
    }
}
