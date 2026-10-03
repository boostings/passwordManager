package pm.domain.health;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import pm.vault.record.VaultRecord;

/**
 * Flags records whose secret has not changed for longer than a maximum age (ADR 0012 §7).
 *
 * <p>Records carry no separate "password changed" time, so the age is measured from
 * {@link VaultRecord#updated()}: any edit resets it. That under-reports age when only a title or
 * note changed, which is the safe direction for a reminder, not for an audit. A record dated in the
 * future (clock skew between devices) counts as age zero.
 */
public final class AgeCheck {
    /** Default maximum age: one year. */
    public static final Duration DEFAULT_MAX_AGE = Duration.ofDays(365);

    private final Clock clock;
    private final Duration maxAge;

    /**
     * Returns a check against {@code clock}.
     *
     * @throws IllegalArgumentException if {@code maxAge} is zero or negative
     */
    public AgeCheck(Clock clock, Duration maxAge) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.maxAge = Objects.requireNonNull(maxAge, "maxAge");
        if (maxAge.isZero() || maxAge.isNegative()) {
            throw new IllegalArgumentException("maxAge must be positive");
        }
    }

    /** How long ago {@code since} was, never negative. */
    public Duration age(Instant since) {
        Objects.requireNonNull(since, "since");
        Duration age = Duration.between(since, clock.instant());
        return age.isNegative() ? Duration.ZERO : age;
    }

    /** The age of {@code record}'s last change. */
    public Duration age(VaultRecord record) {
        return age(Objects.requireNonNull(record, "record").updated());
    }

    /** Whether {@code record} was last changed more than the maximum age ago. */
    public boolean isOld(VaultRecord record) {
        return age(record).compareTo(maxAge) > 0;
    }
}
