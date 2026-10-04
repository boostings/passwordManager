package pm.fuzz;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** A clock the harness moves forward; safe to read from a listener thread. */
public final class FuzzClock extends Clock {
    /** Where every harness run starts. */
    public static final Instant T0 = Instant.parse("2026-10-03T12:00:00Z");

    private volatile Instant now = T0;

    /** A clock at {@link #T0}. */
    public FuzzClock() {
        // starts at T0
    }

    /** Moves the clock forward by {@code d}. */
    public void advance(Duration d) {
        now = now.plus(d);
    }

    @Override
    public Instant instant() {
        return now;
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }
}
