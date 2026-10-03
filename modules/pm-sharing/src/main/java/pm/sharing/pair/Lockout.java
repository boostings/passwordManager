package pm.sharing.pair;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * Pairing rate limit (lan-share.md §5 step 6, SR-203): after three failed ceremonies from any
 * source, new pairings are refused for 60 s; each further failure doubles the wait, up to 1 h. A
 * successful pairing clears the count. Kept in memory for the life of the process; one instance
 * serves every connection, so its state is guarded by a lock.
 */
public final class Lockout {
    /** Failures allowed before the first lock. */
    static final int FREE_FAILURES = 2;
    /** The first lock. */
    static final Duration FIRST = Duration.ofSeconds(60);
    /** The longest lock. */
    static final Duration CAP = Duration.ofHours(1);
    /** Doublings past which the wait is certainly above the cap (60 s × 2^6 > 1 h). */
    private static final int MAX_DOUBLINGS = 6;

    private final ReentrantLock guard = new ReentrantLock();
    private int failures;
    private Instant lockedUntil = Instant.MIN;

    /** A lockout with no failures. */
    public Lockout() {
        // no failures yet
    }

    /** Whether a new pairing may start at {@code now}. */
    public boolean allows(Instant now) {
        Objects.requireNonNull(now, "now");
        return locked(() -> !now.isBefore(lockedUntil));
    }

    /** How long until pairing is allowed again; zero if it is allowed now. */
    public Duration remaining(Instant now) {
        Objects.requireNonNull(now, "now");
        return locked(() -> now.isBefore(lockedUntil) ? Duration.between(now, lockedUntil) : Duration.ZERO);
    }

    /** Counts a failed ceremony that ended at {@code now}. */
    public void failed(Instant now) {
        Objects.requireNonNull(now, "now");
        locked(() -> {
            failures++;
            if (failures > FREE_FAILURES) {
                Duration wait = FIRST.multipliedBy(1L << Math.min(failures - FREE_FAILURES - 1, MAX_DOUBLINGS));
                lockedUntil = now.plus(wait.compareTo(CAP) > 0 ? CAP : wait);
            }
            return null;
        });
    }

    /** Clears the count after a successful pairing. */
    public void succeeded() {
        locked(() -> {
            failures = 0;
            return null;
        });
    }

    private <T> T locked(Supplier<T> body) {
        guard.lock();
        try {
            return body.get();
        } finally {
            guard.unlock();
        }
    }
}
