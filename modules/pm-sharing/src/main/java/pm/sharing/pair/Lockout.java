package pm.sharing.pair;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * Pairing rate limit (lan-share.md §5 step 6, SR-203): after three failed ceremonies from any
 * source, new pairings are refused for 60 s; each further failure doubles the wait, up to 1 h. A
 * successful pairing clears the count. One instance serves every connection, so its state is
 * guarded by a lock. The state can be read out and {@linkplain #restore restored}, so a caller can
 * keep it across processes.
 */
public final class Lockout {
    /** Failures allowed before the first lock. */
    public static final int FREE_FAILURES = 2;
    /** The first lock. */
    public static final Duration FIRST = Duration.ofSeconds(60);
    /** The longest lock. */
    public static final Duration CAP = Duration.ofHours(1);
    /** Most failures a restored state keeps; past this the wait is at the cap anyway. */
    static final int MAX_FAILURES = 1_000;
    /** Doublings past which the wait is certainly above the cap (60 s × 2^6 > 1 h). */
    private static final int MAX_DOUBLINGS = 6;

    private final ReentrantLock guard = new ReentrantLock();
    private int failCount;
    private Instant lockEnd = Instant.MIN;

    /** A lockout with no failures. */
    public Lockout() {
        // no failures yet
    }

    /**
     * A lockout in a saved state. Clock-safe: a lock that would end more than {@link #CAP} after
     * {@code now} (a clock set back, or a tampered state) ends at {@code now} plus the cap; the
     * failure count is kept between 0 and an internal bound.
     */
    public static Lockout restore(int failures, Instant lockedUntil, Instant now) {
        Objects.requireNonNull(lockedUntil, "lockedUntil");
        Objects.requireNonNull(now, "now");
        Lockout l = new Lockout();
        l.failCount = Math.clamp(failures, 0, MAX_FAILURES);
        Instant latest = now.plus(CAP);
        l.lockEnd = lockedUntil.isAfter(latest) ? latest : lockedUntil;
        return l;
    }

    /** Failures counted since the last success. */
    public int failures() {
        return locked(() -> failCount);
    }

    /** When the current lock ends; in the past when there is none. */
    public Instant lockedUntil() {
        return locked(() -> lockEnd);
    }

    /** Whether a new pairing may start at {@code now}. */
    public boolean allows(Instant now) {
        Objects.requireNonNull(now, "now");
        return locked(() -> !now.isBefore(lockEnd));
    }

    /** How long until pairing is allowed again; zero if it is allowed now. */
    public Duration remaining(Instant now) {
        Objects.requireNonNull(now, "now");
        return locked(() -> now.isBefore(lockEnd) ? Duration.between(now, lockEnd) : Duration.ZERO);
    }

    /** Counts a failed ceremony that ended at {@code now}. */
    public void failed(Instant now) {
        Objects.requireNonNull(now, "now");
        locked(() -> {
            failCount++;
            if (failCount > FREE_FAILURES) {
                Duration wait = FIRST.multipliedBy(1L << Math.min(failCount - FREE_FAILURES - 1, MAX_DOUBLINGS));
                lockEnd = now.plus(wait.compareTo(CAP) > 0 ? CAP : wait);
            }
            return null;
        });
    }

    /** Clears the count after a successful pairing. */
    public void succeeded() {
        locked(() -> {
            failCount = 0;
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
