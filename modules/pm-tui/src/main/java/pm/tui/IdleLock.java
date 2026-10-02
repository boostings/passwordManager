package pm.tui;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Idle auto-lock timer (SR-504): runs {@code onLock} once {@code timeout} passes without a
 * {@link #touch()}.
 *
 * <p>The countdown starts on construction. Each {@link #touch()} cancels the pending expiry and
 * schedules a fresh one. When an expiry fires, {@code onLock} runs exactly once for it; the timer
 * is then idle until the next {@link #touch()} re-arms it.
 *
 * <p><b>Executor ownership.</b> The {@link ScheduledExecutorService} is injected and owned by the
 * caller. {@link #close()} cancels this timer's pending expiry but never shuts the executor down;
 * the caller must do that. {@link #newDaemonScheduler()} builds a suitable executor.
 *
 * <p><b>Failure policy.</b> If {@code onLock} throws a {@link RuntimeException}, the timer state is
 * already consistent (no pending expiry, not closed), so a later {@link #touch()} re-arms it
 * normally. The exception is not swallowed: it is handed to the running thread's {@link
 * Thread.UncaughtExceptionHandler} rather than being parked unseen in the expired future.
 *
 * <p>Shared state is guarded by a {@link ReentrantLock} ({@code lock}); {@code synchronized} is
 * banned by the PMD CERT rule set. Error Prone's {@code @GuardedBy} annotation is not on the
 * compile classpath, so the guard is documented per field instead.
 */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: TPS00-J executor; PMD 7 flags executors too
public final class IdleLock implements AutoCloseable {

    /** Upper bound on the timeout (SR-504): one day. */
    static final Duration MAX_TIMEOUT = Duration.ofHours(24);

    private static final String THREAD_NAME = "pm-idle-lock";

    private final long timeoutNanos;
    private final Runnable onLock;
    private final ScheduledExecutorService ses;
    private final ReentrantLock lock = new ReentrantLock();

    /** Guarded by {@code lock}: the expiry currently scheduled, or {@code null}. */
    private ScheduledFuture<?> pending;

    /** Guarded by {@code lock}: incremented on every (re)schedule so stale expiries do nothing. */
    private long generation;

    /** Guarded by {@code lock}: once true, nothing is ever scheduled again. */
    private boolean closed;

    /**
     * Creates the timer and starts the countdown (SR-504).
     *
     * @param timeout idle period; must be positive and at most 24 hours
     * @param onLock action run once per expiry
     * @param ses scheduler used for the countdown; owned by the caller and never shut down here
     * @throws IllegalArgumentException if {@code timeout} is not positive or exceeds 24 hours
     */
    public IdleLock(Duration timeout, Runnable onLock, ScheduledExecutorService ses) {
        Objects.requireNonNull(timeout, "timeout");
        this.onLock = Objects.requireNonNull(onLock, "onLock");
        this.ses = Objects.requireNonNull(ses, "ses");
        if (timeout.isNegative() || timeout.isZero() || timeout.compareTo(MAX_TIMEOUT) > 0) {
            throw new IllegalArgumentException("idle timeout must be in (0, 24h]: " + timeout);
        }
        this.timeoutNanos = timeout.toNanos();
        touch(); // starts the countdown; the class is final, so this cannot escape to a subclass
    }

    /**
     * Builds a single-thread scheduler on a named daemon thread for use with this class (SR-504).
     * Cancelled expiries are removed from the queue immediately, so frequent {@link #touch()} calls
     * do not accumulate. The caller owns the returned executor and must shut it down.
     *
     * @return a new scheduler whose only worker is a daemon thread named {@code pm-idle-lock}
     */
    public static ScheduledExecutorService newDaemonScheduler() {
        ThreadFactory factory =
                r -> {
                    Thread t = new Thread(r, THREAD_NAME);
                    t.setDaemon(true);
                    return t;
                };
        ScheduledThreadPoolExecutor exec = new ScheduledThreadPoolExecutor(1, factory);
        exec.setRemoveOnCancelPolicy(true);
        return exec;
    }

    /** Restarts the countdown; called on every key event. A no-op after {@link #close()}. */
    public void touch() {
        lock.lock();
        try {
            if (closed) {
                return;
            }
            rescheduleLocked();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Cancels any pending lock and disables further {@link #touch()} calls. Idempotent. Does
     * <em>not</em> shut down the injected executor, which belongs to the caller.
     */
    @Override
    public void close() {
        lock.lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
            generation++;
            cancelPendingLocked();
        } finally {
            lock.unlock();
        }
    }

    private void rescheduleLocked() {
        cancelPendingLocked();
        long gen = ++generation;
        pending = ses.schedule(() -> expire(gen), timeoutNanos, TimeUnit.NANOSECONDS);
    }

    private void cancelPendingLocked() {
        if (pending != null) {
            pending.cancel(false);
            pending = null;
        }
    }

    private void expire(long gen) {
        lock.lock();
        try {
            if (closed || gen != generation) {
                return; // superseded by a touch() or close() that raced this expiry
            }
            pending = null;
        } finally {
            lock.unlock();
        }
        try {
            onLock.run();
        } catch (RuntimeException e) {
            Thread current = Thread.currentThread();
            current.getUncaughtExceptionHandler().uncaughtException(current, e);
        }
    }
}
