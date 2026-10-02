package pm.tui;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ScheduledExecutorService;

/**
 * Idle auto-lock timer (SR-504): runs {@code onLock} once {@code timeout} passes without a
 * {@link #touch()}.
 */
@SuppressWarnings({
    "PMD.DoNotUseThreads", // CE-002: TPS00-J executor; PMD 7 flags executors too
    "DoNotCallSuggester" // M1 stub: removed when implemented (not a CERT suppression)
})
public final class IdleLock implements AutoCloseable {

    /** Creates the timer; scheduling uses {@code ses}. */
    public IdleLock(Duration timeout, Runnable onLock, ScheduledExecutorService ses) {
        Objects.requireNonNull(timeout, "timeout");
        Objects.requireNonNull(onLock, "onLock");
        Objects.requireNonNull(ses, "ses");
    }

    /** Restarts the countdown; called on every key event. */
    public void touch() {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Cancels any pending lock. */
    @Override
    public void close() {
        throw new UnsupportedOperationException("M1 stub");
    }
}
