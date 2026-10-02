package pm.tui;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.Callable;
import java.util.concurrent.Delayed;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Deterministic {@link ScheduledExecutorService} for {@link IdleLockTest} (SR-504): a manual clock
 * that runs due one-shot tasks on the calling thread only when {@link #advance(Duration)} is called.
 */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: test double of an executor; no threads are created
final class IdleLockFakeScheduler extends AbstractExecutorService implements ScheduledExecutorService {

    private final List<Task> tasks = new ArrayList<>();
    private long nowNanos;
    private long nextSeq;
    private boolean stopped;

    /** Moves the clock forward, running every task that falls due, in due order. */
    void advance(Duration d) {
        long target = nowNanos + d.toNanos();
        Optional<Task> next = nextDue(target);
        while (next.isPresent()) {
            Task t = next.get();
            tasks.remove(t);
            nowNanos = t.dueNanos;
            t.done = true;
            t.command.run();
            next = nextDue(target);
        }
        nowNanos = target;
    }

    /** Number of scheduled tasks that are neither cancelled nor run. */
    long liveTasks() {
        return tasks.stream().filter(t -> !t.cancelled).count();
    }

    private Optional<Task> nextDue(long target) {
        return tasks.stream()
                .filter(t -> !t.cancelled && t.dueNanos <= target)
                .min(Comparator.comparingLong((Task t) -> t.dueNanos).thenComparingLong(t -> t.seq));
    }

    @Override
    public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
        Task t = new Task(command, nowNanos + unit.toNanos(delay), nextSeq++);
        tasks.add(t);
        return t;
    }

    @Override
    public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) {
        throw new UnsupportedOperationException("not used by IdleLock");
    }

    @Override
    public ScheduledFuture<?> scheduleAtFixedRate(Runnable command, long initialDelay, long period, TimeUnit unit) {
        throw new UnsupportedOperationException("not used by IdleLock");
    }

    @Override
    public ScheduledFuture<?> scheduleWithFixedDelay(Runnable command, long initialDelay, long delay, TimeUnit unit) {
        throw new UnsupportedOperationException("not used by IdleLock");
    }

    @Override
    public void shutdown() {
        stopped = true;
    }

    @Override
    public List<Runnable> shutdownNow() {
        stopped = true;
        return List.of();
    }

    @Override
    public boolean isShutdown() {
        return stopped;
    }

    @Override
    public boolean isTerminated() {
        return stopped;
    }

    @Override
    public boolean awaitTermination(long timeout, TimeUnit unit) {
        return stopped;
    }

    @Override
    public void execute(Runnable command) {
        command.run();
    }

    /** A one-shot scheduled task on the manual clock. */
    private final class Task implements ScheduledFuture<Object> {
        private final Runnable command;
        private final long dueNanos;
        private final long seq;
        private boolean cancelled;
        private boolean done;

        Task(Runnable command, long dueNanos, long seq) {
            this.command = command;
            this.dueNanos = dueNanos;
            this.seq = seq;
        }

        @Override
        public long getDelay(TimeUnit unit) {
            return unit.convert(dueNanos - nowNanos, TimeUnit.NANOSECONDS);
        }

        @Override
        public int compareTo(Delayed o) {
            return Long.compare(getDelay(TimeUnit.NANOSECONDS), o.getDelay(TimeUnit.NANOSECONDS));
        }

        // compareTo orders by delay; equality stays identity (two tasks may share a due time).
        @Override
        public boolean equals(Object o) {
            return super.equals(o);
        }

        @Override
        public int hashCode() {
            return super.hashCode();
        }

        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            boolean wasLive = !cancelled && !done;
            cancelled = true;
            return wasLive;
        }

        @Override
        public boolean isCancelled() {
            return cancelled;
        }

        @Override
        public boolean isDone() {
            return done || cancelled;
        }

        @Override
        public Object get() {
            return null;
        }

        @Override
        public Object get(long timeout, TimeUnit unit) {
            return null;
        }
    }
}
