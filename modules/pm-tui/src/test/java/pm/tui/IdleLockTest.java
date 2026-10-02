package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** SR-504 idle auto-lock: deterministic timing on a manual clock, plus one real-executor smoke test. */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: exercises executors and an uncaught-exception handler
class IdleLockTest {
    private static final Duration FIVE_MIN = Duration.ofMinutes(5);
    private static final Duration ONE_MIN = Duration.ofMinutes(1);

    private final IdleLockFakeScheduler clock = new IdleLockFakeScheduler();
    private final AtomicInteger locks = new AtomicInteger();

    private IdleLock newLock() {
        return new IdleLock(FIVE_MIN, locks::incrementAndGet, clock);
    }

    @Test
    void firesAtTimeout() {
        try (IdleLock idle = newLock()) {
            clock.advance(FIVE_MIN.minusNanos(1));
            assertEquals(0, locks.get());
            clock.advance(Duration.ofNanos(1));
            assertEquals(1, locks.get());
            assertEquals(0, clock.liveTasks());
            idle.touch(); // re-arms after an expiry
            assertEquals(1, clock.liveTasks());
        }
    }

    @Test
    void firesOncePerExpiryUntilTouched() {
        try (IdleLock idle = newLock()) {
            clock.advance(FIVE_MIN);
            clock.advance(Duration.ofHours(1));
            assertEquals(1, locks.get());
            assertEquals(0, clock.liveTasks());
            idle.touch();
            clock.advance(FIVE_MIN);
            assertEquals(2, locks.get());
        }
    }

    @Test
    void touchAtFourMinutesDefersLockToNine() {
        try (IdleLock idle = newLock()) {
            clock.advance(Duration.ofMinutes(4));
            idle.touch();
            clock.advance(ONE_MIN); // t = 5 min
            assertEquals(0, locks.get());
            clock.advance(Duration.ofMinutes(4).minusNanos(1)); // just before t = 9 min
            assertEquals(0, locks.get());
            clock.advance(Duration.ofNanos(1)); // t = 9 min
            assertEquals(1, locks.get());
            assertEquals(0, clock.liveTasks());
        }
    }

    @Test
    void touchLeavesExactlyOnePendingExpiry() {
        try (IdleLock idle = newLock()) {
            idle.touch();
            idle.touch();
            idle.touch();
            assertEquals(1, clock.liveTasks());
        }
    }

    @Test
    void closePreventsFiring() {
        IdleLock idle = newLock();
        try (idle) { // closed here; the test then probes post-close behaviour
            idle.touch();
            clock.advance(Duration.ofMinutes(4));
        }
        assertEquals(0, clock.liveTasks());
        clock.advance(Duration.ofHours(1));
        assertEquals(0, locks.get());
    }

    @Test
    void closeTwiceIsHarmlessAndLeavesExecutorRunning() {
        IdleLock idle = newLock();
        try (idle) { // closed here; the test then probes post-close behaviour
            idle.touch();
            assertEquals(1, clock.liveTasks());
        }
        idle.close();
        assertEquals(0, clock.liveTasks());
        clock.advance(Duration.ofHours(1));
        assertEquals(0, locks.get());
        assertFalse(clock.isShutdown(), "close() must not shut down the caller-owned executor");
    }

    @Test
    void touchAfterCloseDoesNothing() {
        IdleLock idle = newLock();
        try (idle) { // closed here; the test then probes post-close behaviour
            idle.touch();
            assertEquals(1, clock.liveTasks());
        }
        idle.touch();
        assertEquals(0, clock.liveTasks());
        clock.advance(Duration.ofHours(1));
        assertEquals(0, locks.get());
    }

    @Test
    void onLockExceptionIsReportedAndTimerKeepsWorking() {
        AtomicInteger calls = new AtomicInteger();
        IllegalStateException boom = new IllegalStateException("boom");
        Runnable failingOnce =
                () -> {
                    if (calls.getAndIncrement() == 0) {
                        throw boom;
                    }
                };
        List<Throwable> reported = new ArrayList<>();
        Thread current = Thread.currentThread();
        Thread.UncaughtExceptionHandler saved = current.getUncaughtExceptionHandler();
        current.setUncaughtExceptionHandler((t, e) -> reported.add(e));
        try (IdleLock idle = new IdleLock(FIVE_MIN, failingOnce, clock)) {
            clock.advance(FIVE_MIN);
            assertEquals(1, calls.get());
            assertEquals(1, reported.size());
            assertSame(boom, reported.get(0));
            assertEquals(0, clock.liveTasks());

            idle.touch();
            assertEquals(1, clock.liveTasks());
            clock.advance(FIVE_MIN);
            assertEquals(2, calls.get());
            assertEquals(1, reported.size());
        } finally {
            current.setUncaughtExceptionHandler(saved);
        }
    }

    @Test
    void rejectsInvalidTimeouts() {
        Runnable noop = locks::incrementAndGet;
        for (Duration bad : List.of(Duration.ZERO, Duration.ofNanos(-1), Duration.ofMinutes(-5),
                Duration.ofHours(24).plusNanos(1), Duration.ofDays(365))) {
            assertThrows(IllegalArgumentException.class, () -> new IdleLock(bad, noop, clock), bad::toString);
        }
        assertEquals(0, clock.liveTasks());
        assertThrows(NullPointerException.class, () -> new IdleLock(null, noop, clock));
        assertThrows(NullPointerException.class, () -> new IdleLock(FIVE_MIN, null, clock));
        assertThrows(NullPointerException.class, () -> new IdleLock(FIVE_MIN, noop, null));
    }

    @Test
    void acceptsBoundaryTimeouts() {
        try (IdleLock tiny = new IdleLock(Duration.ofNanos(1), locks::incrementAndGet, clock);
                IdleLock day = new IdleLock(Duration.ofHours(24), locks::incrementAndGet, clock)) {
            clock.advance(Duration.ofHours(24));
            assertEquals(2, locks.get());
            tiny.touch();
            day.touch();
            assertEquals(2, clock.liveTasks());
        }
    }

    @Test
    void realDaemonSchedulerFiresSmoke() throws InterruptedException {
        ScheduledExecutorService ses = IdleLock.newDaemonScheduler();
        try {
            CountDownLatch fired = new CountDownLatch(1);
            AtomicInteger daemon = new AtomicInteger();
            Runnable onLock =
                    () -> {
                        Thread t = Thread.currentThread();
                        daemon.set(t.isDaemon() && "pm-idle-lock".equals(t.getName()) ? 1 : -1);
                        fired.countDown();
                    };
            try (IdleLock idle = new IdleLock(Duration.ofMillis(50), onLock, ses)) {
                assertTrue(fired.await(2, TimeUnit.SECONDS), "idle lock did not fire within 2 s");
                assertEquals(1, daemon.get());
                idle.touch();
            }
            assertFalse(ses.isShutdown(), "close() must not shut down the caller-owned executor");
        } finally {
            ses.shutdownNow();
        }
    }
}
