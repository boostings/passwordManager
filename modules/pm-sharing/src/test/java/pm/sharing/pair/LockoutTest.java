package pm.sharing.pair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** SR-203: three failures lock pairing for 60 s, each further failure doubles it, capped at 1 h. */
@Tag("T-LAN-04")
class LockoutTest {
    private static final Instant T0 = Instant.parse("2026-10-03T12:00:00Z");

    @Test
    void theWaitDoublesFromSixtySecondsToTheOneHourCap() {
        Lockout l = new Lockout();
        l.failed(T0);
        l.failed(T0);
        assertTrue(l.allows(T0));
        assertEquals(Duration.ZERO, l.remaining(T0));
        long[] expected = {60, 120, 240, 480, 960, 1920, 3600, 3600, 3600};
        for (long seconds : expected) {
            l.failed(T0);
            assertFalse(l.allows(T0));
            assertEquals(Duration.ofSeconds(seconds), l.remaining(T0));
            assertTrue(l.allows(T0.plusSeconds(seconds)));
        }
    }

    @Test
    void successClearsTheCountButNotACurrentLock() {
        Lockout l = new Lockout();
        for (int i = 0; i < 3; i++) {
            l.failed(T0);
        }
        l.succeeded();
        assertFalse(l.allows(T0.plusSeconds(59)));
        Instant later = T0.plusSeconds(60);
        l.failed(later);
        l.failed(later);
        assertTrue(l.allows(later));
        l.failed(later);
        assertEquals(Lockout.FIRST, l.remaining(later));
    }
}
