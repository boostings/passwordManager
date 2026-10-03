package pm.domain.health;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pm.domain.health.Records.id;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import pm.vault.record.LoginRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

class HealthCheckTest {
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String STRONG = "k#9Tq!vM2z&Rb7@x-sample";

    @Test
    void reportsWeakReusedAndOldWithoutTouchingThePasswords() {
        Instant fresh = NOW.minus(Duration.ofDays(10));
        Instant stale = NOW.minus(Duration.ofDays(400));
        try (LoginRecord weak = Records.login(1, "Password1", fresh);
                LoginRecord reusedA = Records.login(2, STRONG, fresh);
                LoginRecord reusedB = Records.login(3, STRONG, stale);
                LoginRecord fine = Records.login(4, "Zr8$wQ!m3Lp#Tx6&-sample", fresh);
                WifiRecord open = Records.wifi(5, "OPEN", "", stale);
                WifiRecord home = Records.wifi(6, "WPA3", "aaaaaaaaaaaa", fresh)) {
            List<VaultRecord> records = List.of(weak, reusedA, reusedB, fine, open, home);
            HealthReport report = new HealthCheck(CLOCK).run(records);
            assertEquals(5, report.checked(), "the open network has no password to check");
            assertEquals(List.of(id(1), id(6)), report.weak().stream().map(HealthReport.Weak::id).toList());
            assertTrue(report.weak().get(0).estimate().weaknesses().contains(Weakness.COMMON));
            assertEquals(List.of(new ReuseGroup(List.of(id(2), id(3)))), report.reused());
            assertEquals(List.of(new HealthReport.Old(id(3), Duration.ofDays(400))), report.old());
            assertFalse(report.isClean());
            assertTrue(records.stream().map(HealthCheck::password).allMatch(p -> !p.isClosed()));
        }
    }

    @Test
    void cleanVaultAndCustomMaxAge() {
        try (LoginRecord a = Records.login(1, STRONG, NOW.minus(Duration.ofDays(40)))) {
            assertTrue(new HealthCheck(CLOCK).run(List.of(a)).isClean());
            HealthReport strict = new HealthCheck(CLOCK, Duration.ofDays(30)).run(List.of(a));
            assertEquals(List.of(id(1)), strict.old().stream().map(HealthReport.Old::id).toList());
        }
        assertTrue(new HealthCheck(CLOCK).run(List.of()).isClean());
        assertThrows(NullPointerException.class, () -> new HealthCheck(CLOCK).run(null));
        assertThrows(IllegalArgumentException.class, () -> new HealthReport(-1, List.of(), List.of(), List.of()));
        assertThrows(NullPointerException.class, () -> new HealthReport.Weak(null, null));
        assertThrows(NullPointerException.class, () -> new HealthReport.Old(id(1), null));
    }
}
