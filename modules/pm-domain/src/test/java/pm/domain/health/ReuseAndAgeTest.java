package pm.domain.health;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pm.domain.health.Records.id;
import static pm.domain.health.Records.secret;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.vault.record.LoginRecord;

class ReuseAndAgeTest {
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void reusedPasswordsAreGroupedLargestFirstInInputOrder() {
        List<SecretBytes> secrets = new ArrayList<>();
        try {
            String[] pws = {"alpha-sample", "beta-sample", "alpha-sample", "", "gamma-sample", "beta-sample",
                "alpha-sample", ""};
            List<ReuseCheck.Entry> entries = new ArrayList<>();
            for (int i = 0; i < pws.length; i++) {
                secrets.add(secret(pws[i]));
                entries.add(new ReuseCheck.Entry(id(i), secrets.get(i)));
            }
            List<ReuseGroup> groups = ReuseCheck.find(entries);
            assertEquals(List.of(new ReuseGroup(List.of(id(0), id(2), id(6))), new ReuseGroup(List.of(id(1), id(5)))),
                    groups);
            assertTrue(secrets.stream().noneMatch(SecretBytes::isClosed), "caller keeps ownership");
            assertEquals(List.of(), ReuseCheck.find(entries.subList(0, 2)));
            assertEquals(List.of(), ReuseCheck.find(List.of()));
        } finally {
            secrets.forEach(SecretBytes::close);
        }
    }

    @Test
    void manyDistinctPasswordsProduceNoFalseGroups() {
        List<SecretBytes> secrets = new ArrayList<>();
        try {
            List<ReuseCheck.Entry> entries = new ArrayList<>();
            for (int i = 0; i < 2000; i++) {
                secrets.add(secret("sample-" + i));
                entries.add(new ReuseCheck.Entry(id(i), secrets.get(i)));
            }
            secrets.add(secret("sample-1999"));
            entries.add(new ReuseCheck.Entry(id(9999), secrets.get(secrets.size() - 1)));
            assertEquals(List.of(new ReuseGroup(List.of(id(1999), id(9999)))), ReuseCheck.find(entries));
        } finally {
            secrets.forEach(SecretBytes::close);
        }
    }

    @Test
    void reuseValidation() {
        assertThrows(NullPointerException.class, () -> ReuseCheck.find(null));
        assertThrows(NullPointerException.class, () -> new ReuseCheck.Entry(null, null));
        assertThrows(NullPointerException.class, () -> new ReuseCheck.Entry(UUID.randomUUID(), null));
        assertThrows(IllegalArgumentException.class, () -> new ReuseGroup(List.of(id(1))));
        assertThrows(NullPointerException.class, () -> new ReuseGroup(null));
    }

    @Test
    void ageIsMeasuredFromTheLastUpdateAgainstTheInjectedClock() {
        AgeCheck check = new AgeCheck(CLOCK, Duration.ofDays(365));
        try (LoginRecord exactly = Records.login(1, "x-sample", NOW.minus(Duration.ofDays(365)));
                LoginRecord older = Records.login(2, "x-sample", NOW.minus(Duration.ofDays(365)).minusSeconds(1));
                LoginRecord future = Records.login(3, "x-sample", NOW.plus(Duration.ofDays(2)))) {
            assertFalse(check.isOld(exactly));
            assertTrue(check.isOld(older));
            assertEquals(Duration.ofDays(365).plusSeconds(1), check.age(older));
            assertEquals(Duration.ZERO, check.age(future));
            assertFalse(check.isOld(future));
        }
        assertThrows(IllegalArgumentException.class, () -> new AgeCheck(CLOCK, Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new AgeCheck(CLOCK, Duration.ofDays(-1)));
        assertThrows(NullPointerException.class, () -> new AgeCheck(null, Duration.ofDays(1)));
        assertThrows(NullPointerException.class, () -> check.age((Instant) null));
        assertEquals(Duration.ofDays(365), AgeCheck.DEFAULT_MAX_AGE);
    }
}
