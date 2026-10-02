package pm.crypto.log;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.crypto.Sensitive;

/** SR-500: {@link SafeLog} refuses secret-bearing arguments at every level. */
final class SafeLogTest {
    private static final String EVENT = "TEST_EVENT";
    private static final String REFUSAL_CODE = "SECRET_ARG";
    private static final SafeLog LOG = SafeLog.of(SafeLogTest.class);

    /** One of the SafeLog level methods. */
    @FunctionalInterface
    private interface Emitter {
        void emit(SafeLog log, String eventCode, Object... args);
    }

    /** A test type carrying the {@code @Sensitive} marker. */
    @Sensitive
    private static final class Tagged {
        @Override
        public String toString() {
            return "Tagged";
        }
    }

    @Test
    void refusesSecretBytes() {
        try (SecretBytes refused = SecretBytes.copyOf(new byte[] {1, 2, 3})) {
            assertRefusedAtEveryLevel(refused);
        }
    }

    @Test
    void refusesSecretChars() {
        try (SecretChars refused = SecretChars.takeOwnership(new char[] {'a', 'b'})) {
            assertRefusedAtEveryLevel(refused);
        }
    }

    @Test
    void refusesByteArray() {
        assertRefusedAtEveryLevel(new byte[] {1});
    }

    @Test
    void refusesCharArray() {
        assertRefusedAtEveryLevel(new char[] {'x'});
    }

    @Test
    void refusesSensitiveAnnotatedType() {
        assertRefusedAtEveryLevel(new Tagged());
    }

    @Test
    void refusesWhenAnyArgIsRefused() {
        assertRefusedAtEveryLevel("ok", 1, new byte[] {1});
    }

    @Test
    void acceptsPlainArgsAndNull() {
        Object[] plain = {"text", 42, null};
        assertDoesNotThrow(() -> LOG.info(EVENT, plain));
        assertDoesNotThrow(() -> LOG.warn(EVENT, plain));
        assertDoesNotThrow(() -> LOG.error(EVENT, plain));
        assertDoesNotThrow(() -> LOG.info(EVENT));
        assertDoesNotThrow(() -> LOG.info(EVENT, (Object[]) null));
    }

    @Test
    void nullEventCodeIsRejected() {
        assertThrows(NullPointerException.class, () -> LOG.info(null, "x"));
    }

    @Test
    void ofNullThrows() {
        assertThrows(NullPointerException.class, () -> SafeLog.of(null));
    }

    private static void assertRefusedAtEveryLevel(Object... args) {
        assertRefused(SafeLog::info, args);
        assertRefused(SafeLog::warn, args);
        assertRefused(SafeLog::error, args);
    }

    private static void assertRefused(Emitter level, Object... args) {
        IllegalArgumentException e =
                assertThrows(IllegalArgumentException.class, () -> callAt(level, args));
        assertEquals(REFUSAL_CODE, e.getMessage());
    }

    private static void callAt(Emitter level, Object... args) {
        level.emit(LOG, EVENT, args);
    }
}
