package pm.crypto.log;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAccessor;
import java.time.temporal.TemporalField;
import java.time.temporal.UnsupportedTemporalTypeException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.DoubleAdder;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import pm.crypto.SecretBytes;
import pm.crypto.Sensitive;

/**
 * SR-500: captures what {@link SafeLog} actually emits and proves a canary secret never reaches the
 * log, whatever shape it is wrapped in (adversarial-review finding F1).
 */
final class SafeLogLeakTest {
    private static final String CANARY = "hunter2-CANARY-7f3a";
    private static final String EVENT = "TEST_EVENT";

    /** A sensitive class whose {@code toString} would leak the canary. */
    @Sensitive
    private static class Creds {
        @Override
        public String toString() {
            return "Creds[" + CANARY + "]";
        }
    }

    /** Not annotated itself; inherits {@code @Sensitive} from {@link Creds}. */
    private static final class SubCreds extends Creds {
    }

    /** A sensitive record whose generated {@code toString} would leak the canary. */
    @Sensitive
    private record Entry(String site, String password) {
    }

    /** An enum whose {@code toString} would leak; SafeLog must render {@code name()}. */
    private enum Mode {
        PLAIN {
            @Override
            public String toString() {
                return CANARY;
            }
        }
    }

    /** A project {@code Number} subclass; not a JDK value type, so it is refused. */
    private static final class LeakyNumber extends Number {
        private static final long serialVersionUID = 1L;

        @Override
        public int intValue() {
            return 0;
        }

        @Override
        public long longValue() {
            return 0;
        }

        @Override
        public float floatValue() {
            return 0;
        }

        @Override
        public double doubleValue() {
            return 0;
        }

        @Override
        public String toString() {
            return CANARY;
        }
    }

    /** A project {@code TemporalAccessor}; not a java.base class, so it is refused. */
    private static final class LeakyTemporal implements TemporalAccessor {
        @Override
        public boolean isSupported(TemporalField field) {
            return false;
        }

        @Override
        public long getLong(TemporalField field) {
            throw new UnsupportedTemporalTypeException("none");
        }

        @Override
        public String toString() {
            return CANARY;
        }
    }

    /** {@link System.Logger} that records every emitted message. */
    private static final class Capture implements System.Logger {
        private final List<String> lines = Collections.synchronizedList(new ArrayList<>());

        @Override
        public String getName() {
            return "capture";
        }

        @Override
        public boolean isLoggable(Level level) {
            return true;
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String msg, Throwable thrown) {
            lines.add(msg);
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String format, Object... params) {
            lines.add(format);
        }

        String all() {
            return String.join("\n", lines);
        }
    }

    /** A mutable builder holding the canary, as a caller might pass one. */
    private static StringBuilder builderOf(char[] chars) {
        StringBuilder builder = new StringBuilder(chars.length);
        builder.append(chars);
        return builder;
    }

    private static byte[] canaryBytes() {
        return CANARY.getBytes(StandardCharsets.UTF_8);
    }

    private static LongAdder adderOf(byte[] key) {
        LongAdder adder = new LongAdder();
        adder.add(ByteBuffer.wrap(key).getLong());
        return adder;
    }

    static Stream<Arguments> wrappedSecrets() {
        Supplier<char[]> pw = CANARY::toCharArray;
        return Stream.of(
                Arguments.of("CharBuffer", (Supplier<Object>) () -> CharBuffer.wrap(pw.get())),
                Arguments.of("StringBuilder", (Supplier<Object>) () -> builderOf(pw.get())),
                Arguments.of("List<@Sensitive class>", (Supplier<Object>) () -> List.of(new Creds())),
                Arguments.of("List<@Sensitive record>", (Supplier<Object>) () -> List.of(new Entry("bank", CANARY))),
                Arguments.of("Optional<@Sensitive record>",
                        (Supplier<Object>) () -> Optional.of(new Entry("bank", CANARY))),
                Arguments.of("Map value", (Supplier<Object>) () -> Map.of("k", new Entry("x", CANARY))),
                Arguments.of("Map value String", (Supplier<Object>) () -> Map.of("k", CANARY)),
                Arguments.of("subclass of @Sensitive", (Supplier<Object>) SubCreds::new),
                Arguments.of("direct @Sensitive record", (Supplier<Object>) () -> new Entry("bank", CANARY)),
                Arguments.of("Object[] wrapping String", (Supplier<Object>) () -> new Object[] {CANARY}),
                Arguments.of("Object[] wrapping char[]", (Supplier<Object>) () -> new Object[] {pw.get()}),
                Arguments.of("List<Character>", (Supplier<Object>) () -> CANARY.chars().mapToObj(c -> (char) c).toList()),
                Arguments.of("char[]", (Supplier<Object>) pw::get),
                Arguments.of("byte[]", (Supplier<Object>) () -> CANARY.getBytes(StandardCharsets.UTF_8)),
                Arguments.of("project Number subclass", (Supplier<Object>) LeakyNumber::new),
                Arguments.of("project TemporalAccessor", (Supplier<Object>) LeakyTemporal::new),
                Arguments.of("BigInteger(key)", (Supplier<Object>) () -> new BigInteger(1, canaryBytes())),
                Arguments.of("BigDecimal(key)",
                        (Supplier<Object>) () -> new BigDecimal(new BigInteger(1, canaryBytes()))),
                Arguments.of("AtomicLong(key prefix)",
                        (Supplier<Object>) () -> new AtomicLong(ByteBuffer.wrap(canaryBytes()).getLong())),
                Arguments.of("AtomicInteger(key prefix)",
                        (Supplier<Object>) () -> new AtomicInteger(ByteBuffer.wrap(canaryBytes()).getInt())),
                Arguments.of("LongAdder(key prefix)", (Supplier<Object>) () -> adderOf(canaryBytes())),
                Arguments.of("Throwable", (Supplier<Object>) () -> new IllegalStateException(CANARY)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("wrappedSecrets")
    void wrappedSecretNeverReachesTheLog(String shape, Supplier<Object> secret) {
        Capture capture = new Capture();
        SafeLog log = SafeLog.over(capture);
        Object arg = secret.get();
        assertThrows(IllegalArgumentException.class, () -> log.info(EVENT, "ok", arg), shape);
        assertThrows(IllegalArgumentException.class, () -> log.warn(EVENT, arg), shape);
        assertThrows(IllegalArgumentException.class, () -> log.error(EVENT, arg), shape);
        assertTrue(capture.lines.isEmpty(), shape + " emitted: " + capture.all());
        assertFalse(capture.all().contains(CANARY), shape);
    }

    @Test
    void secretInsideListOfSecretBytesIsRefused() {
        Capture capture = new Capture();
        try (SecretBytes s = SecretBytes.copyOf(CANARY.getBytes(StandardCharsets.UTF_8))) {
            assertThrows(IllegalArgumentException.class, () -> SafeLog.over(capture).info(EVENT, List.of(s)));
        }
        assertTrue(capture.lines.isEmpty());
    }

    @Test
    void varargsArrayOfSecretBytesIsRefused() {
        Capture capture = new Capture();
        try (SecretBytes s = SecretBytes.copyOf(CANARY.getBytes(StandardCharsets.UTF_8))) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> SafeLog.over(capture).info(EVENT, new Object[] {s}));
            assertEquals("SECRET_ARG", e.getMessage());
        }
        assertTrue(capture.lines.isEmpty());
    }

    @Test
    void subclassOfSensitiveIsRefusedAsSecret() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> SafeLog.over(new Capture()).info(EVENT, new SubCreds()));
        assertEquals("SECRET_ARG", e.getMessage());
    }

    @Test
    void secretInsideEventCodeIsRefused() {
        Capture capture = new Capture();
        SafeLog log = SafeLog.over(capture);
        for (String code : List.of("EVT pw=" + CANARY, "EVT_" + CANARY, CANARY, "evt", "", "1EVT",
                "E".repeat(65), "EVT\n" + CANARY)) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> log.info(code));
            assertEquals("BAD_EVENT_CODE", e.getMessage());
            assertFalse(e.getMessage().contains(CANARY));
        }
        assertTrue(capture.lines.isEmpty(), capture.all());
    }

    @Test
    void longestValidEventCodeIsAccepted() {
        Capture capture = new Capture();
        String code = "E" + "_9".repeat(31) + "Z";
        SafeLog.over(capture).info(code);
        assertEquals(List.of(code), capture.lines);
    }

    @Test
    void enumIsRenderedByNameNotToString() {
        Capture capture = new Capture();
        SafeLog.over(capture).info(EVENT, Mode.PLAIN);
        assertEquals(List.of(EVENT + " PLAIN"), capture.lines);
    }

    @Test
    void allowlistedValuesAreEmitted() {
        Capture capture = new Capture();
        UUID id = new UUID(1, 2);
        Instant at = Instant.EPOCH;
        SafeLog.over(capture).warn(EVENT, "text", 42, 7L, 1.5d, true, 'c', id, Duration.ofSeconds(3), at,
                Path.of("vault"), null);
        assertEquals(List.of(EVENT + " text 42 7 1.5 true c " + id + " PT3S " + at + " vault null"),
                capture.lines);
    }

    /** D5: each java.base boxed primitive is accepted; nothing wider. */
    @Test
    void everyBoxedPrimitiveNumberIsEmitted() {
        Capture capture = new Capture();
        SafeLog.over(capture).info(EVENT, 1, 2L, (short) 3, (byte) 4, 5.5f, 6.5d);
        assertEquals(List.of(EVENT + " 1 2 3 4 5.5 6.5"), capture.lines);
    }

    /** D5: wide JDK numbers are refused as UNLOGGABLE_ARG, even holding a harmless value. */
    @Test
    void wideJdkNumbersAreRefused() {
        Capture capture = new Capture();
        SafeLog log = SafeLog.over(capture);
        for (Object n : List.of(BigInteger.ONE, BigDecimal.ONE, new AtomicInteger(1), new AtomicLong(1),
                new LongAdder(), new DoubleAdder())) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> log.info(EVENT, n));
            assertEquals("UNLOGGABLE_ARG", e.getMessage(), n.getClass().getName());
        }
        assertTrue(capture.lines.isEmpty(), capture.all());
    }
}
