package pm.domain.health;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.fuzz.Allocation;
import pm.fuzz.Seeds;
import pm.fuzz.Stretch;

/**
 * Fuzz harness for the breach range response parser (ADR 0012 §8, SR-074, SR-078, T-FUZZ-BREACH).
 * It lives in {@code pm.domain.health} so it can reach the package-private {@code match} and the
 * production body collector ({@code BreachClient.boundedBody()}, capped at the client's own 1 MiB)
 * without a network round trip per input.
 *
 * <p>The input is a response body, optionally {@link Stretch stretched} so a 4 KiB input can describe
 * a body at or past 1 MiB. Oracles, each independent of the parser:
 * <ul>
 *   <li>differential: {@link BreachClient#match} agrees with {@link #reference}, a separate
 *       line-by-line reading of the format ADR 0012 §8 fixes (35 uppercase hex, {@code :}, 1 to 18
 *       digits, optional CR, blank lines skipped, no lines at all is {@code MALFORMED}, the count
 *       is the largest on a matching line);</li>
 *   <li>only {@link BreachCheckException} with {@code MALFORMED}, its message the code name;</li>
 *   <li>the suffix buffer is zero-filled on every path;</li>
 *   <li>bounded allocation: at most {@code 1 MiB + 4 x input} per call;</li>
 *   <li>the production collector, fed the same bytes in chunks the input chooses, returns exactly
 *       them when they are at most {@link #MAX_BODY} (1 MiB, ADR 0012 §8, written here) and fails with
 *       {@code BodyTooLarge} when they are longer.</li>
 * </ul>
 */
@Tag("T-FUZZ-BREACH")
class BreachRangeFuzzTest {
    /** The SHA-1 suffix of "password" (5BAA6 prefix); the seeds hold lines with and without it. */
    static final String SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
    /** ADR 0012 §8 body limit, written here rather than read from the client. */
    static final int MAX_BODY = 1 << 20;
    private static final long NOT_PARSED = -1;
    /** Bodies longer than this are fed in chunks {@code 1 << CHUNK_SHIFT} times larger, to keep a run fast. */
    private static final int CHUNKY = 64 * 1024;
    private static final int CHUNK_SHIFT = 10;
    /**
     * Fixed part of the per-call allocation ceiling. A warm parse allocates a few hundred bytes, but
     * in fuzzing mode the first call through freshly instrumented code allocated 188 KiB (measured
     * 2026-10-04). A count or buffer sized from the input would allocate far more.
     */
    private static final long ALLOCATION_BASE = 1L << 20;

    /**
     * Loads and initialises every class the parser touches before anything is measured, so the
     * allocation oracle sees the parse, not one-time class loading.
     */
    @BeforeAll
    static void warmUp() throws BreachCheckException {
        byte[] body = (SUFFIX + ":1\r\n").getBytes(StandardCharsets.US_ASCII);
        assertEquals(1, BreachClient.match(body, SUFFIX.getBytes(StandardCharsets.US_ASCII)));
        assertEquals(1, reference(body));
        boundedBody(body);
        byte[] malformed = new byte[0];
        assertThrows(BreachCheckException.class,
                () -> BreachClient.match(malformed, SUFFIX.getBytes(StandardCharsets.US_ASCII)));
        boundedBody(new byte[MAX_BODY + 1]);
    }

    @FuzzTest
    void fuzz(byte[] in) {
        check(Stretch.apply(in, MAX_BODY + 1));
    }

    private static void check(byte[] body) {
        byte[] suffix = SUFFIX.getBytes(StandardCharsets.US_ASCII);
        long expected = reference(body);
        long start = Allocation.current();
        long actual;
        try {
            actual = BreachClient.match(body, suffix);
        } catch (BreachCheckException e) {
            assertEquals(BreachCheckException.Code.MALFORMED, e.code());
            assertEquals(e.code().name(), e.getMessage());
            actual = NOT_PARSED;
        }
        long used = Allocation.current() - start;
        assertTrue(used < ALLOCATION_BASE + 4L * body.length, () -> "allocation bound: " + used + " bytes");
        assertArrayEquals(new byte[suffix.length], suffix, "suffix not zero-filled");
        assertEquals(expected, actual, "differs from the reference reading");
        boundedBody(body);
    }

    /** The count for {@link #SUFFIX}, 0 for no match, {@link #NOT_PARSED} for a malformed body. */
    static long reference(byte[] body) {
        String text = new String(body, StandardCharsets.ISO_8859_1);
        long best = 0;
        boolean anyLine = false;
        for (String raw : text.split("\n", -1)) {
            String line = raw.endsWith("\r") ? raw.substring(0, raw.length() - 1) : raw;
            if (line.isEmpty()) {
                continue;
            }
            anyLine = true;
            if (!line.matches("[0-9A-F]{35}:[0-9]{1,18}")) {
                return NOT_PARSED;
            }
            if (line.startsWith(SUFFIX)) {
                best = Math.max(best, Long.parseLong(line.substring(36)));
            }
        }
        return anyLine ? best : NOT_PARSED;
    }

    /** Feeds {@code body} to the client's own collector and checks the result against {@link #MAX_BODY}. */
    private static void boundedBody(byte[] body) {
        CompletableFuture<byte[]> result = feed(body);
        if (result.isCompletedExceptionally()) {
            Throwable cause = result.handle((v, t) -> t).join();
            assertTrue(body.length > MAX_BODY, "within-limit body refused");
            assertTrue(cause instanceof BreachClient.BodyTooLarge, "unexpected failure " + cause);
        } else {
            assertTrue(body.length <= MAX_BODY, "over-limit body accepted");
            assertArrayEquals(body, result.join(), "reassembled body differs");
        }
    }

    /** Pushes {@code body} through {@code BreachClient.boundedBody()} in chunks its first byte sizes. */
    private static CompletableFuture<byte[]> feed(byte[] body) {
        BreachClient.BoundedBody sink = BreachClient.boundedBody();
        sink.onSubscribe(new Flow.Subscription() {
            @Override
            public void request(long n) {
                assertTrue(n > 0);
            }

            @Override
            public void cancel() {
                // Nothing to stop: the harness pushes the chunks itself.
            }
        });
        int chunk = body.length == 0 ? 1 : (1 + (body[0] & 0x3f)) << (body.length > CHUNKY ? CHUNK_SHIFT : 0);
        for (int at = 0; at < body.length; at += chunk) {
            sink.onNext(List.of(ByteBuffer.wrap(body, at, Math.min(chunk, body.length - at))));
        }
        sink.onComplete();
        CompletableFuture<byte[]> result = sink.getBody().toCompletableFuture();
        assertTrue(result.isDone(), "body not complete");
        return result;
    }

    /**
     * The production body limit, at and one past it, deterministically and through the fuzz entry
     * point: a stretched input whose run makes the body exactly 1 MiB is collected whole, one byte
     * more is refused.
     */
    @Test
    void productionBodyLimitHoldsAtAndJustPastOneMebibyte() {
        byte[] line = (SUFFIX + ":1\n").getBytes(StandardCharsets.US_ASCII);
        byte[] atLimit = Stretch.encode(line.length, MAX_BODY - line.length, (byte) '\n', line);
        assertEquals(MAX_BODY, Stretch.apply(atLimit, MAX_BODY + 1).length);
        fuzz(atLimit);
        byte[] overLimit = Stretch.encode(line.length, MAX_BODY - line.length + 1, (byte) '\n', line);
        assertEquals(MAX_BODY + 1, Stretch.apply(overLimit, MAX_BODY + 1).length);
        fuzz(overLimit);
        CompletableFuture<byte[]> refused = feed(new byte[MAX_BODY + 1]);
        assertTrue(refused.isCompletedExceptionally(), "a body one byte over 1 MiB was collected");
        assertEquals(MAX_BODY, feed(new byte[MAX_BODY]).join().length);
    }

    /** Each seed gives the count its name says; the reference agrees on all of them. */
    @Test
    void seedCorpusParsesAsLabelled() throws IOException {
        Map<String, Long> expected = Map.of("hit-crlf.txt", 9_545_824L, "padding-only.txt", 0L,
                "miss-no-final-newline.txt", 0L, "lowercase.txt", NOT_PARSED,
                "nineteen-digits.txt", NOT_PARSED, "blank-lines.txt", NOT_PARSED, "duplicate-suffix.txt", 7L,
                "over-body-limit.txt", 0L);
        for (Map.Entry<String, Long> seed : expected.entrySet()) {
            byte[] body = Seeds.read(BreachRangeFuzzTest.class, seed.getKey());
            assertEquals(seed.getValue(), reference(body), seed.getKey());
            fuzz(body);
        }
    }
}
