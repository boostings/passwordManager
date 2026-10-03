package pm.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import pm.domain.env.DotEnv;
import pm.domain.env.DotEnvException;
import pm.domain.env.EnvEntry;

/**
 * Fuzz harness for the {@code .env} parser (plan.md §13 M2 exit criteria, T-FUZZ-ENV). Imported
 * files are untrusted, so {@link DotEnv#parse} may only throw {@link DotEnvException}; anything
 * else, or an accepted result that breaks the limits below, fails the run. The 24 CPU-hour
 * campaign runs this target with {@code JAZZER_FUZZ=1}; without it the seed corpus in
 * {@code DotEnvFuzzTestInputs} is replayed as a regression test.
 */
class DotEnvFuzzTest {
    @FuzzTest
    void fuzz(byte[] in) {
        List<EnvEntry> entries;
        try {
            entries = DotEnv.parse(in);
        } catch (DotEnvException expected) {
            return; // rejecting input is the expected outcome for most mutations
        }
        try {
            assertTrue(entries.size() <= DotEnv.MAX_ENTRIES, "entry limit");
            Set<String> names = new HashSet<>();
            entries.stream().map(EnvEntry::name).forEach(n -> {
                assertTrue(DotEnv.isValidName(n), "name syntax");
                assertTrue(names.add(n), "duplicate name accepted");
            });
            int[] lengths = entries.stream().mapToInt(e -> e.value().length()).toArray();
            assertTrue(IntStream.of(lengths).allMatch(n -> n <= DotEnv.MAX_VALUE_BYTES), "value limit");
            int valueBytes = IntStream.of(lengths).sum();
            // Every value byte came from the input, which also holds names and separators.
            assertTrue(valueBytes <= in.length, "values longer than the file");
        } finally {
            entries.forEach(EnvEntry::close);
        }
    }

    /** Each seed is accepted or rejected exactly as its name says. */
    @Test
    void seedCorpusParsesAsLabelled() throws IOException, DotEnvException {
        Map<String, Integer> accepted = Map.of("typical.env", 4, "bom-crlf.env", 2, "quoted-multiline.env", 2);
        for (Map.Entry<String, Integer> seed : accepted.entrySet()) {
            List<EnvEntry> entries = DotEnv.parse(Seeds.read(DotEnvFuzzTest.class, seed.getKey()));
            assertEquals(seed.getValue(), entries.size(), seed.getKey());
            entries.forEach(EnvEntry::close);
        }
        Map<String, DotEnvException.Code> rejected = Map.of(
                "duplicate.env", DotEnvException.Code.DUPLICATE_NAME,
                "bad-name.env", DotEnvException.Code.BAD_NAME);
        for (Map.Entry<String, DotEnvException.Code> seed : rejected.entrySet()) {
            byte[] file = Seeds.read(DotEnvFuzzTest.class, seed.getKey());
            DotEnvException e = assertThrows(DotEnvException.class, () -> DotEnv.parse(file), seed.getKey());
            assertEquals(seed.getValue(), e.code(), seed.getKey());
        }
    }

    /** The size limit is checked before anything is read. */
    @Test
    void oversizedInputIsRejectedUpFront() {
        DotEnvException e = assertThrows(DotEnvException.class,
                () -> DotEnv.parse(new byte[DotEnv.MAX_INPUT_BYTES + 1]));
        assertEquals(DotEnvException.Code.TOO_LARGE, e.code());
    }
}
