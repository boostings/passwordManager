package pm.fuzz;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/**
 * Fuzz harness for the CBOR reader under the limits of the unauthenticated vault header (SR-021,
 * T-FUZZ-VAULT). The only exception the reader may throw is {@link CborException}; anything else
 * (a runtime exception, an {@link Error}) fails the run. Whatever it accepts must be the
 * deterministic encoding of the value it returns.
 *
 * <p>Without {@code JAZZER_FUZZ=1} the harness replays the seed corpus in
 * {@code CborReaderFuzzTestInputs} as a regression test.
 */
class CborReaderFuzzTest {
    @FuzzTest
    void fuzz(byte[] in) {
        try {
            CborValue decoded = CborReader.decode(in, CborLimits.HEADER);
            assertArrayEquals(in, CborWriter.encode(decoded, CborLimits.HEADER));
        } catch (CborException expected) {
            // Rejecting input is the expected outcome for almost every mutation.
        }
    }

    /** Each seed is writer output: it decodes to the value its file name says and encodes back unchanged. */
    @Test
    void seedCorpusIsWriterOutput() throws IOException, CborException {
        Map<String, CborValue> seeds = Map.of(
                "uint-1.cbor", new CborValue.UInt(1),
                "bool-true.cbor", new CborValue.Bool(true),
                "text-hello.cbor", new CborValue.Text("hello"),
                "array-1-2.cbor", new CborValue.Array(List.of(new CborValue.UInt(1), new CborValue.UInt(2))),
                "map-a-1.cbor", new CborValue.MapV(Map.of("a", new CborValue.UInt(1))));
        for (Map.Entry<String, CborValue> seed : seeds.entrySet()) {
            byte[] bytes = Seeds.read(CborReaderFuzzTest.class, seed.getKey());
            assertEquals(seed.getValue(), CborReader.decode(bytes, CborLimits.HEADER), seed.getKey());
            assertArrayEquals(bytes, CborWriter.encode(seed.getValue()), seed.getKey());
        }
    }
}
