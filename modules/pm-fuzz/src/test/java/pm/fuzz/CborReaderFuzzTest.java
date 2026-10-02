package pm.fuzz;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;

import com.code_intelligence.jazzer.junit.FuzzTest;

import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;

class CborReaderFuzzTest {
    @FuzzTest
    void fuzz(byte[] in) {
        try {
            CborReader.decode(in, CborLimits.HEADER);
        } catch (CborException expected) {
            // Accept any malformed input; the implementation must reject it without crashing.
        }
    }

    @Test
    void acceptsKnownSeedCorpus() {
        assertDoesNotThrow(() -> {
            CborReader.decode(new byte[] {0x01}, CborLimits.HEADER);
            CborReader.decode(new byte[] {(byte) 0x82, 0x01, 0x02}, CborLimits.HEADER);
            CborReader.decode(new byte[] {(byte) 0xA1, 0x61, 0x61, 0x01}, CborLimits.HEADER);
            CborReader.decode(new byte[] {(byte) 0x65, 'h', 'e', 'l', 'l', 'o'}, CborLimits.HEADER);
            CborReader.decode(new byte[] {(byte) 0xF5}, CborLimits.HEADER);
        });
    }
}
