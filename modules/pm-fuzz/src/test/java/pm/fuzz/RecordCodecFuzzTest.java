package pm.fuzz;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import com.code_intelligence.jazzer.junit.FuzzTest;

import pm.crypto.SecretBytes;
import pm.vault.record.RecordCodec;
import pm.vault.record.RecordException;

class RecordCodecFuzzTest {
    @FuzzTest
    void fuzz(byte[] in) {
        try {
            RecordCodec.decodePayload(SecretBytes.copyOf(in));
        } catch (RecordException expected) {
            // Accept any malformed payload; the implementation must reject it without partial returns.
        }
    }

    @Test
    void rejectsMalformedSeedCorpus() {
        byte[] malformed = new byte[] {(byte) 0xA1, 0x61, 0x61, 0x00};
        assertThrows(RecordException.class, () -> RecordCodec.decodePayload(SecretBytes.copyOf(malformed)));
    }
}
