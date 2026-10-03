package pm.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.vault.record.LoginRecord;
import pm.vault.record.ProjectRecord;
import pm.vault.record.RecordCodec;
import pm.vault.record.RecordException;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/**
 * Fuzz harness for the payload decoder (SR-021, T-FUZZ-VAULT). The only exception it may throw is
 * {@link RecordException}; anything else fails the run. Whatever it accepts must survive a
 * re-encode and a second decode unchanged, so a payload the vault reads is one it can write.
 *
 * <p>Without {@code JAZZER_FUZZ=1} the harness replays the seed corpus in
 * {@code RecordCodecFuzzTestInputs} (one writer-produced payload per record type) as a regression
 * test.
 */
class RecordCodecFuzzTest {
    @FuzzTest
    void fuzz(byte[] in) {
        try (SecretBytes plaintext = SecretBytes.copyOf(in)) {
            List<VaultRecord> decoded = RecordCodec.decodePayload(plaintext);
            try (SecretBytes again = RecordCodec.encodePayload(decoded)) {
                List<VaultRecord> second = RecordCodec.decodePayload(again);
                assertEquals(decoded, second);
                second.forEach(VaultRecord::close);
            }
            decoded.forEach(VaultRecord::close);
        } catch (RecordException expected) {
            // Rejecting input is the expected outcome for almost every mutation.
        }
    }

    /** Each seed is writer output holding exactly one record of the type its file name says. */
    @Test
    void seedCorpusHoldsOneRecordOfEachType() throws IOException, RecordException {
        Map<String, Class<? extends VaultRecord>> seeds = Map.of(
                "login.cbor", LoginRecord.class,
                "wifi.cbor", WifiRecord.class,
                "ssh-key.cbor", SshKeyRecord.class,
                "project.cbor", ProjectRecord.class);
        for (Map.Entry<String, Class<? extends VaultRecord>> seed : seeds.entrySet()) {
            byte[] bytes = Seeds.read(RecordCodecFuzzTest.class, seed.getKey());
            try (SecretBytes plaintext = SecretBytes.copyOf(bytes)) {
                List<VaultRecord> decoded = RecordCodec.decodePayload(plaintext);
                assertEquals(List.of(seed.getValue()), decoded.stream().map(Object::getClass).toList(), seed.getKey());
                try (SecretBytes again = RecordCodec.encodePayload(decoded)) {
                    assertEquals(plaintext, again, seed.getKey());
                }
                decoded.forEach(VaultRecord::close);
            }
        }
    }

    @Test
    void emptySeedHoldsNoRecords() throws IOException, RecordException {
        try (SecretBytes plaintext = SecretBytes.copyOf(Seeds.read(RecordCodecFuzzTest.class, "empty.cbor"))) {
            assertEquals(List.of(), RecordCodec.decodePayload(plaintext));
        }
    }

    @Test
    void rejectsAPayloadWithoutTheRequiredKeys() {
        // {"a": 0}: valid CBOR, wrong schema.
        byte[] wrongSchema = {(byte) 0xA1, 0x61, 0x61, 0x00};
        try (SecretBytes plaintext = SecretBytes.copyOf(wrongSchema)) {
            RecordException e = assertThrows(RecordException.class, () -> RecordCodec.decodePayload(plaintext));
            assertEquals(RecordException.Code.SCHEMA, e.code());
        }
    }
}
