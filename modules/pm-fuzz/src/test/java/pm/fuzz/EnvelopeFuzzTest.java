package pm.fuzz;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import pm.crypto.Argon2Params;
import pm.vault.VaultException;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.envelope.EnvelopeHeader;
import pm.vault.envelope.KdfHeader;
import pm.vault.envelope.ParsedEnvelope;
import pm.vault.envelope.SlotHeader;

/**
 * Fuzz harness for the vault file parser (sprint plan section 6 D, SR-021, T-FUZZ-VAULT).
 * {@link EnvelopeCodec#decode} reads a file before anything in it is authenticated, so the only
 * exception it may throw is {@link VaultException}; anything else fails the run.
 *
 * <p>Without {@code JAZZER_FUZZ=1} the harness replays the seed corpus in
 * {@code EnvelopeFuzzTestInputs} as a regression test.
 */
class EnvelopeFuzzTest {
    private static final int TAG_LENGTH = 16;

    @FuzzTest
    void fuzz(byte[] in) {
        try {
            ParsedEnvelope parsed = EnvelopeCodec.decode(in);
            // The authenticated prefix and the ciphertext must partition the file exactly.
            assertEquals(in.length, parsed.aad().length + parsed.ciphertext().length);
        } catch (VaultException expected) {
            // Rejecting input is the expected outcome for almost every mutation.
        }
    }

    /** Keeps the harness honest: a file the codec writes is one the fuzz target accepts. */
    @Test
    void aFileTheCodecWritesIsAccepted() throws VaultException {
        byte[] file = EnvelopeCodec.encode(header(), filled(EnvelopeCodec.SALT_LENGTH, 0x44), filled(TAG_LENGTH, 0x55));

        ParsedEnvelope parsed = EnvelopeCodec.decode(file);

        assertEquals(header(), parsed.header());
        assertArrayEquals(filled(TAG_LENGTH, 0x55), parsed.ciphertext());
    }

    /**
     * Each seed is codec output (generated once with {@link EnvelopeCodec#encode}) and still parses
     * to the slot count and ciphertext length its file name implies.
     */
    @Test
    void seedCorpusIsAccepted() throws IOException, VaultException {
        Map<String, List<Integer>> seeds = Map.of(
                "valid-envelope.bin", List.of(2, 42),
                "passphrase-only.bin", List.of(1, 64),
                "max-kdf-recovery-first.bin", List.of(2, TAG_LENGTH),
                "large-ciphertext.bin", List.of(2, 1024));
        for (Map.Entry<String, List<Integer>> seed : seeds.entrySet()) {
            byte[] file = Seeds.read(EnvelopeFuzzTest.class, seed.getKey());
            ParsedEnvelope parsed = EnvelopeCodec.decode(file);
            assertEquals(seed.getValue(), List.of(parsed.header().slots().size(), parsed.ciphertext().length),
                    seed.getKey());
            assertArrayEquals(file, EnvelopeCodec.encode(parsed.header(), parsed.dataSalt(), parsed.ciphertext()),
                    seed.getKey());
        }
    }

    @Test
    void anEmptyFileIsRejectedAsCorrupt() {
        VaultException e = assertThrows(VaultException.class, () -> EnvelopeCodec.decode(new byte[0]));
        assertEquals(VaultException.Code.CORRUPT, e.code());
    }

    private static EnvelopeHeader header() {
        Argon2Params floor = Argon2Params.FLOOR;
        KdfHeader kdf = new KdfHeader(EnvelopeCodec.KDF_ALG, floor.memoryKiB(), floor.iterations(),
                floor.parallelism(), filled(EnvelopeCodec.SALT_LENGTH, 0x11));
        List<SlotHeader> slots = List.of(
                new SlotHeader(new UUID(5L, 5L), SlotHeader.MASTER, filled(EnvelopeCodec.WRAPPED_KEY_LENGTH, 0x22)),
                new SlotHeader(new UUID(6L, 6L), SlotHeader.RECOVERY, filled(EnvelopeCodec.WRAPPED_KEY_LENGTH, 0x33)));
        return new EnvelopeHeader(kdf, slots, 1L, 2L, 1L);
    }

    private static byte[] filled(int length, int value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }
}
