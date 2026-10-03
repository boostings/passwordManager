package pm.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.vault.envelope.EnvelopeCodec;

/** The registry accepts only one contiguous chain ending at the current version (ADR 0015). */
final class MigrationRegistryTest {

    private static Migration step(int from) {
        return new Migration() {
            @Override
            public int fromVersion() {
                return from;
            }

            @Override
            public SecretBytes apply(SecretBytes payload) {
                return SecretBytes.copyOf(new byte[0]);
            }
        };
    }

    @Test
    void productionReadsOnlyTheCurrentVersion() {
        MigrationRegistry p = MigrationRegistry.PRODUCTION;
        assertEquals(EnvelopeCodec.VERSION, p.oldestReadable());
        assertTrue(p.canRead(EnvelopeCodec.VERSION));
        assertFalse(p.canRead(EnvelopeCodec.VERSION - 1));
        assertFalse(p.canRead(EnvelopeCodec.VERSION + 1));
        assertTrue(p.chainFrom(EnvelopeCodec.VERSION).isEmpty());
        assertThrows(IllegalArgumentException.class, () -> p.chainFrom(0));
    }

    @Test
    void chainRunsOldestFirstWhateverTheInputOrder() {
        Migration zero = step(0);
        MigrationRegistry r = new MigrationRegistry(List.of(zero));
        assertEquals(0, r.oldestReadable());
        assertEquals(List.of(zero), r.chainFrom(0));
        assertTrue(r.chainFrom(1).isEmpty());
        assertFalse(r.canRead(-1));
        assertFalse(r.canRead(2));
    }

    @Test
    void gapsDuplicatesAndStepsBeyondTheCurrentVersionAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new MigrationRegistry(List.of(step(1))));
        assertThrows(IllegalArgumentException.class, () -> new MigrationRegistry(List.of(step(0), step(0))));
        assertThrows(IllegalArgumentException.class, () -> new MigrationRegistry(List.of(step(-1))));
        assertThrows(NullPointerException.class, () -> new MigrationRegistry(java.util.Arrays.asList(
                (Migration) null)));
    }
}
