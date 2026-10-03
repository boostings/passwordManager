package pm.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.Map;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import pm.crypto.Argon2Params;
import pm.crypto.Hash;
import pm.crypto.SecretChars;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.record.VaultRecord;

/**
 * Golden fixtures (ADR 0015, T-MIG-01): every format version the production build reads has a
 * committed vault file, and the current code opens each one, forever. See {@link Formats} for the
 * throwaway passphrase and the fixture content.
 */
@Tag("T-MIG-01")
final class GoldenFixtureTest {

    /**
     * SHA-256 of each committed fixture. A fixture is written once and never regenerated; if this
     * fails, a fixture file was changed, which would silently drop the test of the real old bytes.
     */
    private static final Map<Integer, String> PINNED = Map.of(
            1, "9752b685383fb468a5bbaa413b5d7f902acca211cde30134c6dfec7dc79e08cd");

    @TempDir
    Path dir;

    static IntStream productionVersions() {
        return IntStream.rangeClosed(MigrationRegistry.PRODUCTION.oldestReadable(), EnvelopeCodec.VERSION);
    }

    @Test
    void everyVersionTheBuildReadsHasAPinnedFixture() {
        assertEquals(PINNED.keySet(), productionVersions().boxed().collect(java.util.stream.Collectors.toSet()));
        productionVersions().forEach(v ->
                assertEquals(PINNED.get(v), HexFormat.of().formatHex(Hash.sha256(Formats.golden(v))), "v" + v));
    }

    @ParameterizedTest
    @MethodSource("productionVersions")
    void currentCodeOpensTheGoldenFixture(int version) throws IOException, StorageException, VaultException {
        Path vaultPath = dir.resolve("vault.pmv");
        Formats.install(vaultPath, Formats.golden(version));
        assertEquals(version, EnvelopeCodec.peekVersion(Formats.golden(version)));
        try (VaultFileStore store = VaultFileStore.open(vaultPath)) {
            VaultService service = new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR);
            assertEquals(version, service.fileFormatVersion());
            assertGoldenContent(service);
            assertEquals(EnvelopeCodec.VERSION, service.fileFormatVersion());
        }
    }

    @Test
    void generatorWritesAFixtureTheCurrentCodeOpens() throws StorageException, VaultException {
        Path vaultPath = dir.resolve("generated.pmv");
        writeGolden(vaultPath);
        try (VaultFileStore store = VaultFileStore.open(vaultPath)) {
            assertGoldenContent(new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR));
        }
    }

    /**
     * Writes a golden fixture with the current code: a new vault with {@link Formats#GOLDEN_PHRASE}
     * holding {@link Formats#goldenRecords()}. This is how {@code golden/v1.bin} was made; a future
     * format adds its own fixture the same way and pins its hash above.
     */
    static void writeGolden(Path vaultPath) throws StorageException, VaultException {
        try (VaultFileStore store = VaultFileStore.open(vaultPath);
             SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE);
             CreatedVault created = new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR).create(pw)) {
            Formats.goldenRecords().forEach(created.vault()::put);
            created.vault().save();
        }
    }

    static void assertGoldenContent(VaultService service) throws VaultException {
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE);
             Vault vault = service.unlockWithPassphrase(pw)) {
            var expected = Formats.goldenRecords();
            try {
                assertEquals(expected, vault.records());
            } finally {
                expected.forEach(VaultRecord::close);
            }
        }
    }
}
