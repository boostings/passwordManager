package pm.vault;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import pm.crypto.Aead;
import pm.crypto.Argon2Params;
import pm.crypto.CryptoException;
import pm.crypto.Csprng;
import pm.crypto.KeyWrap;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.storage.OwnerOnly;
import pm.storage.StorageException;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.envelope.EnvelopeHeader;
import pm.vault.envelope.KdfHeader;
import pm.vault.envelope.SlotHeader;
import pm.vault.record.LoginRecord;
import pm.vault.record.ProjectRecord;
import pm.vault.record.RecordCodec;
import pm.vault.record.RecordException;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;
import pm.vault.slot.SlotCrypto;

/**
 * Format fixtures for the migration and backup tests (ADR 0015).
 *
 * <p><b>Golden fixtures.</b> {@code src/test/resources/pm/vault/golden/v<N>.bin} holds one vault
 * file for every format version this build reads in production. Each was written once by the code
 * of its time with {@link #GOLDEN_PHRASE}, a documented throwaway passphrase that protects nothing
 * else, and holds exactly {@link #goldenRecords()}. The files are never regenerated: their SHA-256
 * is pinned in {@code GoldenFixtureTest}. The extension is {@code .bin}, not {@code .pmv}, because
 * these are deliberate fixtures rather than an accidentally committed vault, which is what the
 * gitleaks {@code pm-vault-file} rule looks for.
 *
 * <p><b>Synthetic format 0.</b> No format 0 was ever released. To exercise the framework, tests
 * define one: the version-1 envelope with prefix version 0 and a payload that is the bare CBOR
 * record array, without the {@code {schema_version, records}} map. {@link V0ToV1} is its migration.
 */
final class Formats {

    /** Throwaway passphrase of every golden fixture. Documented in ADR 0015; protects nothing. */
    static final String GOLDEN_PHRASE = "golden fixture throwaway phrase";

    /** Registry with the synthetic 0 to 1 step. */
    static final MigrationRegistry WITH_V0 = new MigrationRegistry(List.of(new V0ToV1()));

    private static final Instant T = Instant.parse("2026-10-03T00:00:00Z");
    private static final String K_SCHEMA_VERSION = "schema_version";
    private static final String K_RECORDS = "records";

    private Formats() {
    }

    /** The exact content of every golden fixture: one record of each type, fixed ids and times. */
    static List<VaultRecord> goldenRecords() {
        return List.of(
                new LoginRecord(UUID.fromString("0a0a0a0a-0000-4000-8000-000000000001"), "Golden login", "alice",
                        secret("golden-login-value"), List.of("https://golden.example"), "note",
                        List.of("golden"), T, T, T),
                new WifiRecord(UUID.fromString("0a0a0a0a-0000-4000-8000-000000000002"), "Golden wifi", "GoldenNet",
                        "WPA3", secret("golden-wifi-value"), false, "", T, T),
                new SshKeyRecord(UUID.fromString("0a0a0a0a-0000-4000-8000-000000000003"), "Golden ssh", "ed25519",
                        secret("golden-ssh-value"), "ssh-ed25519 GOLDEN", "SHA256:golden", "comment",
                        List.of("golden.example"), T, T),
                new ProjectRecord(UUID.fromString("0a0a0a0a-0000-4000-8000-000000000004"), "Golden project",
                        "/home/alice/golden", "git@golden.example:alice/golden.git",
                        Map.of("dev/GOLDEN_VAR", secret("golden-env-value")), Map.of("profile", "dev"), T, T));
    }

    static SecretBytes secret(String text) {
        return SecretBytes.copyOf(text.getBytes(StandardCharsets.UTF_8));
    }

    /** Reads a golden fixture from the test resources. */
    static byte[] golden(int version) {
        try (InputStream in = Formats.class.getResourceAsStream("golden/v" + version + ".bin")) {
            if (in == null) {
                throw new IllegalStateException("missing golden fixture v" + version);
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Writes {@code bytes} as an owner-only file, as the store requires of a vault. */
    static void install(Path file, byte[] bytes) throws IOException, StorageException {
        Files.write(file, bytes);
        OwnerOnly.apply(file);
    }

    /**
     * Builds a synthetic format-0 file holding {@code records}, with a passphrase slot for
     * {@code phrase} and, if {@code rk} is not null, a recovery slot.
     */
    static byte[] v0File(String phrase, SecretBytes rk, List<VaultRecord> records) throws CryptoException {
        Argon2Params p = Argon2Params.FLOOR;
        KdfHeader kdf = new KdfHeader(EnvelopeCodec.KDF_ALG, p.memoryKiB(), p.iterations(), p.parallelism(),
                Csprng.bytes(EnvelopeCodec.SALT_LENGTH));
        UUID master = Csprng.uuid();
        UUID recovery = Csprng.uuid();
        byte[] dataSalt = Csprng.bytes(EnvelopeCodec.SALT_LENGTH);
        try (SecretBytes vk = Csprng.secretBytes(Vault.KEY_LENGTH);
             SecretChars pw = Fixtures.chars(phrase);
             SecretBytes kekP = SlotCrypto.kekFromPassphrase(pw, kdf, master);
             SecretBytes v1 = RecordCodec.encodePayload(records);
             SecretBytes v0 = toV0(v1);
             SecretBytes dk = Vault.dataKey(vk, dataSalt)) {
            List<SlotHeader> slots = rk == null
                    ? List.of(new SlotHeader(master, SlotHeader.MASTER, KeyWrap.wrap(kekP, vk)))
                    : List.of(new SlotHeader(master, SlotHeader.MASTER, KeyWrap.wrap(kekP, vk)),
                            recoverySlot(rk, recovery, vk));
            EnvelopeHeader header = new EnvelopeHeader(kdf, slots, T.getEpochSecond(), T.getEpochSecond(), 1L);
            byte[] aad = EnvelopeCodec.aadOf(0, EnvelopeCodec.encodeHeader(header), dataSalt);
            byte[] ciphertext = Aead.sealWithFreshKey(dk, v0, aad);
            byte[] file = Arrays.copyOf(aad, aad.length + ciphertext.length);
            System.arraycopy(ciphertext, 0, file, aad.length, ciphertext.length);
            return file;
        }
    }

    private static SlotHeader recoverySlot(SecretBytes rk, UUID id, SecretBytes vk) throws CryptoException {
        try (SecretBytes kekR = SlotCrypto.kekFromRecovery(rk, id)) {
            return new SlotHeader(id, SlotHeader.RECOVERY, KeyWrap.wrap(kekR, vk));
        }
    }

    /** Format 1 payload to synthetic format 0: unwraps the record array. */
    private static SecretBytes toV0(SecretBytes v1) {
        return v1.apply(bytes -> {
            CborValue root = decode(bytes);
            try {
                CborValue records = ((CborValue.MapV) root).entries().get(K_RECORDS);
                return SecretBytes.takeOwnership(CborWriter.encode(records, CborLimits.PAYLOAD));
            } finally {
                root.wipe();
            }
        });
    }

    private static CborValue decode(byte[] bytes) {
        try {
            return CborReader.decode(bytes, CborLimits.PAYLOAD);
        } catch (CborException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The synthetic step: wraps the bare record array of format 0 in the format 1 map. */
    static final class V0ToV1 implements Migration {
        @Override
        public int fromVersion() {
            return 0;
        }

        @Override
        public SecretBytes apply(SecretBytes payload) throws RecordException {
            // Not CBOR at all reads as null and fails the shape check below.
            CborValue root = payload.apply(bytes -> {
                try {
                    return CborReader.decode(bytes, CborLimits.PAYLOAD);
                } catch (CborException e) {
                    return null;
                }
            });
            if (!(root instanceof CborValue.Array records)) {
                throw new RecordException(RecordException.Code.SCHEMA, "format 0 payload is not an array");
            }
            CborValue wrapped = new CborValue.MapV(Map.of(
                    K_SCHEMA_VERSION, new CborValue.UInt(RecordCodec.SCHEMA_VERSION),
                    K_RECORDS, records));
            try {
                return SecretBytes.takeOwnership(CborWriter.encode(wrapped, CborLimits.PAYLOAD));
            } finally {
                wrapped.wipe();
            }
        }
    }
}
