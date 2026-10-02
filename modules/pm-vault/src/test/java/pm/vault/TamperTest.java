package pm.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.Argon2Params;
import pm.crypto.CryptoException;
import pm.crypto.KeyWrap;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.envelope.ParsedEnvelope;
import pm.vault.envelope.SlotHeader;
import pm.vault.slot.SlotCrypto;

/**
 * M1 exit criterion SR-020 / T-TAMPER-01: any single-byte change to the vault file is
 * detected before any record is deserialized.
 *
 * <p>Part 1 flips every byte and opens at the VK layer
 * ({@link VaultService#openWithVaultKey}), so the suite does not pay one Argon2 run per
 * byte. Part 2 runs 10 evenly spaced flips through the full passphrase unlock. A counting
 * payload codec proves zero record decodes in both parts.
 */
final class TamperTest {

    private static final int SAMPLED_FLIPS = 10;
    private static final Set<VaultException.Code> VK_LAYER_CODES =
            Set.of(VaultException.Code.CORRUPT, VaultException.Code.UNSUPPORTED_VERSION);
    private static final Set<VaultException.Code> FULL_UNLOCK_CODES =
            Set.of(VaultException.Code.CORRUPT, VaultException.Code.UNSUPPORTED_VERSION,
                    VaultException.Code.WRONG_CREDENTIAL);

    @TempDir
    Path dir;

    private VaultFileStore store;
    private Fixtures.CountingCodec codec;
    private VaultService service;
    private byte[] file;

    @BeforeEach
    void buildVaultWithThreeRecords() throws StorageException, VaultException {
        store = VaultFileStore.open(dir.resolve("vault.pmv"));
        codec = new Fixtures.CountingCodec();
        service = new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR, codec);
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw)) {
            created.vault().put(Fixtures.login("mail", "alice", "pw-one"));
            created.vault().put(Fixtures.login("bank", "bob", "pw-two"));
            created.vault().put(Fixtures.login("forge", "carol", "pw-three"));
            created.vault().save();
        }
        file = store.readAll();
    }

    @AfterEach
    void closeStore() {
        store.close();
    }

    @Test
    void untamperedFileOpensAtTheVaultKeyLayer() throws VaultException, CryptoException {
        try (SecretBytes vk = vaultKey();
             Vault v = service.openWithVaultKey(file, vk)) {
            assertEquals(3, v.records().size());
        }
        assertEquals(1, codec.decodes.get(), "the counting hook sees a real decode");
    }

    @Test
    void everySingleByteFlipFailsBeforeAnyRecordIsParsed() throws CryptoException {
        int flips = 0;
        try (SecretBytes vk = vaultKey()) {
            for (int i = 0; i < file.length; i++) {
                byte[] tampered = flip(file, i);
                VaultException e = assertThrows(VaultException.class,
                        () -> openAtVkLayer(tampered, vk), "byte " + i);
                assertTrue(VK_LAYER_CODES.contains(e.code()), "byte " + i + " gave " + e.code());
                flips++;
            }
        }
        assertEquals(file.length, flips);
        assertEquals(0, codec.decodes.get(), "no record decode may run on tampered input");
    }

    @Test
    void sampledFlipsFailThroughFullPassphraseUnlock() throws StorageException {
        for (int k = 0; k < SAMPLED_FLIPS; k++) {
            int index = (int) ((long) k * (file.length - 1) / (SAMPLED_FLIPS - 1));
            store.writeAtomically(flip(file, index));
            try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE)) {
                VaultException e = assertThrows(VaultException.class,
                        () -> unlock(pw), "byte " + index);
                assertTrue(FULL_UNLOCK_CODES.contains(e.code()), "byte " + index + " gave " + e.code());
            }
        }
        assertEquals(0, codec.decodes.get(), "no record decode may run on tampered input");
    }

    private Vault openAtVkLayer(byte[] bytes, SecretBytes vk) throws VaultException {
        return service.openWithVaultKey(bytes, vk);
    }

    private Vault unlock(SecretChars pw) throws VaultException {
        return service.unlockWithPassphrase(pw);
    }

    /** Recovers VK through the public slot API, as unlock does, so part 1 can skip Argon2. */
    private SecretBytes vaultKey() throws CryptoException {
        ParsedEnvelope env;
        try {
            env = EnvelopeCodec.decode(file);
        } catch (VaultException e) {
            throw new IllegalStateException(e);
        }
        SlotHeader slot = env.header().firstSlot(SlotHeader.MASTER);
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             SecretBytes kek = SlotCrypto.kekFromPassphrase(pw, env.header().kdf(), slot.id())) {
            return KeyWrap.unwrap(kek, slot.wrappedKey());
        }
    }

    private static byte[] flip(byte[] src, int index) {
        byte[] out = src.clone();
        out[index] ^= (byte) 0x01;
        return out;
    }
}
