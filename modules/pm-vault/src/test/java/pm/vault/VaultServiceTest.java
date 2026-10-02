package pm.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.Argon2Params;
import pm.crypto.CryptoException;
import pm.crypto.RecoveryKey;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.envelope.EnvelopeHeader;
import pm.vault.envelope.KdfHeader;
import pm.vault.envelope.SlotHeader;
import pm.vault.record.LoginRecord;
import pm.vault.record.RecordException;
import pm.vault.record.VaultRecord;

/**
 * Create, unlock (passphrase and recovery key), lock and save (M1.2 C 2b). Uses
 * {@link Argon2Params#FLOOR} so each unlock costs one floor-level Argon2 run.
 */
final class VaultServiceTest {

    @TempDir
    Path dir;

    private Path vaultPath;
    private VaultFileStore store;
    private VaultService service;

    @BeforeEach
    void open() throws StorageException {
        vaultPath = dir.resolve("vault.pmv");
        store = VaultFileStore.open(vaultPath);
        service = new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR);
    }

    @AfterEach
    void closeStore() {
        store.close();
    }

    @Test
    void createThenUnlockWithPassphraseThenWithRecoveryKey() throws VaultException {
        char[] recovery;
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw)) {
            assertFalse(created.vault().isLocked());
            assertTrue(created.vault().records().isEmpty());
            recovery = recoveryChars(created);
        }
        assertTrue(Files.exists(vaultPath));

        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault v = service.unlockWithPassphrase(pw)) {
            assertFalse(v.isLocked());
            assertEquals(1L, v.header().saveSeq());
        }
        try (SecretChars rk = SecretChars.takeOwnership(recovery);
             Vault v = service.unlockWithRecoveryKey(rk)) {
            assertFalse(v.isLocked());
        }
    }

    @Test
    void recoveryKeyIsFormattedAsEightGroupsOfSeven() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw)) {
            assertEquals(8 * 7 + 7, rkLength(created));
        }
    }

    @Test
    void newVaultHeaderHasBothSlotsAndCreationTime() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw)) {
            EnvelopeHeader h = created.vault().header();
            assertEquals(Fixtures.T0.getEpochSecond(), h.created());
            assertEquals(Fixtures.T0.getEpochSecond(), h.saved());
            assertEquals(2, h.slots().size());
            assertEquals(SlotHeader.MASTER, h.slots().get(0).type());
            assertEquals(SlotHeader.RECOVERY, h.slots().get(1).type());
            assertEquals(Argon2Params.FLOOR.memoryKiB(), h.kdf().m());
        }
    }

    @Test
    void createRefusesWhenVaultExists() throws VaultException {
        createAndClose();
        try (SecretChars pw = Fixtures.chars("another")) {
            VaultException e = assertThrows(VaultException.class, () -> service.create(pw));
            assertEquals(VaultException.Code.ALREADY_EXISTS, e.code());
        }
    }

    @Test
    void wrongPassphraseIsWrongCredential() throws VaultException {
        createAndClose();
        try (SecretChars wrong = Fixtures.chars("correct horse battery stapler")) {
            VaultException e = assertThrows(VaultException.class, () -> unlock(wrong));
            assertEquals(VaultException.Code.WRONG_CREDENTIAL, e.code());
            assertEquals("WRONG_CREDENTIAL", e.getMessage());
        }
    }

    @Test
    void mistypedRecoveryKeyIsBadInputFromParse() throws VaultException {
        char[] typed;
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw)) {
            typed = recoveryChars(created);
        }
        typed[0] = typed[0] == 'A' ? 'B' : 'A';
        try (SecretChars rk = SecretChars.takeOwnership(typed)) {
            VaultException e = assertThrows(VaultException.class, () -> recover(rk));
            assertEquals(VaultException.Code.WRONG_CREDENTIAL, e.code());
            CryptoException cause = assertInstanceOf(CryptoException.class, e.getCause());
            assertEquals(CryptoException.Code.BAD_INPUT, cause.code());
        }
    }

    @Test
    void validButDifferentRecoveryKeyIsWrongCredential() throws VaultException {
        createAndClose();
        try (SecretBytes other = RecoveryKey.generate();
             SecretChars rk = RecoveryKey.format(other)) {
            VaultException e = assertThrows(VaultException.class, () -> recover(rk));
            assertEquals(VaultException.Code.WRONG_CREDENTIAL, e.code());
            CryptoException cause = assertInstanceOf(CryptoException.class, e.getCause());
            assertEquals(CryptoException.Code.AUTH_FAILED, cause.code());
        }
    }

    @Test
    void recoveryKeyIsCaseSpaceAndDashTolerant() throws VaultException {
        char[] typed;
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw)) {
            typed = recoveryChars(created);
        }
        for (int i = 0; i < typed.length; i++) {
            typed[i] = typed[i] == '-' ? ' ' : Character.toLowerCase(typed[i]);
        }
        try (SecretChars rk = SecretChars.takeOwnership(typed);
             Vault v = service.unlockWithRecoveryKey(rk)) {
            assertFalse(v.isLocked());
        }
    }

    @Test
    void saveSeqIncreasesOnEverySave() throws VaultException {
        createAndClose();
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault v = service.unlockWithPassphrase(pw)) {
            assertEquals(1L, v.header().saveSeq());
            v.save();
            assertEquals(2L, v.header().saveSeq());
            v.save();
            assertEquals(3L, v.header().saveSeq());
        }
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault v = service.unlockWithPassphrase(pw)) {
            assertEquals(3L, v.header().saveSeq());
        }
    }

    @Test
    void saveUsesFreshDataSaltAndClockTime() throws VaultException, StorageException {
        createAndClose();
        byte[] first = store.readAll();
        Clock later = Clock.fixed(Instant.parse("2026-10-03T08:00:00Z"), ZoneOffset.UTC);
        VaultService laterService = new VaultService(store, later, Argon2Params.FLOOR);
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault v = laterService.unlockWithPassphrase(pw)) {
            v.save();
            assertEquals(later.instant().getEpochSecond(), v.header().saved());
            assertEquals(Fixtures.T0.getEpochSecond(), v.header().created());
        }
        byte[] firstSalt = EnvelopeCodec.decode(first).dataSalt();
        byte[] secondSalt = EnvelopeCodec.decode(store.readAll()).dataSalt();
        assertNotEquals(HexFormat.of().formatHex(firstSalt), HexFormat.of().formatHex(secondSalt),
                "data_salt must be fresh per save (T-ENC-01)");
    }

    @Test
    void closeLocksAndIsIdempotent() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw)) {
            created.vault().close();
            created.vault().close();
            assertTrue(created.vault().isLocked());
            VaultException e = assertThrows(VaultException.class, () -> created.vault().save());
            assertEquals(VaultException.Code.LOCKED, e.code());
            assertThrows(IllegalStateException.class, () -> created.vault().records());
            assertThrows(IllegalStateException.class, () -> created.vault().search("x"));
            assertThrows(IllegalStateException.class, () -> created.vault().remove(new UUID(0L, 0L)));
            assertThrows(IllegalStateException.class,
                    () -> created.vault().put(Fixtures.login("a", "b", "c")));
        }
    }

    @Test
    void closingCreatedVaultZeroesTheRecoveryKey() throws VaultException {
        CreatedVault[] closed = new CreatedVault[1];
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw)) {
            assertFalse(created.vault().isLocked());
            closed[0] = created;
        }
        assertTrue(rkWiped(closed[0]));
        assertTrue(closed[0].vault().isLocked());
    }

    @Test
    void missingFileIsStorageError() {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE)) {
            VaultException e = assertThrows(VaultException.class, () -> unlock(pw));
            assertEquals(VaultException.Code.STORAGE, e.code());
            assertInstanceOf(StorageException.class, e.getCause());
        }
    }

    @Test
    void garbageFileIsCorrupt() throws VaultException, StorageException {
        store.writeAtomically(new byte[] {1, 2, 3});
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE)) {
            VaultException e = assertThrows(VaultException.class, () -> unlock(pw));
            assertEquals(VaultException.Code.CORRUPT, e.code());
        }
    }

    @Test
    void recoveryUnlockOfVaultWithoutRecoverySlotIsWrongCredential() throws VaultException {
        Argon2Params f = Argon2Params.FLOOR;
        EnvelopeHeader masterOnly = new EnvelopeHeader(
                new KdfHeader(EnvelopeCodec.KDF_ALG, f.memoryKiB(), f.iterations(), f.parallelism(),
                        new byte[EnvelopeCodec.SALT_LENGTH]),
                List.of(new SlotHeader(new UUID(1L, 1L), SlotHeader.MASTER,
                        new byte[EnvelopeCodec.WRAPPED_KEY_LENGTH])),
                1L, 1L, 0L);
        try (SecretBytes vk = SecretBytes.copyOf(new byte[Vault.KEY_LENGTH]);
             Vault v = new Vault(store, Fixtures.CLOCK, PayloadCodec.RECORDS, masterOnly, vk, List.of())) {
            v.save();
        }
        try (SecretBytes other = RecoveryKey.generate();
             SecretChars rk = RecoveryKey.format(other)) {
            VaultException e = assertThrows(VaultException.class, () -> recover(rk));
            assertEquals(VaultException.Code.WRONG_CREDENTIAL, e.code());
        }
    }

    @Test
    void duplicateIdsInAuthenticatedPayloadAreCorruptAndClosed() throws VaultException {
        createAndClose();
        try (LoginRecord a = Fixtures.login("dup", "x", "one");
             LoginRecord b = Fixtures.login("dup", "y", "two");
             SecretChars pw = Fixtures.chars(Fixtures.PHRASE)) {
            VaultService dup = new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR,
                    new FixedDecode(List.of(a, b)));
            VaultException e = assertThrows(VaultException.class, () -> unlockVia(dup, pw));
            assertEquals(VaultException.Code.CORRUPT, e.code());
            assertTrue(Fixtures.pwOf(a).isClosed());
            assertTrue(Fixtures.pwOf(b).isClosed());
        }
    }

    @Test
    void createLeavesNoFileWhenTheFirstSaveFails() {
        VaultService failing = new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR, new FailingEncode());
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE)) {
            assertThrows(IllegalStateException.class, () -> createVia(failing, pw));
        }
        assertFalse(store.exists());
    }

    @Test
    void rejectsParallelismTheHeaderCannotStore() {
        Argon2Params tooWide = new Argon2Params(Argon2Params.FLOOR.memoryKiB(), Argon2Params.FLOOR.iterations(),
                EnvelopeCodec.MAX_PARALLELISM + 1);
        assertThrows(IllegalArgumentException.class, () -> new VaultService(store, Fixtures.CLOCK, tooWide));
    }

    @Test
    void exceptionMessagesAreCodesOnly() {
        for (VaultException.Code c : VaultException.Code.values()) {
            assertEquals(c.name(), new VaultException(c, new IllegalStateException("/home/user/vault.pmv")).getMessage());
        }
    }

    private Vault unlock(SecretChars pw) throws VaultException {
        return service.unlockWithPassphrase(pw);
    }

    private Vault recover(SecretChars typed) throws VaultException {
        return service.unlockWithRecoveryKey(typed);
    }

    private static Vault unlockVia(VaultService s, SecretChars pw) throws VaultException {
        return s.unlockWithPassphrase(pw);
    }

    private static CreatedVault createVia(VaultService s, SecretChars pw) throws VaultException {
        return s.create(pw);
    }

    /** True if the recovery key chars are all zero, or access is refused because it is closed. */
    private static boolean rkWiped(CreatedVault created) {
        try {
            boolean[] zero = {true};
            created.recoveryKey().withChars(c -> {
                for (char ch : c) {
                    zero[0] &= ch == '\0';
                }
            });
            return zero[0];
        } catch (IllegalStateException closedAlready) {
            return true;
        }
    }

    /** Decodes every payload to a fixed list. */
    private static final class FixedDecode implements PayloadCodec {
        private final List<VaultRecord> result;

        FixedDecode(List<VaultRecord> result) {
            this.result = List.copyOf(result);
        }

        @Override
        public SecretBytes encode(List<VaultRecord> records) {
            return PayloadCodec.RECORDS.encode(records);
        }

        @Override
        public List<VaultRecord> decode(SecretBytes plaintext) {
            return result;
        }
    }

    /** Fails every encode, so the first save inside create() fails. */
    private static final class FailingEncode implements PayloadCodec {
        @Override
        public SecretBytes encode(List<VaultRecord> records) {
            throw new IllegalStateException("encode");
        }

        @Override
        public List<VaultRecord> decode(SecretBytes plaintext) throws RecordException {
            return PayloadCodec.RECORDS.decode(plaintext);
        }
    }

    private static int rkLength(CreatedVault created) {
        return created.recoveryKey().length();
    }

    /** Copies the recovery key out so a test can retype or mangle it. */
    private static char[] recoveryChars(CreatedVault created) {
        char[] out = new char[created.recoveryKey().length()];
        created.recoveryKey().withChars(c -> System.arraycopy(c, 0, out, 0, c.length));
        return out;
    }

    private void createAndClose() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw)) {
            assertFalse(created.vault().isLocked());
        }
    }
}
