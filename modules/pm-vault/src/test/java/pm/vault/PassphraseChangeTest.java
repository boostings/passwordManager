package pm.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import pm.crypto.Argon2Params;
import pm.crypto.ConstantTime;
import pm.crypto.Hash;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.envelope.EnvelopeHeader;
import pm.vault.envelope.KdfHeader;
import pm.vault.envelope.SlotHeader;
import pm.vault.record.DeviceIdentityRecord;
import pm.vault.record.TrustedDeviceRecord;
import pm.vault.record.VaultRecord;

/**
 * T-KEY-03: changing the master passphrase (ADR 0004 addendum M7.6, SR-130, SR-131), what a failed
 * change reports (SR-152), and stale vaults whose saves would undo it (SR-151). Every file
 * left on disk is checked by unlocking a copy of it with the old passphrase, the new one and the
 * recovery key. The recovery key opening a changed file is also the proof that the vault key did
 * not change: its slot is untouched and still wraps the key the payload was sealed under.
 */
@Tag("T-KEY-03")
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: the race test saves from a second thread while a change is paused
final class PassphraseChangeTest {
    private static final String NEW_PHRASE = "a new passphrase after the change";
    private static final String VAULT = "vault.pmv";
    private static final String BAK_1 = "vault.pmv.bak.1";
    private static final UUID IDENTITY_ID = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID PEER_ID = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final byte[] USER = "user-handle-1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CLIENT_DATA_HASH = Hash.sha256("cd".getBytes(StandardCharsets.UTF_8));

    @TempDir
    Path dir;

    private final AtomicInteger copies = new AtomicInteger();
    private VaultFileStore store;
    private VaultService service;
    private CreatedVault created;
    private Vault vault;
    /** What every unlock of a file written from {@link #vault} must hold. */
    private List<VaultRecord> expected;

    /** The credentials a test tries on a file. */
    private enum Key { OLD, NEW, RECOVERY }

    /** A crash: nothing after the step runs, so what is on disk then is what the user is left with. */
    private static final class SimulatedCrash extends RuntimeException {
        private static final long serialVersionUID = 1L;

        SimulatedCrash() {
            super("SIMULATED_CRASH");
        }
    }

    @BeforeEach
    void createVault() throws StorageException, VaultException {
        store = VaultFileStore.open(dir.resolve(VAULT));
        service = new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR);
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE)) {
            created = service.create(pw);
        }
        vault = created.vault();
        vault.put(Fixtures.login("Bank", "alice", "bank-secret"));
        // The LAN identity and the trust list are payload records: a change saves them as they are.
        vault.put(DeviceIdentityRecord.of(IDENTITY_ID, "laptop", SecretBytes.copyOf(filled(48, 1)),
                filled(40, 3), Fixtures.T0));
        vault.put(TrustedDeviceRecord.of(PEER_ID, "phone", filled(32, 7), Fixtures.T0));
        vault.save();
        expected = vault.records();
    }

    @AfterEach
    void closeVault() throws IOException {
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        created.close();
        store.close();
    }

    // ---- success ---------------------------------------------------------------------------------

    @Test
    void theNewPassphraseAndTheRecoveryKeyOpenTheVaultAndTheOldPassphraseNoLonger()
            throws IOException, StorageException, VaultException {
        EnvelopeHeader before = vault.header();
        byte[] original = read(VAULT);
        // A service tuned differently from the vault: the header's own m, t and p are kept.
        Argon2Params other = new Argon2Params(Argon2Params.FLOOR.memoryKiB(),
                Argon2Params.FLOOR.iterations() + 1, Argon2Params.FLOOR.parallelism());
        try (SecretChars pw = Fixtures.chars(NEW_PHRASE)) {
            new VaultService(store, Fixtures.CLOCK, other).changePassphrase(vault, pw);
            assertFalse(pw.isClosed(), "the caller owns the passphrase");
        }

        EnvelopeHeader after = vault.header();
        assertEquals(before.saveSeq() + 1, after.saveSeq());
        assertEquals(before.created(), after.created());
        KdfHeader was = before.kdf();
        KdfHeader now = after.kdf();
        assertEquals(List.of(was.alg(), was.m(), was.t(), was.p()), List.of(now.alg(), now.m(), now.t(), now.p()));
        assertEquals(EnvelopeCodec.SALT_LENGTH, now.salt().length);
        assertFalse(ConstantTime.equals(was.salt(), now.salt()), "fresh salt");
        assertEquals(List.of(SlotHeader.MASTER, SlotHeader.RECOVERY), after.slots().stream().map(SlotHeader::type).toList());
        SlotHeader oldMaster = before.firstSlot(SlotHeader.MASTER);
        SlotHeader newMaster = after.firstSlot(SlotHeader.MASTER);
        assertEquals(oldMaster.id(), newMaster.id());
        assertFalse(ConstantTime.equals(oldMaster.wrappedKey(), newMaster.wrappedKey()));
        assertEquals(before.firstSlot(SlotHeader.RECOVERY), after.firstSlot(SlotHeader.RECOVERY));

        assertEquals(EnumSet.of(Key.NEW, Key.RECOVERY), keysOpening(read(VAULT)));
        // The save rotated the file as it was into .bak.1: it keeps the old passphrase.
        assertArrayEquals(original, read(BAK_1));
        assertEquals(EnumSet.of(Key.OLD, Key.RECOVERY), keysOpening(original));

        // The vault stays unlocked and its next save keeps the new passphrase.
        vault.put(Fixtures.login("After", "bob", "after-secret"));
        vault.save();
        expected = vault.records();
        assertEquals(before.saveSeq() + 2, vault.header().saveSeq());
        assertEquals(EnumSet.of(Key.NEW, Key.RECOVERY), keysOpening(read(VAULT)));
    }

    @Test
    void aVaultUnlockedWithTheRecoveryKeyCanSetANewPassphrase() throws IOException, StorageException, VaultException {
        vault.close();
        try (Vault recovered = service.unlockWithRecoveryKey(created.recoveryKey());
             SecretChars pw = Fixtures.chars(NEW_PHRASE)) {
            service.changePassphrase(recovered, pw);
            expected = recovered.records();
            assertEquals(3, expected.size());
            assertEquals(EnumSet.of(Key.NEW, Key.RECOVERY), keysOpening(read(VAULT)));
        }
    }

    // ---- refusals before anything is written ------------------------------------------------------

    @Test
    void theNewPassphraseMustPassTheRuleCreateApplies() throws IOException {
        byte[] original = read(VAULT);
        byte[] bak = read(BAK_1);
        EnvelopeHeader before = vault.header();
        try (SecretChars empty = SecretChars.takeOwnership(new char[0]);
             SecretChars lone = SecretChars.takeOwnership(new char[] {'a', '\uD800', 'b'});
             SecretChars closed = Fixtures.chars(NEW_PHRASE)) {
            assertEquals("EMPTY_PASSPHRASE", assertThrows(IllegalArgumentException.class,
                    () -> service.changePassphrase(vault, empty)).getMessage());
            assertEquals("MALFORMED_CHARS", assertThrows(IllegalArgumentException.class,
                    () -> service.changePassphrase(vault, lone)).getMessage());
            closeNow(closed);
            assertEquals("SECRET_CLOSED", assertThrows(IllegalStateException.class,
                    () -> service.changePassphrase(vault, closed)).getMessage());
            assertThrows(NullPointerException.class, () -> service.changePassphrase(vault, null));
            assertThrows(NullPointerException.class, () -> service.changePassphrase(null, lone));
        }
        assertArrayEquals(original, read(VAULT));
        assertArrayEquals(bak, read(BAK_1));
        assertEquals(before, vault.header());
    }

    @Test
    void createAppliesTheSameRule() throws IOException, StorageException {
        Path other = Files.createDirectory(dir.resolve("other"));
        Files.setPosixFilePermissions(other, PosixFilePermissions.fromString("rwx------"));
        try (VaultFileStore otherStore = VaultFileStore.open(other.resolve(VAULT));
             SecretChars empty = SecretChars.takeOwnership(new char[0])) {
            VaultService fresh = new VaultService(otherStore, Fixtures.CLOCK, Argon2Params.FLOOR);
            assertEquals("EMPTY_PASSPHRASE",
                    assertThrows(IllegalArgumentException.class, () -> fresh.create(empty)).getMessage());
            assertThrows(NullPointerException.class, () -> fresh.create(null));
            assertFalse(otherStore.exists());
        }
    }

    @Test
    void aLockedVaultIsRefused() throws IOException {
        byte[] original = read(VAULT);
        vault.close();
        try (SecretChars pw = Fixtures.chars(NEW_PHRASE)) {
            VaultException e = assertThrows(VaultException.class, () -> service.changePassphrase(vault, pw));
            assertEquals(VaultException.Code.LOCKED, e.code());
        }
        assertArrayEquals(original, read(VAULT));
    }

    /** Like save, put, remove and close: refused on the signing thread, the signature completes. */
    @Test
    void insideThePasskeySigningPortTheChangeIsRefused()
            throws IOException, PasskeyException, StorageException, VaultException {
        PasskeyCreated passkey = vault.createPasskey("Example", "example.com", USER, "alice", "");
        AtomicReference<Throwable> refused = new AtomicReference<>();
        AtomicReference<byte[]> beforeAttempt = new AtomicReference<>();
        AtomicReference<byte[]> afterAttempt = new AtomicReference<>();
        try (SecretChars pw = Fixtures.chars(NEW_PHRASE)) {
            vault.signWithPasskey(passkey.id(), CLIENT_DATA_HASH, p -> {
                beforeAttempt.set(readUnchecked(VAULT));
                refused.set(assertThrows(IllegalStateException.class, () -> service.changePassphrase(vault, pw)));
                afterAttempt.set(readUnchecked(VAULT));
                return PasskeyEnrollmentTest.authData(p.rpId(), p.signCount());
            });
        }
        assertEquals("REENTRANT", refused.get().getMessage());
        assertArrayEquals(beforeAttempt.get(), afterAttempt.get());
        assertFalse(vault.isLocked());
        int count = expected.size() + 1;
        assertEquals(EnumSet.of(Key.OLD, Key.RECOVERY),
                keysOpening(read(VAULT), v -> assertEquals(count, v.records().size())));
    }

    @Test
    void aFileThatCannotBeReadIsRefusedBeforeAnythingIsWritten() throws IOException {
        EnvelopeHeader before = vault.header();
        Files.delete(dir.resolve(VAULT));
        try (SecretChars pw = Fixtures.chars(NEW_PHRASE)) {
            VaultException e = assertThrows(VaultException.class, () -> service.changePassphrase(vault, pw));
            assertEquals(VaultException.Code.STORAGE, e.code());
            assertInstanceOf(StorageException.class, e.getCause());
        }
        assertFalse(Files.exists(dir.resolve(VAULT)));
        assertEquals(before, vault.header());
    }

    /** {@code INSUFFICIENT_MEMORY} from the new slot's Argon2id run, or any other rewrap failure. */
    @Test
    void aFailureToBuildTheNewSlotWritesNothing() throws IOException {
        byte[] original = read(VAULT);
        byte[] bak = read(BAK_1);
        VaultException noMemory = new VaultException(VaultException.Code.INSUFFICIENT_MEMORY, null);
        assertSame(noMemory, assertThrows(VaultException.class, () -> vault.changePassphraseSlot((header, vk) -> {
            throw noMemory;
        }, Vault.WriteProbe.NONE)));
        assertArrayEquals(original, read(VAULT));
        assertArrayEquals(bak, read(BAK_1));
        assertThrows(NullPointerException.class, () -> vault.changePassphraseSlot(null, Vault.WriteProbe.NONE));
        assertThrows(NullPointerException.class, () -> vault.changePassphraseSlot((header, vk) -> header, null));
    }

    // ---- crash and failure in the save -------------------------------------------------------------

    /**
     * A crash at each step of the save leaves a vault file that opens with exactly one of the two
     * passphrases, and always with the recovery key. Inside {@code writeAtomically} the vault file
     * changes in one rename, so a crash at a storage step leaves it as at {@code BACKED_UP} (before
     * the rename) or {@code WRITTEN} (after it); T-FS-02 {@code AtomicWriteCrashTest} covers those
     * steps and the stale {@code .tmp} they leave. Without a crash the same failure is rolled back.
     */
    @ParameterizedTest
    @EnumSource(value = Vault.WriteStep.class, names = "PUT_BACK", mode = EnumSource.Mode.EXCLUDE)
    void aCrashAtAnyStepLeavesAFileThatOpensWithExactlyOnePassphraseAndTheRecoveryKey(Vault.WriteStep step)
            throws IOException, StorageException, VaultException {
        byte[] original = read(VAULT);
        byte[] bakBefore = read(BAK_1);
        EnvelopeHeader before = vault.header();
        AtomicReference<byte[]> leftVault = new AtomicReference<>();
        AtomicReference<byte[]> leftBak = new AtomicReference<>();
        Vault.WriteProbe crash = at -> {
            if (at == step) {
                leftVault.set(readUnchecked(VAULT));
                leftBak.set(readUnchecked(BAK_1));
                throw new SimulatedCrash();
            }
        };
        try (SecretChars pw = Fixtures.chars(NEW_PHRASE)) {
            assertThrows(SimulatedCrash.class, () -> service.changePassphrase(vault, pw, crash));
        }

        boolean renamed = step == Vault.WriteStep.WRITTEN;
        assertEquals(renamed ? EnumSet.of(Key.NEW, Key.RECOVERY) : EnumSet.of(Key.OLD, Key.RECOVERY),
                keysOpening(leftVault.get()));
        assertArrayEquals(step == Vault.WriteStep.SEALED ? bakBefore : original, leftBak.get());

        // Without a crash, the failure put the file back byte for byte and the vault is unchanged.
        assertArrayEquals(original, read(VAULT));
        assertEquals(before, vault.header());
        // It stays usable: trying again succeeds.
        try (SecretChars pw = Fixtures.chars(NEW_PHRASE)) {
            service.changePassphrase(vault, pw);
        }
        assertEquals(before.saveSeq() + 1, vault.header().saveSeq());
        assertEquals(EnumSet.of(Key.NEW, Key.RECOVERY), keysOpening(read(VAULT)));
    }

    @Test
    void anyFailureAfterTheRenameWritesTheOldFileBack() throws IOException {
        VaultException checked = new VaultException(VaultException.Code.STORAGE, null);
        IllegalStateException runtime = new IllegalStateException("simulated");
        OutOfMemoryError error = new OutOfMemoryError("simulated");
        assertRolledBack(checked, at -> {
            if (at == Vault.WriteStep.WRITTEN) {
                throw checked;
            }
        });
        assertRolledBack(runtime, at -> {
            if (at == Vault.WriteStep.WRITTEN) {
                throw runtime;
            }
        });
        assertRolledBack(error, at -> {
            if (at == Vault.WriteStep.WRITTEN) {
                throw error;
            }
        });
    }

    /** {@code probe} makes the change fail with {@code failure}; the file and header stay as they were. */
    private void assertRolledBack(Throwable failure, Vault.WriteProbe probe) throws IOException {
        byte[] original = read(VAULT);
        EnvelopeHeader before = vault.header();
        try (SecretChars pw = Fixtures.chars(NEW_PHRASE)) {
            Throwable thrown = assertThrows(Throwable.class, () -> service.changePassphrase(vault, pw, probe));
            assertSame(failure, thrown);
            assertEquals(0, thrown.getSuppressed().length);
        }
        assertArrayEquals(original, read(VAULT));
        assertEquals(before, vault.header());
    }

    // ---- what a failed change reports (SR-152) -----------------------------------------------------

    /**
     * m76-002 (b): the old file cannot be written back, so the new one stays. The change says so
     * with PASSPHRASE_CHANGED_UNCONFIRMED, and the vault takes the header on disk: closing without
     * a save leaves a file the new passphrase opens, and a later save keeps the new passphrase.
     */
    @Test
    void ifTheOldFileCannotBeWrittenBackTheChangeIsReportedAsMadeAndKept()
            throws IOException, StorageException, VaultException {
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
        VaultException failure = new VaultException(VaultException.Code.STORAGE, null);
        VaultException thrown = failChange(at -> {
            if (at == Vault.WriteStep.WRITTEN) {
                setPermissions(dir, "r-x------");
                throw failure;
            }
        });
        setPermissions(dir, "rwx------");
        assertEquals(VaultException.Code.PASSPHRASE_CHANGED_UNCONFIRMED, thrown.code());
        assertSame(failure, thrown.getCause());
        assertEquals(1, failure.getSuppressed().length);
        assertInstanceOf(StorageException.class, failure.getSuppressed()[0]);

        byte[] left = read(VAULT);
        assertEquals(EnumSet.of(Key.NEW, Key.RECOVERY), keysOpening(left));
        assertEquals(EnvelopeCodec.decode(left).header(), vault.header());
        vault.save();
        assertEquals(EnumSet.of(Key.NEW, Key.RECOVERY), keysOpening(read(VAULT)));
    }

    /**
     * m76-002 (c), unreadable: the file cannot be read back, so which passphrase opens it is
     * unknown. The vault keeps its old header; the recovery key opens the file; and the vault's
     * next save, which would put the old slot back over the new file, is refused.
     */
    @Test
    void ifTheFileCannotBeReadBackTheOutcomeIsReportedAsUnknown()
            throws IOException, StorageException, VaultException {
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
        EnvelopeHeader before = vault.header();
        VaultException failure = new VaultException(VaultException.Code.STORAGE, null);
        VaultException thrown = failChange(at -> {
            if (at == Vault.WriteStep.WRITTEN) {
                setPermissions(dir.resolve(VAULT), "---------");
                throw failure;
            }
        });
        setPermissions(dir.resolve(VAULT), "rw-------");
        assertEquals(VaultException.Code.PASSPHRASE_CHANGE_UNKNOWN, thrown.code());
        assertSame(failure, thrown.getCause());
        // The write-back's read and the read-back both failed.
        assertEquals(2, failure.getSuppressed().length);
        assertInstanceOf(StorageException.class, failure.getSuppressed()[0]);
        assertInstanceOf(StorageException.class, failure.getSuppressed()[1]);
        assertEquals(before, vault.header());

        byte[] left = read(VAULT);
        assertEquals(EnumSet.of(Key.NEW, Key.RECOVERY), keysOpening(left));
        VaultException conflict = assertThrows(VaultException.class, vault::save);
        assertEquals(VaultException.Code.CONFLICT, conflict.code());
        assertArrayEquals(left, read(VAULT));
    }

    /**
     * m76-002 (c), neither: the file read back holds neither the old nor the new passphrase slot
     * (here another vault's file, which the write-back could not replace).
     */
    @Test
    void ifTheFileHoldsNeitherSlotTheOutcomeIsReportedAsUnknown()
            throws IOException, StorageException, VaultException {
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
        byte[] foreign = anotherVaultsFile();
        EnvelopeHeader before = vault.header();
        VaultException failure = new VaultException(VaultException.Code.STORAGE, null);
        VaultException thrown = failChange(at -> {
            if (at == Vault.WriteStep.WRITTEN) {
                writeUnchecked(VAULT, foreign);
                setPermissions(dir, "r-x------");
                throw failure;
            }
        });
        setPermissions(dir, "rwx------");
        assertEquals(VaultException.Code.PASSPHRASE_CHANGE_UNKNOWN, thrown.code());
        assertSame(failure, thrown.getCause());
        assertEquals(1, failure.getSuppressed().length);
        assertEquals(before, vault.header());
        assertArrayEquals(foreign, read(VAULT));
    }

    /**
     * m76-003: an Error inside the write-back (here a second OutOfMemoryError) is attached to the
     * failure instead of replacing it, and the read-back still reports the new file in place.
     */
    @Test
    void anErrorWhileWritingBackIsAttachedAndTheOutcomeStillReported()
            throws IOException, StorageException, VaultException {
        OutOfMemoryError afterRename = new OutOfMemoryError("after the rename");
        OutOfMemoryError inPutBack = new OutOfMemoryError("in the write-back");
        VaultException thrown = failChange(at -> {
            if (at == Vault.WriteStep.WRITTEN) {
                throw afterRename;
            }
            if (at == Vault.WriteStep.PUT_BACK) {
                throw inPutBack;
            }
        });
        assertEquals(VaultException.Code.PASSPHRASE_CHANGED_UNCONFIRMED, thrown.code());
        assertSame(afterRename, thrown.getCause());
        assertArrayEquals(new Throwable[] {inPutBack}, afterRename.getSuppressed());
        assertEquals(EnumSet.of(Key.NEW, Key.RECOVERY), keysOpening(read(VAULT)));
    }

    /**
     * The JVM may throw one preallocated OutOfMemoryError twice; attaching it to itself would
     * throw IllegalArgumentException from the failure path.
     */
    @Test
    void theSameErrorTwiceIsNotAttachedToItself() throws IOException, StorageException, VaultException {
        OutOfMemoryError preallocated = new OutOfMemoryError("preallocated");
        VaultException thrown = failChange(at -> {
            if (at == Vault.WriteStep.WRITTEN || at == Vault.WriteStep.PUT_BACK) {
                throw preallocated;
            }
        });
        assertEquals(VaultException.Code.PASSPHRASE_CHANGED_UNCONFIRMED, thrown.code());
        assertSame(preallocated, thrown.getCause());
        assertEquals(0, preallocated.getSuppressed().length);
        assertEquals(EnumSet.of(Key.NEW, Key.RECOVERY), keysOpening(read(VAULT)));
    }

    /** Runs a change to {@link #NEW_PHRASE} that {@code probe} makes fail; returns what it threw. */
    private VaultException failChange(Vault.WriteProbe probe) {
        try (SecretChars pw = Fixtures.chars(NEW_PHRASE)) {
            return assertThrows(VaultException.class, () -> service.changePassphrase(vault, pw, probe));
        }
    }

    /** A valid vault file of a different vault (its own salt and slots). */
    private byte[] anotherVaultsFile() throws IOException, StorageException, VaultException {
        Path otherDir = Files.createDirectory(dir.resolve("other"));
        Files.setPosixFilePermissions(otherDir, PosixFilePermissions.fromString("rwx------"));
        try (VaultFileStore otherStore = VaultFileStore.open(otherDir.resolve(VAULT));
             SecretChars pw = Fixtures.chars(NEW_PHRASE);
             CreatedVault other = new VaultService(otherStore, Fixtures.CLOCK, Argon2Params.FLOOR).create(pw)) {
            assertFalse(other.vault().isLocked());
            return Files.readAllBytes(otherDir.resolve(VAULT));
        }
    }

    // ---- stale writers (SR-151) ---------------------------------------------------------------------

    /**
     * m76-001, the adversary's sequence: a second vault over the same service, unlocked before the
     * change, saves after it. The save is refused and nothing is written, so the file still opens
     * only with the new passphrase. A change from the stale vault is refused the same way.
     */
    @Test
    void aStaleVaultCannotUndoAPassphraseChange() throws IOException, StorageException, VaultException {
        try (Vault stale = unlockWith(service, Fixtures.PHRASE)) {
            try (SecretChars pw = Fixtures.chars(NEW_PHRASE)) {
                service.changePassphrase(vault, pw);
            }
            byte[] changed = read(VAULT);
            byte[] bak = read(BAK_1);

            stale.put(Fixtures.login("FromStale", "b", "s4"));
            VaultException e = assertThrows(VaultException.class, stale::save);
            assertEquals(VaultException.Code.CONFLICT, e.code());
            try (SecretChars other = Fixtures.chars("yet another passphrase")) {
                assertEquals(VaultException.Code.CONFLICT, assertThrows(VaultException.class,
                        () -> service.changePassphrase(stale, other)).code());
            }

            assertArrayEquals(changed, read(VAULT));
            assertArrayEquals(bak, read(BAK_1));
            assertEquals(EnumSet.of(Key.NEW, Key.RECOVERY), keysOpening(changed));
        }
    }

    /** m76-001, a lost update: a stale vault's save cannot overwrite a record another vault saved. */
    @Test
    void aStaleVaultCannotUndoAnotherVaultsSave() throws IOException, StorageException, VaultException {
        try (Vault stale = unlockWith(service, Fixtures.PHRASE)) {
            vault.put(Fixtures.login("FromFirst", "a", "s3"));
            vault.save();
            byte[] saved = read(VAULT);

            stale.put(Fixtures.login("FromStale", "b", "s4"));
            assertEquals(VaultException.Code.CONFLICT, assertThrows(VaultException.class, stale::save).code());
            assertArrayEquals(saved, read(VAULT));
            expected = vault.records();
            assertEquals(EnumSet.of(Key.OLD, Key.RECOVERY), keysOpening(saved));
        }
    }

    /** One vault's own saves, one after another, and a vault unlocked after them, all go through. */
    @Test
    void aVaultSavesAgainAfterItsOwnSaves() throws IOException, StorageException, VaultException {
        long seq = vault.header().saveSeq();
        for (int i = 0; i < 3; i++) {
            vault.put(Fixtures.login("Site " + i, "u", "p" + i));
            vault.save();
        }
        try (SecretChars pw = Fixtures.chars(NEW_PHRASE)) {
            service.changePassphrase(vault, pw);
        }
        vault.save();
        assertEquals(seq + 5, vault.header().saveSeq());
        try (Vault later = unlockWith(service, NEW_PHRASE)) {
            later.put(Fixtures.login("Later", "u", "p"));
            later.save();
            assertEquals(seq + 6, later.header().saveSeq());
        }
    }

    /** A file that is no longer a vault this build reads is not overwritten either. */
    @Test
    void aFileThatIsNoLongerAVaultIsNotOverwritten() throws IOException {
        byte[] newer = read(VAULT);
        newer[9] = (byte) (EnvelopeCodec.VERSION + 1);
        byte[] junk = "not a vault".getBytes(StandardCharsets.UTF_8);
        for (byte[] file : List.of(newer, junk)) {
            Files.write(dir.resolve(VAULT), file);
            assertEquals(VaultException.Code.CONFLICT, assertThrows(VaultException.class, vault::save).code());
            assertArrayEquals(file, read(VAULT));
        }
    }

    /**
     * The check and the write are one step for every vault over the store: a stale vault's save
     * that starts while a change is between its check and its rename waits for the change, then
     * is refused. Without the shared save lock it would pass the check and write first.
     */
    @Test
    void aStaleSaveThatRacesAChangeWaitsForItAndIsRefused()
            throws IOException, InterruptedException, StorageException, VaultException {
        try (Vault stale = unlockWith(service, Fixtures.PHRASE)) {
            stale.put(Fixtures.login("FromStale", "b", "s4"));
            CountDownLatch paused = new CountDownLatch(1);
            CountDownLatch resume = new CountDownLatch(1);
            AtomicReference<Exception> changeFailure = new AtomicReference<>();
            AtomicReference<Exception> staleOutcome = new AtomicReference<>();
            Thread changer = new Thread(() -> {
                try (SecretChars pw = Fixtures.chars(NEW_PHRASE)) {
                    service.changePassphrase(vault, pw, at -> {
                        if (at == Vault.WriteStep.SEALED) {
                            paused.countDown();
                            awaitLatch(resume);
                        }
                    });
                } catch (VaultException | RuntimeException e) {
                    changeFailure.set(e);
                }
            });
            Thread saver = new Thread(() -> {
                try {
                    stale.save();
                } catch (VaultException | RuntimeException e) {
                    staleOutcome.set(e);
                }
            });
            changer.start();
            assertTrue(paused.await(30, TimeUnit.SECONDS));
            saver.start();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
            while (saver.getState() != Thread.State.WAITING && saver.isAlive() && System.nanoTime() < deadline) {
                Thread.onSpinWait();
            }
            assertEquals(Thread.State.WAITING, saver.getState(), "the stale save waits for the change");
            resume.countDown();
            changer.join(TimeUnit.SECONDS.toMillis(30));
            saver.join(TimeUnit.SECONDS.toMillis(30));

            assertNull(changeFailure.get());
            VaultException refused = assertInstanceOf(VaultException.class, staleOutcome.get());
            assertEquals(VaultException.Code.CONFLICT, refused.code());
            assertEquals(EnumSet.of(Key.NEW, Key.RECOVERY), keysOpening(read(VAULT)));
        }
    }

    private static void awaitLatch(CountDownLatch latch) {
        try {
            assertTrue(latch.await(30, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    // ---- helpers -----------------------------------------------------------------------------------

    /** The keys that unlock {@code file}, each unlock holding {@link #expected}. */
    private Set<Key> keysOpening(byte[] file) throws IOException, StorageException, VaultException {
        return keysOpening(file, v -> assertEquals(expected, v.records()));
    }

    /** The keys that unlock {@code file}, read from a fresh directory; {@code check} runs on each unlock. */
    private Set<Key> keysOpening(byte[] file, Consumer<Vault> check)
            throws IOException, StorageException, VaultException {
        Path copyDir = Files.createDirectory(dir.resolve("copy-" + copies.incrementAndGet()));
        Path copy = copyDir.resolve(VAULT);
        Files.write(copy, file);
        Files.setPosixFilePermissions(copy, PosixFilePermissions.fromString("rw-------"));
        Files.setPosixFilePermissions(copyDir, PosixFilePermissions.fromString("rwx------"));
        Set<Key> opening = EnumSet.noneOf(Key.class);
        try (VaultFileStore copyStore = VaultFileStore.open(copy)) {
            VaultService reader = new VaultService(copyStore, Fixtures.CLOCK, Argon2Params.FLOOR);
            for (Key key : Key.values()) {
                try (Vault v = unlock(reader, key)) {
                    check.accept(v);
                    opening.add(key);
                } catch (VaultException e) {
                    assertEquals(VaultException.Code.WRONG_CREDENTIAL, e.code(), key.name());
                }
            }
        }
        return opening;
    }

    private Vault unlock(VaultService reader, Key key) throws VaultException {
        return switch (key) {
            case OLD -> unlockWith(reader, Fixtures.PHRASE);
            case NEW -> unlockWith(reader, NEW_PHRASE);
            case RECOVERY -> reader.unlockWithRecoveryKey(created.recoveryKey());
        };
    }

    private static Vault unlockWith(VaultService reader, String phrase) throws VaultException {
        try (SecretChars pw = Fixtures.chars(phrase)) {
            return reader.unlockWithPassphrase(pw);
        }
    }

    private byte[] read(String name) throws IOException {
        return Files.readAllBytes(dir.resolve(name));
    }

    private byte[] readUnchecked(String name) {
        try {
            return read(name);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private void writeUnchecked(String name, byte[] bytes) {
        try {
            Files.write(dir.resolve(name), bytes);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void setPermissions(Path path, String permissions) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(permissions));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Closes a try-with-resources secret early (the statement closes it again; close is idempotent). */
    private static void closeNow(SecretChars secret) {
        secret.close();
    }

    private static byte[] filled(int length, int value) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) value);
        return out;
    }
}
