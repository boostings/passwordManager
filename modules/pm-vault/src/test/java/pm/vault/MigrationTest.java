package pm.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import pm.crypto.Argon2Params;
import pm.crypto.CryptoException;
import pm.crypto.RecoveryKey;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.storage.OwnerOnly;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.record.RecordException;
import pm.vault.record.VaultRecord;

/**
 * Format migration framework (ADR 0015, T-MIG-01, SR-701): migration from every prior version,
 * rollback on injected failures, refusal of a newer version. Uses the synthetic format 0 of
 * {@link Formats} injected through the registry.
 */
@Tag("T-MIG-01")
final class MigrationTest {

    private static final String ROLLBACK = VaultService.ROLLBACK_SUFFIX_PREFIX + 0;

    @TempDir
    Path dir;

    private Path vaultPath;
    private Path rollbackPath;
    private VaultFileStore store;

    @BeforeEach
    void open() throws StorageException {
        vaultPath = dir.resolve("vault.pmv");
        rollbackPath = dir.resolve("vault.pmv" + ROLLBACK);
        store = VaultFileStore.open(vaultPath);
    }

    @AfterEach
    void closeStore() {
        store.close();
    }

    static IntStream everyReadableVersion() {
        return IntStream.rangeClosed(Formats.WITH_V0.oldestReadable(), EnvelopeCodec.VERSION);
    }

    /** One file per prior version: the synthetic format 0 and the committed golden format 1. */
    private static byte[] fixture(int version) throws CryptoException {
        if (version == 0) {
            List<VaultRecord> records = Formats.goldenRecords();
            try {
                return Formats.v0File(Formats.GOLDEN_PHRASE, null, records);
            } finally {
                records.forEach(VaultRecord::close);
            }
        }
        return Formats.golden(version);
    }

    @ParameterizedTest
    @MethodSource("everyReadableVersion")
    void everyPriorVersionMigratesToTheCurrentOneWithItsContentIntact(int version)
            throws CryptoException, IOException, StorageException, VaultException {
        byte[] original = fixture(version);
        Formats.install(vaultPath, original);
        VaultService service = service(VaultService.MigrationProbe.NONE);

        GoldenFixtureTest.assertGoldenContent(service);

        byte[] migrated = Files.readAllBytes(vaultPath);
        assertEquals(EnvelopeCodec.VERSION, EnvelopeCodec.peekVersion(migrated));
        assertFalse(Files.exists(rollbackPath, LinkOption.NOFOLLOW_LINKS), "rollback copy deleted after verify");
        if (version < EnvelopeCodec.VERSION) {
            // The save rotated the pre-migration file into .bak.1 (plan.md §21: backup first).
            assertArrayEquals(original, Files.readAllBytes(dir.resolve("vault.pmv.bak.1")));
        }
        // The migrated file opens with the production build, which has no format-0 reader.
        GoldenFixtureTest.assertGoldenContent(new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR));
    }

    @Test
    void recoveryKeyUnlockAlsoMigrates() throws CryptoException, IOException, StorageException, VaultException {
        try (SecretBytes rk = RecoveryKey.generate()) {
            List<VaultRecord> records = Formats.goldenRecords();
            try {
                Formats.install(vaultPath, Formats.v0File(Formats.GOLDEN_PHRASE, rk, records));
            } finally {
                records.forEach(VaultRecord::close);
            }
            try (SecretChars typed = RecoveryKey.format(rk);
                 Vault vault = service(VaultService.MigrationProbe.NONE).unlockWithRecoveryKey(typed)) {
                assertEquals(4, vault.records().size());
            }
        }
        assertEquals(EnvelopeCodec.VERSION, EnvelopeCodec.peekVersion(Files.readAllBytes(vaultPath)));
    }

    @Test
    void wrongPassphraseLeavesTheOldFileUntouched() throws CryptoException, IOException, StorageException {
        byte[] original = installV0();
        try (SecretChars pw = Fixtures.chars("not the phrase")) {
            VaultException e = assertThrows(VaultException.class,
                    () -> service(VaultService.MigrationProbe.NONE).unlockWithPassphrase(pw));
            assertEquals(VaultException.Code.WRONG_CREDENTIAL, e.code());
        }
        assertUntouched(original);
    }

    @Test
    void tamperedOldFileIsRefusedBeforeAnyMigrationRuns() throws CryptoException, IOException, StorageException {
        byte[] original = installV0();
        byte[] tampered = original.clone();
        tampered[tampered.length - 1] ^= 1;
        Formats.install(vaultPath, tampered);
        assertCode(VaultException.Code.CORRUPT, service(VaultService.MigrationProbe.NONE));
        assertUntouched(tampered);
    }

    @Test
    void relabellingTheVersionFailsAuthentication() throws CryptoException, IOException, StorageException {
        // The version is in the AAD: a format-0 file presented as format 1 does not verify.
        byte[] relabelled = installV0().clone();
        relabelled[9] = (byte) EnvelopeCodec.VERSION;
        Formats.install(vaultPath, relabelled);
        assertCode(VaultException.Code.CORRUPT, service(VaultService.MigrationProbe.NONE));
        assertUntouched(relabelled);
    }

    @Test
    void versionWithoutAMigrationChainIsUnsupported() throws CryptoException, IOException, StorageException {
        byte[] original = installV0();
        assertCode(VaultException.Code.UNSUPPORTED_VERSION,
                new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR));
        assertUntouched(original);
    }

    @Test
    void newerVersionIsRefusedAsADowngrade() throws IOException, StorageException, VaultException {
        byte[] newer = Formats.golden(EnvelopeCodec.VERSION).clone();
        newer[9] = (byte) (EnvelopeCodec.VERSION + 1);
        Formats.install(vaultPath, newer);
        assertEquals(EnvelopeCodec.VERSION + 1, new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR)
                .fileFormatVersion());
        assertCode(VaultException.Code.UNSUPPORTED_VERSION, service(VaultService.MigrationProbe.NONE));
        assertCode(VaultException.Code.UNSUPPORTED_VERSION,
                new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR));
        assertUntouched(newer);
    }

    @Test
    void failingMigrationStepWritesNothing() throws CryptoException, IOException, StorageException {
        byte[] original = installV0();
        Migration failing = new Migration() {
            @Override
            public int fromVersion() {
                return 0;
            }

            @Override
            public SecretBytes apply(SecretBytes payload) throws RecordException {
                throw new RecordException(RecordException.Code.SCHEMA, "injected");
            }
        };
        VaultService service = new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR,
                PayloadCodec.RECORDS, new MigrationRegistry(List.of(failing)), VaultService.MigrationProbe.NONE);
        assertCode(VaultException.Code.CORRUPT, service);
        assertUntouched(original);
    }

    @Test
    void migrationOutputThatTheCurrentCodecRejectsWritesNothing()
            throws CryptoException, IOException, StorageException {
        byte[] original = installV0();
        Migration garbage = new Migration() {
            @Override
            public int fromVersion() {
                return 0;
            }

            @Override
            public SecretBytes apply(SecretBytes payload) {
                return SecretBytes.copyOf(new byte[] {(byte) 0xff});
            }
        };
        VaultService service = new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR,
                PayloadCodec.RECORDS, new MigrationRegistry(List.of(garbage)), VaultService.MigrationProbe.NONE);
        assertCode(VaultException.Code.CORRUPT, service);
        assertUntouched(original);
    }

    @Test
    void rollbackCopyIsOwnerOnlyAndHoldsTheOriginal() throws CryptoException, IOException, StorageException,
            VaultException {
        byte[] original = installV0();
        AtomicReference<byte[]> seen = new AtomicReference<>();
        VaultService service = service(step -> {
            if (step == VaultService.MigrationStep.ROLLBACK_COPY_WRITTEN) {
                try {
                    seen.set(Files.readAllBytes(rollbackPath));
                    assertTrue(OwnerOnly.isOwnerOnly(rollbackPath));
                    if (dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                        assertEquals("rw-------",
                                PosixFilePermissions.toString(Files.getPosixFilePermissions(rollbackPath)));
                    }
                } catch (IOException | StorageException e) {
                    throw new AssertionError(e);
                }
            }
        });
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE);
             Vault vault = service.unlockWithPassphrase(pw)) {
            assertFalse(vault.isLocked());
        }
        assertArrayEquals(original, seen.get());
        assertFalse(Files.exists(rollbackPath, LinkOption.NOFOLLOW_LINKS));
    }

    @Test
    void failureAfterTheRollbackCopyRestoresNothingBecauseNothingChanged()
            throws CryptoException, IOException, StorageException {
        byte[] original = installV0();
        assertCode(VaultException.Code.STORAGE, service(failAt(VaultService.MigrationStep.ROLLBACK_COPY_WRITTEN)));
        assertUntouched(original);
    }

    @Test
    void failureMidWriteAfterTheNewFileIsInstalledRollsBack()
            throws CryptoException, IOException, StorageException {
        byte[] original = installV0();
        AtomicReference<Integer> versionWhenFailed = new AtomicReference<>();
        VaultService service = service(step -> {
            if (step == VaultService.MigrationStep.MIGRATED_WRITTEN) {
                versionWhenFailed.set(versionOnDisk());
                throw new VaultException(VaultException.Code.STORAGE, null);
            }
        });
        assertCode(VaultException.Code.STORAGE, service);
        assertEquals(EnvelopeCodec.VERSION, versionWhenFailed.get(), "the migrated file was in place");
        assertUntouched(original);
    }

    @Test
    void migratedFileThatFailsVerificationOnReopenRollsBack()
            throws CryptoException, IOException, StorageException {
        byte[] original = installV0();
        VaultService service = service(step -> {
            if (step == VaultService.MigrationStep.MIGRATED_WRITTEN) {
                try {
                    byte[] written = Files.readAllBytes(vaultPath);
                    written[written.length - 1] ^= 1;
                    Files.write(vaultPath, written);
                } catch (IOException e) {
                    throw new AssertionError(e);
                }
            }
        });
        assertCode(VaultException.Code.CORRUPT, service);
        assertUntouched(original);
    }

    @Test
    void runtimeFailureMidMigrationAlsoRollsBack() throws CryptoException, IOException, StorageException {
        byte[] original = installV0();
        VaultService service = service(step -> {
            if (step == VaultService.MigrationStep.MIGRATED_WRITTEN) {
                throw new IllegalStateException("injected");
            }
        });
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            assertThrows(IllegalStateException.class, () -> service.unlockWithPassphrase(pw));
        }
        assertUntouched(original);
    }

    @Test
    void errorMidMigrationStillRollsBack() throws CryptoException, IOException, StorageException, VaultException {
        byte[] original = installV0();
        VaultService service = service(step -> {
            if (step == VaultService.MigrationStep.MIGRATED_WRITTEN) {
                throw new OutOfMemoryError("injected");
            }
        });
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            assertThrows(OutOfMemoryError.class, () -> service.unlockWithPassphrase(pw));
        }
        assertUntouched(original);
        // The store is still usable and the original still migrates.
        GoldenFixtureTest.assertGoldenContent(service(VaultService.MigrationProbe.NONE));
    }

    @Test
    void staleRollbackCopyIsRemovedOnceTheCurrentFileOpens()
            throws CryptoException, IOException, StorageException, VaultException {
        // An interrupted run: the migrated file was installed but the process died before the
        // copy was deleted.
        Formats.install(vaultPath, Formats.golden(EnvelopeCodec.VERSION));
        Formats.install(rollbackPath, fixture(0));
        GoldenFixtureTest.assertGoldenContent(new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR));
        assertFalse(Files.exists(rollbackPath, LinkOption.NOFOLLOW_LINKS));
    }

    @Test
    void staleRollbackCopyIsKeptWhenTheCurrentFileDoesNotOpen() throws IOException, StorageException {
        byte[] damaged = Formats.golden(EnvelopeCodec.VERSION).clone();
        damaged[damaged.length - 1] ^= 1;
        Formats.install(vaultPath, damaged);
        Formats.install(rollbackPath, new byte[] {1});
        assertCode(VaultException.Code.CORRUPT, new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR));
        assertArrayEquals(new byte[] {1}, Files.readAllBytes(rollbackPath));
    }

    @Test
    void identicalLeftoverRollbackCopyFromAnInterruptedRunIsReused()
            throws CryptoException, IOException, StorageException, VaultException {
        byte[] original = installV0();
        Formats.install(rollbackPath, original);
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE);
             Vault vault = service(VaultService.MigrationProbe.NONE).unlockWithPassphrase(pw)) {
            assertEquals(4, vault.records().size());
        }
        assertEquals(EnvelopeCodec.VERSION, versionOnDisk());
        assertFalse(Files.exists(rollbackPath, LinkOption.NOFOLLOW_LINKS));
    }

    @Test
    void differentLeftoverRollbackCopyIsNeverOverwritten()
            throws CryptoException, IOException, StorageException {
        byte[] original = installV0();
        byte[] other = {1, 2, 3};
        Formats.install(rollbackPath, other);
        assertCode(VaultException.Code.STORAGE, service(VaultService.MigrationProbe.NONE));
        assertUntouched(original, false);
        assertArrayEquals(other, Files.readAllBytes(rollbackPath));
    }

    @Test
    void currentVersionUnlockNeverCreatesARollbackCopy() throws IOException, StorageException, VaultException {
        Formats.install(vaultPath, Formats.golden(EnvelopeCodec.VERSION));
        GoldenFixtureTest.assertGoldenContent(service(failAt(VaultService.MigrationStep.ROLLBACK_COPY_WRITTEN)));
        assertArrayEquals(Formats.golden(EnvelopeCodec.VERSION), Files.readAllBytes(vaultPath));
        assertEquals(EnvelopeCodec.VERSION, VaultService.currentFormatVersion());
    }

    @Test
    void aMigratedFileReplacedByTheOldVersionBeforeVerificationIsCorruptAndRolledBack()
            throws CryptoException, IOException, StorageException {
        byte[] original = installV0();
        VaultService service = service(step -> {
            if (step == VaultService.MigrationStep.MIGRATED_WRITTEN) {
                try {
                    Files.write(vaultPath, original);
                } catch (IOException e) {
                    throw new AssertionError(e);
                }
            }
        });
        assertCode(VaultException.Code.CORRUPT, service);
        assertUntouched(original);
    }

    @Test
    void aRollbackThatCannotWriteKeepsTheCopyAndIsAttachedToTheFailure()
            throws CryptoException, IOException, StorageException {
        installV0();
        VaultService service = service(step -> {
            if (step == VaultService.MigrationStep.MIGRATED_WRITTEN) {
                store.close();
                throw new VaultException(VaultException.Code.STORAGE, null);
            }
        });
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            VaultException e = assertThrows(VaultException.class, () -> service.unlockWithPassphrase(pw));
            assertEquals(VaultException.Code.STORAGE, e.code());
            assertEquals(1, e.getSuppressed().length, "the failed restore is attached");
        }
        assertTrue(Files.exists(rollbackPath, LinkOption.NOFOLLOW_LINKS), "the copy stays for the user");
    }

    @Test
    void aRollbackThatCannotWriteAfterAnErrorKeepsTheCopy() throws CryptoException, IOException, StorageException {
        installV0();
        VaultService service = service(step -> {
            if (step == VaultService.MigrationStep.MIGRATED_WRITTEN) {
                store.close();
                throw new OutOfMemoryError("injected");
            }
        });
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            OutOfMemoryError e = assertThrows(OutOfMemoryError.class, () -> service.unlockWithPassphrase(pw));
            assertEquals(0, e.getSuppressed().length);
        }
        assertTrue(Files.exists(rollbackPath, LinkOption.NOFOLLOW_LINKS), "the copy stays for the user");
    }

    // ---- helpers -------------------------------------------------------------------------------

    private VaultService service(VaultService.MigrationProbe probe) {
        return new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR, PayloadCodec.RECORDS,
                Formats.WITH_V0, probe);
    }

    private static VaultService.MigrationProbe failAt(VaultService.MigrationStep at) {
        return step -> {
            if (step == at) {
                throw new VaultException(VaultException.Code.STORAGE, null);
            }
        };
    }

    private byte[] installV0() throws CryptoException, IOException, StorageException {
        byte[] file = fixture(0);
        Formats.install(vaultPath, file);
        return file;
    }

    private int versionOnDisk() {
        try {
            return EnvelopeCodec.peekVersion(Files.readAllBytes(vaultPath));
        } catch (IOException | VaultException e) {
            throw new AssertionError(e);
        }
    }

    private static void assertCode(VaultException.Code expected, VaultService service) {
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            VaultException e = assertThrows(VaultException.class, () -> service.unlockWithPassphrase(pw));
            assertEquals(expected, e.code());
        }
    }

    private void assertUntouched(byte[] original) throws IOException {
        assertUntouched(original, true);
    }

    private void assertUntouched(byte[] original, boolean noRollbackCopy) throws IOException {
        assertArrayEquals(original, Files.readAllBytes(vaultPath), "original vault bytes");
        assertFalse(Files.exists(dir.resolve("vault.pmv.tmp"), LinkOption.NOFOLLOW_LINKS), "no staging file");
        if (noRollbackCopy) {
            assertFalse(Files.exists(rollbackPath, LinkOption.NOFOLLOW_LINKS), "no rollback copy left");
        }
    }
}
