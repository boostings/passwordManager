package pm.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.CryptoException;
import pm.crypto.KeyWrap;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.storage.BackupDirectory;
import pm.storage.OwnerOnly;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.envelope.KdfHeader;
import pm.vault.envelope.SlotHeader;
import pm.vault.internal.PasskeyRecordAccess;
import pm.vault.record.PasskeyFixtures;
import pm.vault.record.PasskeyRecord;

/** The checks behind the vault's rarer failures, driven directly rather than by a large or racing setup. */
class VaultEdgesTest {
    @TempDir
    Path dir;

    @Test
    void aClockBeforeTheEpochIsAConfigurationError() {
        Clock before = Clock.fixed(Instant.ofEpochSecond(-1), ZoneOffset.UTC);
        assertEquals("clock before epoch", assertThrows(IllegalStateException.class,
                () -> VaultService.epochSeconds(before)).getMessage());
        assertEquals(0, VaultService.epochSeconds(Clock.fixed(Instant.EPOCH, ZoneOffset.UTC)));
    }

    @Test
    @SuppressWarnings("PMD.CloseResource") // `closed` is the store the try block already closed
    void anUnsafeVaultPathIsStorageAndAClosedStoreIsAProgrammingError() throws IOException, StorageException {
        Path vault = dir.resolve("vault.pmv");
        VaultFileStore closed;
        try (VaultFileStore store = VaultFileStore.open(vault)) {
            closed = store;
            Files.createDirectory(vault);
            VaultException e = assertThrows(VaultException.class, () -> VaultService.storeExists(store));
            assertEquals(VaultException.Code.STORAGE, e.code());
            assertInstanceOf(StorageException.class, e.getCause());
        }
        assertThrows(IllegalStateException.class, () -> VaultService.storeExists(closed));
    }

    @Test
    void aKdfFailureOtherThanMemoryIsPassedOn() {
        KdfHeader shortSalt = new KdfHeader(EnvelopeCodec.KDF_ALG, 65_536, 3, 1, new byte[31]);
        try (SecretChars pw = Fixtures.chars("pw")) {
            CryptoException e = assertThrows(CryptoException.class,
                    () -> VaultReader.passphraseKek(pw, shortSalt, UUID.randomUUID()));
            assertEquals(CryptoException.Code.BAD_INPUT, e.code());
        }
    }

    @Test
    void anUnwrapFailureOtherThanAuthenticationIsPassedOnAndAShortKeyIsCorrupt() throws CryptoException {
        SlotHeader slot = new SlotHeader(UUID.randomUUID(), SlotHeader.MASTER, new byte[EnvelopeCodec.WRAPPED_KEY_LENGTH]);
        try (SecretBytes shortKek = SecretBytes.copyOf(new byte[16])) {
            assertEquals(CryptoException.Code.BAD_INPUT,
                    assertThrows(CryptoException.class, () -> VaultReader.unwrap(shortKek, slot)).code());
        }
        try (SecretBytes kek = SecretBytes.copyOf(new byte[32]);
             SecretBytes shortKey = SecretBytes.copyOf(new byte[Vault.KEY_LENGTH - 1])) {
            byte[] wrapped = KeyWrap.wrap(kek, shortKey);
            assertEquals(EnvelopeCodec.WRAPPED_KEY_LENGTH, wrapped.length, "a 31-byte key pads to the same length");
            SlotHeader crafted = new SlotHeader(slot.id(), SlotHeader.MASTER, wrapped);
            assertEquals(VaultException.Code.CORRUPT,
                    assertThrows(VaultException.class, () -> VaultReader.unwrap(kek, crafted)).code());
        }
    }

    @Test
    void thePasskeyHookIsInstalledOnceAndACounterOnlyMovesUp() {
        PasskeyRecordAccess.Hook hook = PasskeyRecordAccess.hook();
        assertEquals("ALREADY_INSTALLED",
                assertThrows(IllegalStateException.class, () -> PasskeyRecordAccess.install(hook)).getMessage());
        try (PasskeyRecord record = PasskeyFixtures.passkey("00000000-0000-0000-0000-000000000001")) {
            assertThrows(IllegalArgumentException.class,
                    () -> hook.advanced(record, record.signCount(), PasskeyFixtures.T0));
        }
    }

    @Test
    void aFileAboveTheReadBoundIsNeverWritten() throws VaultException {
        VaultException e = assertThrows(VaultException.class, () -> Vault.refuseOversized(11, 10));
        assertEquals(VaultException.Code.STORAGE, e.code());
        assertEquals(StorageException.Code.TOO_LARGE, StorageException.class.cast(e.getCause()).code());
        Vault.refuseOversized(10, 10);
    }

    @Test
    void aRestoreThatDoesNotReadBackIsStorage() throws VaultException {
        assertEquals(VaultException.Code.STORAGE, assertThrows(VaultException.class,
                () -> VaultBackups.requireReadBack(new byte[] {1}, new byte[] {2})).code());
        VaultBackups.requireReadBack(new byte[] {1}, new byte[] {1});
    }

    @Test
    void aBackupAlreadyGoneCountsTowardsTheRotationButIsNotReported() throws IOException, StorageException {
        Path backups = Files.createDirectory(dir.resolve("backups"));
        OwnerOnly.apply(backups);
        String present = "pm-backup-20261003T080910Z-001.pmbackup";
        Files.write(backups.resolve(present), new byte[] {1});
        OwnerOnly.apply(backups.resolve(present));
        List<String> names = List.of("pm-backup-20261003T080910Z-000.pmbackup", present,
                "pm-backup-20261003T080910Z-002.pmbackup");
        List<Path> skipped = new ArrayList<>();
        VaultBackups.Rotation rotation = VaultBackups.deleteOldest(BackupDirectory.open(backups), names, 1, null, skipped);
        assertEquals(List.of(present), rotation.removed().stream().map(f -> String.valueOf(f.getFileName())).toList());
        assertEquals(List.of(), rotation.skipped());
    }
}
