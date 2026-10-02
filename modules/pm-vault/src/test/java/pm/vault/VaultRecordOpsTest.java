package pm.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.Argon2Params;
import pm.crypto.SecretChars;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.record.LoginRecord;
import pm.vault.record.VaultRecord;

/**
 * Record operations and persistence across lock/unlock (M1.2 C 2c). Records declared in a
 * try header are also owned by the vault after {@code put}; closing twice is harmless
 * because {@code close()} is idempotent.
 */
final class VaultRecordOpsTest {

    @TempDir
    Path dir;

    private VaultFileStore store;
    private VaultService service;

    @BeforeEach
    void open() throws StorageException {
        store = VaultFileStore.open(dir.resolve("vault.pmv"));
        service = new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR);
    }

    @AfterEach
    void closeStore() {
        store.close();
    }

    @Test
    void putSaveCloseUnlockReturnsEqualRecords() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw);
             Vault v = created.vault()) {
            v.put(Fixtures.login("mail", "alice", "s3cret-mail"));
            v.put(Fixtures.login("bank", "alice.b", "s3cret-bank"));
            v.put(Fixtures.login("forge", "al", "s3cret-forge"));
            v.save();
            assertEquals(3, v.records().size());
        }
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault reopened = service.unlockWithPassphrase(pw);
             LoginRecord mail = Fixtures.login("mail", "alice", "s3cret-mail");
             LoginRecord bank = Fixtures.login("bank", "alice.b", "s3cret-bank");
             LoginRecord forge = Fixtures.login("forge", "al", "s3cret-forge")) {
            List<VaultRecord> got = reopened.records();
            assertEquals(3, got.size());
            assertSameLogin(mail, got.get(0));
            assertSameLogin(bank, got.get(1));
            assertSameLogin(forge, got.get(2));
        }
    }

    @Test
    void recordsSnapshotIsUnmodifiable() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw);
             Vault v = created.vault()) {
            v.put(Fixtures.login("a", "u", "p"));
            List<VaultRecord> snapshot = v.records();
            assertThrows(UnsupportedOperationException.class, snapshot::clear);
            v.put(Fixtures.login("b", "u", "p"));
            assertEquals(1, snapshot.size(), "snapshot does not track later changes");
        }
    }

    @Test
    void putReplacesByIdAndClosesTheReplacedRecordOnLock() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw);
             LoginRecord first = Fixtures.login("mail", "alice", "old");
             LoginRecord second = Fixtures.login("mail", "alice", "new")) {
            assertEquals(first.id(), second.id());
            created.vault().put(first);
            created.vault().put(second);
            assertEquals(1, created.vault().records().size());
            assertSame(second, created.vault().records().get(0));
            assertFalse(Fixtures.pwOf(first).isClosed(), "retired, closed on lock");
            created.vault().close();
            assertTrue(Fixtures.pwOf(first).isClosed());
            assertTrue(Fixtures.pwOf(second).isClosed());
        }
    }

    @Test
    void replacementSharingTheOldSecretStaysUsable() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw);
             LoginRecord first = Fixtures.login("mail", "alice", "shared");
             LoginRecord renamed = new LoginRecord(first.id(), "mail-renamed", first.username(),
                     Fixtures.pwOf(first), first.urls(), first.notes(), first.tags(),
                     first.created(), first.updated(), first.lastUsed())) {
            created.vault().put(first);
            created.vault().put(renamed);
            created.vault().save();
            assertFalse(Fixtures.pwOf(renamed).isClosed());
        }
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault reopened = service.unlockWithPassphrase(pw);
             LoginRecord expected = Fixtures.login("mail", "alice", "shared")) {
            assertEquals("mail-renamed", reopened.records().get(0).title());
            assertEquals(Fixtures.pwOf(expected), Fixtures.pwOf((LoginRecord) reopened.records().get(0)));
        }
    }

    @Test
    void puttingTheSameInstanceTwiceDoesNotCloseIt() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw);
             LoginRecord r = Fixtures.login("mail", "alice", "pw")) {
            created.vault().put(r);
            created.vault().put(r);
            assertFalse(Fixtures.pwOf(r).isClosed());
            assertEquals(1, created.vault().records().size());
        }
    }

    @Test
    void removeClosesAndReportsPresence() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw);
             Vault v = created.vault();
             LoginRecord r = Fixtures.login("mail", "alice", "pw")) {
            v.put(r);
            assertTrue(v.remove(r.id()));
            assertTrue(Fixtures.pwOf(r).isClosed());
            assertFalse(v.remove(r.id()));
            assertFalse(v.remove(new UUID(7L, 7L)));
            assertTrue(v.records().isEmpty());
        }
    }

    @Test
    void searchMatchesPublicFieldsButNeverSecrets() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw);
             Vault v = created.vault()) {
            v.put(Fixtures.login("Mail", "alice", "hunter2"));
            v.put(Fixtures.login("bank", "bob", "letmein"));
            assertEquals(1, v.search("MAIL").size());
            assertEquals(1, v.search("bob").size());
            assertEquals(2, v.search("").size());
            assertTrue(v.search("hunter").isEmpty());
        }
    }

    @Test
    void lockClosesEveryRecordSecret() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw);
             LoginRecord r = Fixtures.login("mail", "alice", "pw")) {
            created.vault().put(r);
            created.vault().close();
            assertTrue(Fixtures.pwOf(r).isClosed());
        }
    }

    @Test
    void savedChangesSurviveRemoveAndReplace() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw);
             Vault v = created.vault()) {
            v.put(Fixtures.login("mail", "alice", "one"));
            v.put(Fixtures.login("bank", "bob", "two"));
            v.save();
            assertTrue(v.remove(Fixtures.login("mail", "x", "y").id()));
            v.put(Fixtures.login("bank", "robert", "three"));
            v.save();
        }
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault reopened = service.unlockWithPassphrase(pw);
             LoginRecord expected = Fixtures.login("bank", "robert", "three")) {
            assertEquals(1, reopened.records().size());
            assertSameLogin(expected, reopened.records().get(0));
            assertEquals(3L, reopened.header().saveSeq());
        }
    }

    @Test
    void failedSaveKeepsPreviousHeader() throws VaultException, IOException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw);
             Vault v = created.vault()) {
            // A non-empty directory where the vault file was makes any backup/rename fail.
            Path vaultPath = dir.resolve("vault.pmv");
            Files.delete(vaultPath);
            Files.createDirectories(vaultPath.resolve("blocker"));
            VaultException e = assertThrows(VaultException.class, v::save);
            assertEquals(VaultException.Code.STORAGE, e.code());
            assertInstanceOf(StorageException.class, e.getCause());
            assertEquals(1L, v.header().saveSeq(), "ERR03-J: header unchanged after a failed save");
        }
    }

    private static void assertSameLogin(LoginRecord expected, VaultRecord actual) {
        assertInstanceOf(LoginRecord.class, actual);
        assertEquals(expected.id(), actual.id());
        assertEquals(expected.title(), actual.title());
        assertEquals(expected.created(), actual.created());
        assertEquals(expected.updated(), actual.updated());
        assertEquals(expected.username(), ((LoginRecord) actual).username());
        assertEquals(expected.urls(), ((LoginRecord) actual).urls());
        assertEquals(expected.tags(), ((LoginRecord) actual).tags());
        assertEquals(expected.notes(), ((LoginRecord) actual).notes());
        assertEquals(Fixtures.pwOf(expected), Fixtures.pwOf((LoginRecord) actual), "compared in constant time");
    }
}
