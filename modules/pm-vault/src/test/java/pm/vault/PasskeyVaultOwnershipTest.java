package pm.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import pm.crypto.Argon2Params;
import pm.crypto.CryptoException;
import pm.crypto.Hash;
import pm.crypto.SecretChars;
import pm.crypto.passkey.Es256;
import pm.crypto.passkey.PasskeyKey;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.internal.PasskeyRecordAccess;
import pm.vault.record.LoginRecord;
import pm.vault.record.PasskeyFixtures;
import pm.vault.record.PasskeyRecord;
import pm.vault.record.VaultRecord;

/**
 * The passkey key and counter belong to the vault (M6.2 review fixes, ADR 0016 addendum, SR-085,
 * SR-087, SR-088, AC-51). Regression tests for the adversarial review: a stale record put back
 * cannot roll the counter back; nothing handed out of the vault can close the live key; a nested
 * sign on the port's thread is refused; signing does not rotate the {@code .bak.N} recovery points;
 * a restore raises every passkey counter by 2^20 and above the counter of the vault it overwrites,
 * and a raise that would reach 2^32 - 1 leaves the credential exhausted.
 */
@Tag("T-PK-02")
final class PasskeyVaultOwnershipTest {
    private static final UUID PK_ID = UUID.fromString("55555555-5555-4555-8555-555555555555");
    private static final UUID LOGIN_ID = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final byte[] CLIENT_DATA_HASH = Hash.sha256("ownership".getBytes(StandardCharsets.UTF_8));
    private static final int COUNTER_OFFSET = 33;
    private static final byte[] RP_ID_HASH = Hash.sha256("example.com".getBytes(StandardCharsets.US_ASCII));
    private static final int SIGNS = 5;

    @TempDir
    Path dir;

    private final AtomicInteger copies = new AtomicInteger();
    private VaultFileStore store;
    private VaultService service;
    private byte[] cosePublicKey;

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
    void aStaleRecordPutBackNeverRollsTheCounterBack() throws PasskeyException, VaultException, CryptoException {
        List<Long> released = new ArrayList<>();
        try (Vault v = vaultWithPasskey(0)) {
            try (VaultRecord stale = v.records().get(0)) {
                released.add(sign(v).signCount());
                released.add(sign(v).signCount());
                v.put(stale);
            }
            v.save();
            assertEquals(2, countOnDisk());
            released.add(sign(v).signCount());
        }
        assertEquals(List.of(1L, 2L, 3L), released);
        assertEquals(3, countOnDisk());
    }

    @Test
    void aPutKeepsTheVaultsKeyAndCounterAndTakesOnlyTheEditableFields() throws PasskeyException, VaultException,
            CryptoException {
        try (Vault v = vaultWithPasskey(7)) {
            try (PasskeyKey other = PasskeyKey.generate();
                 PasskeyRecord forged = PasskeyFixtures.passkey(PK_ID, other, 0)) {
                v.put(forged);
                assertTrue(PasskeyRecordAccess.hook().privateKey(forged).isClosed(),
                        "the vault took ownership and closed the edit");
            }
            v.save();
            PasskeyAssertion a = sign(v);
            assertEquals(8, a.signCount());
            assertTrue(Es256.verify(cosePublicKey, a.authenticatorData(), CLIENT_DATA_HASH, a.signature()),
                    "still signed with the original key");
        }
        assertEquals(8, countOnDisk());
    }

    @Test
    void recordsAndSearchHandOutKeylessViews() throws VaultException {
        try (Vault v = vaultWithPasskey(0)) {
            assertKeyless(v.records().get(0));
            assertKeyless(v.search("example").get(0));
            assertNotSame(v.records().get(0), v.records().get(0), "each call hands out a new view");
        }
    }

    @Test
    void closingAnythingHandedOutLeavesTheVaultUsable() throws PasskeyException, VaultException, CryptoException {
        try (Vault v = vaultWithPasskey(0)) {
            try (VaultRecord snapshot = v.records().get(0)) {
                PasskeyAssertion first = v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, persisted -> {
                    persisted.close();
                    return authenticatorData(persisted.signCount());
                });
                assertEquals(1, first.signCount());
                assertTrue(Es256.verify(cosePublicKey, first.authenticatorData(), CLIENT_DATA_HASH, first.signature()));
                assertEquals(PK_ID, snapshot.id());
            }
            v.records().forEach(VaultRecord::close);
            v.save();
            PasskeyAssertion second = sign(v);
            assertEquals(2, second.signCount());
            assertTrue(Es256.verify(cosePublicKey, second.authenticatorData(), CLIENT_DATA_HASH, second.signature()));
        }
        assertEquals(2, countOnDisk());
    }

    @Test
    void aNestedSignOnThePortsThreadIsRefused() throws PasskeyException, VaultException {
        AtomicReference<PasskeyException> nested = new AtomicReference<>();
        try (Vault v = vaultWithPasskey(0)) {
            PasskeyAssertion outer = v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, persisted -> {
                try {
                    v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, PasskeyVaultOwnershipTest::port);
                } catch (PasskeyException e) {
                    nested.set(e);
                }
                return authenticatorData(persisted.signCount());
            });
            assertEquals(1, outer.signCount());
            assertEquals(PasskeyException.Code.REENTRANT, nested.get().code());
            assertEquals(2, sign(v).signCount());
        }
        assertEquals(2, countOnDisk());
    }

    @Test
    void signingDoesNotPushOutTheBackupOfADeletedRecord() throws PasskeyException, VaultException, IOException,
            StorageException {
        try (Vault v = vaultWithPasskey(0)) {
            v.put(new LoginRecord(LOGIN_ID, "Bank", "alice", pm.crypto.SecretBytes.copyOf(
                    "pw".getBytes(StandardCharsets.UTF_8)), List.of(), "", List.of(), Fixtures.T0, Fixtures.T0,
                    Fixtures.T0));
            v.save();
            v.remove(LOGIN_ID);
            v.save();
            List<byte[]> before = backups();
            assertTrue(anyBackupHoldsTheLogin(), "a backup holds the deleted login");
            for (int i = 0; i < SIGNS; i++) {
                sign(v);
            }
            List<byte[]> after = backups();
            assertEquals(before.size(), after.size());
            for (int i = 0; i < before.size(); i++) {
                assertArrayEquals(before.get(i), after.get(i), "bak." + (i + 1));
            }
            assertTrue(anyBackupHoldsTheLogin(), "still recoverable after " + SIGNS + " signs");
            // A sign with a pending edit is a content save, so it does rotate.
            v.put(Fixtures.login("mail", "bob", "pw2"));
            sign(v);
            assertNotEquals(java.util.HexFormat.of().formatHex(before.get(0)),
                    java.util.HexFormat.of().formatHex(Files.readAllBytes(dir.resolve("vault.pmv.bak.1"))));
        }
        assertEquals(SIGNS + 1, countOnDisk());
    }

    @Test
    void aRestoreRaisesEveryPasskeyCounter() throws PasskeyException, VaultException, IOException, StorageException {
        Instant now = Instant.parse("2026-10-04T00:00:00Z");
        VaultBackups backups = new VaultBackups(Clock.fixed(now, ZoneOffset.UTC));
        Path backup;
        try (Vault v = vaultWithPasskey(5)) {
            backup = backups.create(v, dir.resolve("backups"), 3).file();
            for (int i = 0; i < SIGNS; i++) {
                sign(v);
            }
        }
        Path target = Files.createDirectory(dir.resolve("restored")).resolve("vault.pmv");
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE)) {
            VaultBackups.Restored restored = backups.restore(backup, target, pw, false);
            assertFalse(restored.replacedExisting());
        }
        long raised = 5 + VaultBackups.RESTORE_COUNTER_MARGIN;
        try (VaultFileStore other = VaultFileStore.open(target);
             SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault reopened = new VaultService(other, Fixtures.CLOCK, Argon2Params.FLOOR).unlockWithPassphrase(pw)) {
            assertEquals(raised, stored(reopened).signCount());
            assertEquals(raised + 1, sign(reopened).signCount());
        }
        assertEquals(1L << 20, VaultBackups.RESTORE_COUNTER_MARGIN);
    }

    /** Ways a port could try to get a signature the vault did not bind to this record and counter. */
    enum Forgery {
        FOREIGN_RP_HASH, OTHER_SITE, NO_USER_PRESENCE, ATTESTED_DATA, OLD_COUNTER, LATER_COUNTER, ZERO_COUNTER,
        SHORT, EXTENSION_FLAG_WITHOUT_DATA, TRAILING_DATA_WITHOUT_EXTENSION_FLAG
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(Forgery.class)
    void authenticatorDataNotBoundToTheRecordIsRefusedAndTheCounterStaysBurnt(Forgery forgery)
            throws PasskeyException, VaultException {
        try (Vault v = vaultWithPasskey(5)) {
            PasskeyException e = assertThrows(PasskeyException.class,
                    () -> v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, persisted -> forged(forgery, persisted)));
            assertEquals(PasskeyException.Code.SIGN_FAILED, e.code());
            assertEquals(6, stored(v).signCount());
            assertEquals(7, sign(v).signCount());
        }
        assertEquals(7, countOnDisk());
    }

    @Test
    void userVerifiedAndExtensionDataAreLeftToTheCaller() throws PasskeyException, VaultException {
        try (Vault v = vaultWithPasskey(5)) {
            PasskeyAssertion verified = v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, persisted -> {
                byte[] data = authenticatorData(persisted.signCount());
                data[RP_ID_HASH.length] = 0x05;
                return data;
            });
            assertEquals(6, verified.signCount());
            PasskeyAssertion extended = v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, persisted -> {
                byte[] data = java.util.Arrays.copyOf(authenticatorData(persisted.signCount()),
                        Es256.MIN_AUTHENTICATOR_DATA_BYTES + 1);
                data[RP_ID_HASH.length] = (byte) 0x81;
                data[Es256.MIN_AUTHENTICATOR_DATA_BYTES] = (byte) 0xA0;
                return data;
            });
            assertEquals(7, extended.signCount());
        }
    }

    private static byte[] forged(Forgery forgery, PasskeyRecord persisted) {
        long count = persisted.signCount();
        byte[] data = authenticatorData(count);
        int flags = RP_ID_HASH.length;
        return switch (forgery) {
            case FOREIGN_RP_HASH -> {
                data[0] ^= 1;
                yield data;
            }
            case OTHER_SITE -> {
                byte[] other = Hash.sha256("evil.com".getBytes(StandardCharsets.US_ASCII));
                System.arraycopy(other, 0, data, 0, other.length);
                yield data;
            }
            case NO_USER_PRESENCE -> {
                data[flags] = 0x04;
                yield data;
            }
            case ATTESTED_DATA -> {
                data[flags] = 0x41;
                yield data;
            }
            case OLD_COUNTER -> authenticatorData(count - 1);
            case LATER_COUNTER -> authenticatorData(count + 1);
            case ZERO_COUNTER -> authenticatorData(0);
            case SHORT -> java.util.Arrays.copyOf(data, Es256.MIN_AUTHENTICATOR_DATA_BYTES - 1);
            case EXTENSION_FLAG_WITHOUT_DATA -> {
                data[flags] = (byte) 0x81;
                yield data;
            }
            case TRAILING_DATA_WITHOUT_EXTENSION_FLAG -> java.util.Arrays.copyOf(data, data.length + 1);
        };
    }

    @Test
    void restoringTheSameBackupTwiceNeverReusesACounter() throws PasskeyException, VaultException, IOException,
            StorageException {
        VaultBackups backups = new VaultBackups(Clock.fixed(Instant.parse("2026-10-04T00:00:00Z"), ZoneOffset.UTC));
        Path backup;
        try (Vault v = vaultWithPasskey(5)) {
            backup = backups.create(v, dir.resolve("backups"), 3).file();
        }
        Path target = createOwnerOnly(dir.resolve("restored")).resolve("vault.pmv");
        List<Long> released = new ArrayList<>();
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE)) {
            backups.restore(backup, target, pw, false);
        }
        try (VaultFileStore other = VaultFileStore.open(target);
             SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault restored = new VaultService(other, Fixtures.CLOCK, Argon2Params.FLOOR).unlockWithPassphrase(pw)) {
            for (int i = 0; i < 3; i++) {
                released.add(sign(restored).signCount());
            }
        }
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE)) {
            assertTrue(backups.restore(backup, target, pw, true).replacedExisting());
        }
        long highest = 5 + VaultBackups.RESTORE_COUNTER_MARGIN + 3;
        assertEquals(List.of(highest - 2, highest - 1, highest), released);
        try (VaultFileStore other = VaultFileStore.open(target);
             SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault again = new VaultService(other, Fixtures.CLOCK, Argon2Params.FLOOR).unlockWithPassphrase(pw)) {
            assertEquals(highest + 1, stored(again).signCount());
            long next = sign(again).signCount();
            assertEquals(highest + 2, next);
            assertFalse(released.contains(next));
        }
    }

    @Test
    void aRestoreThatWouldReachTheLastCounterLeavesTheCredentialExhausted() throws PasskeyException, VaultException,
            IOException, StorageException {
        long max = PasskeyRecord.MAX_SIGN_COUNT;
        VaultBackups backups = new VaultBackups(Clock.fixed(Instant.parse("2026-10-04T00:00:00Z"), ZoneOffset.UTC));
        Path backup;
        List<Long> released = new ArrayList<>();
        try (Vault v = vaultWithPasskey(max - 2)) {
            backup = backups.create(v, dir.resolve("backups"), 3).file();
            released.add(sign(v).signCount());
            released.add(sign(v).signCount());
        }
        assertEquals(List.of(max - 1, max), released);
        Path target = createOwnerOnly(dir.resolve("restored")).resolve("vault.pmv");
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE)) {
            backups.restore(backup, target, pw, false);
        }
        try (VaultFileStore other = VaultFileStore.open(target);
             SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault restored = new VaultService(other, Fixtures.CLOCK, Argon2Params.FLOOR).unlockWithPassphrase(pw)) {
            assertEquals(max, stored(restored).signCount());
            PasskeyException e = assertThrows(PasskeyException.class, () -> sign(restored));
            assertEquals(PasskeyException.Code.COUNTER_EXHAUSTED, e.code());
        }
    }

    @Test
    void theRestoreRaiseIsAboveTheFloorAndExhaustsInsteadOfCapping() throws VaultException {
        long max = PasskeyRecord.MAX_SIGN_COUNT;
        long margin = VaultBackups.RESTORE_COUNTER_MARGIN;
        assertEquals(max, raisedCount(max - 10, Map.of()));
        assertEquals(max, raisedCount(max - margin, Map.of()));
        assertEquals(max - 1, raisedCount(max - margin - 1, Map.of()));
        assertEquals(max, raisedCount(max - 1, Map.of()));
        assertEquals(max, raisedCount(max, Map.of()));
        assertEquals(margin, raisedCount(0, Map.of()));
        assertEquals(5 + margin + 4, raisedCount(5, Map.of(PK_ID, 5 + margin + 3)));
        assertEquals(5 + margin, raisedCount(5, Map.of(PK_ID, 3L)));
        assertEquals(5 + margin, raisedCount(5, Map.of(LOGIN_ID, max)));
        assertEquals(max, raisedCount(5, Map.of(PK_ID, max)));
        assertEquals(max, raisedCount(5, Map.of(PK_ID, max - 1)));
    }

    // ---- helpers -------------------------------------------------------------------------------

    /** The counter after {@link Vault#raisedForRestore} of a vault whose passkey has {@code count}. */
    private long raisedCount(long count, Map<UUID, Long> floors) throws VaultException {
        Path sub = dir.resolve("raise-" + copies.incrementAndGet());
        try (VaultFileStore other = VaultFileStore.open(createOwnerOnly(sub).resolve("vault.pmv"))) {
            VaultService s = new VaultService(other, Fixtures.CLOCK, Argon2Params.FLOOR);
            try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
                 CreatedVault created = s.create(pw);
                 PasskeyKey key = PasskeyKey.generate()) {
                created.vault().put(PasskeyFixtures.passkey(PK_ID, key, count));
                created.vault().save();
            }
            VaultReader reader = new VaultReader(MigrationRegistry.PRODUCTION, PayloadCodec.RECORDS);
            VaultReader.Envelope env = reader.parse(other.readAll());
            try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
                 pm.crypto.SecretBytes vk = VaultReader.keyFromPassphrase(env.header(), pw)) {
                other.writeAtomically(Vault.raisedForRestore(env.header(), vk, PayloadCodec.RECORDS,
                        reader.records(env, vk), VaultBackups.RESTORE_COUNTER_MARGIN, floors,
                        Fixtures.T0.getEpochSecond()));
            }
            try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE); Vault reopened = s.unlockWithPassphrase(pw)) {
                return stored(reopened).signCount();
            }
        } catch (StorageException | IOException e) {
            throw new AssertionError(e);
        }
    }

    private static Path createOwnerOnly(Path sub) throws IOException {
        Files.createDirectory(sub);
        Files.setPosixFilePermissions(sub, PosixFilePermissions.fromString("rwx------"));
        return sub;
    }

    private static void assertKeyless(VaultRecord handedOut) {
        assertFalse(PasskeyRecordAccess.hook().keyIsValid(PasskeyRecord.class.cast(handedOut)));
        assertEquals("example.com", PasskeyRecord.class.cast(handedOut).rpId());
    }

    private Vault vaultWithPasskey(long count) throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             CreatedVault created = service.create(pw);
             PasskeyKey key = PasskeyKey.generate()) {
            cosePublicKey = key.cosePublicKey();
            created.vault().put(PasskeyFixtures.passkey(PK_ID, key, count));
            created.vault().save();
        }
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE)) {
            return service.unlockWithPassphrase(pw);
        }
    }

    private static PasskeyAssertion sign(Vault v) throws PasskeyException {
        return v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, PasskeyVaultOwnershipTest::port);
    }

    private static byte[] port(PasskeyRecord persisted) {
        return authenticatorData(persisted.signCount());
    }

    /** {@code SHA-256("example.com") || UP || signCount}: what the vault accepts for the fixture. */
    private static byte[] authenticatorData(long signCount) {
        byte[] out = new byte[Es256.MIN_AUTHENTICATOR_DATA_BYTES];
        System.arraycopy(RP_ID_HASH, 0, out, 0, RP_ID_HASH.length);
        out[RP_ID_HASH.length] = 1;
        for (int i = 0; i < Integer.BYTES; i++) {
            out[COUNTER_OFFSET + i] = (byte) (signCount >>> (Byte.SIZE * (Integer.BYTES - 1 - i)));
        }
        return out;
    }

    private static PasskeyRecord stored(Vault v) {
        return v.records().stream().filter(r -> r.id().equals(PK_ID)).map(PasskeyRecord.class::cast)
                .findFirst().orElseThrow();
    }

    private long countOnDisk() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault reopened = service.unlockWithPassphrase(pw)) {
            return stored(reopened).signCount();
        }
    }

    /** The {@code .bak.N} files that exist, oldest generation last. */
    private List<byte[]> backups() throws IOException {
        List<byte[]> out = new ArrayList<>();
        for (int n = 1; Files.exists(dir.resolve("vault.pmv.bak." + n)); n++) {
            out.add(Files.readAllBytes(dir.resolve("vault.pmv.bak." + n)));
        }
        return out;
    }

    private boolean anyBackupHoldsTheLogin() throws IOException, StorageException, VaultException {
        for (byte[] file : backups()) {
            Path copyDir = createOwnerOnly(dir.resolve("copy-" + copies.incrementAndGet()));
            Path copy = copyDir.resolve("vault.pmv");
            Files.write(copy, file);
            Files.setPosixFilePermissions(copy, PosixFilePermissions.fromString("rw-------"));
            try (VaultFileStore other = VaultFileStore.open(copy);
                 SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
                 Vault reopened = new VaultService(other, Fixtures.CLOCK, Argon2Params.FLOOR).unlockWithPassphrase(pw)) {
                if (reopened.records().stream().anyMatch(r -> r.id().equals(LOGIN_ID))) {
                    return true;
                }
            }
        }
        return false;
    }
}
