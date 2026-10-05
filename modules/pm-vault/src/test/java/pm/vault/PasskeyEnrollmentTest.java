package pm.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.Argon2Params;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;
import pm.crypto.Hash;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.crypto.passkey.CoseKey;
import pm.crypto.passkey.Es256;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.record.PasskeyRecord;
import pm.vault.record.RecordException;
import pm.vault.record.VaultRecord;

/**
 * Passkey enrollment and edits (M6.3, ADR 0016 M6.3 addendum, SR-115): the key is generated and
 * the record built inside the vault, saved before anything is returned, only public material comes
 * back, a failed save enrolls nothing, and edits change the names only.
 */
@Tag("T-PK-03")
final class PasskeyEnrollmentTest {
    private static final byte[] USER = "user-handle-1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CLIENT_DATA_HASH = Hash.sha256("cd".getBytes(StandardCharsets.UTF_8));
    private static final int COUNTER_OFFSET = 33;

    @TempDir
    Path dir;

    private VaultFileStore store;
    private FailingCodec codec;
    private VaultService service;

    @BeforeEach
    void open() throws StorageException {
        store = VaultFileStore.open(dir.resolve("vault.pmv"));
        codec = new FailingCodec();
        service = new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR, codec);
    }

    @AfterEach
    void closeStore() throws IOException {
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        store.close();
    }

    private Vault fresh() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE); CreatedVault created = service.create(pw)) {
            created.vault().save();
        }
        return reopen();
    }

    private Vault reopen() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE)) {
            return service.unlockWithPassphrase(pw);
        }
    }

    /** The public fields of the vault's view of passkey {@code id}; the view is closed. */
    private static Snap stored(Vault v, UUID id) {
        try (PasskeyRecord r = v.records().stream().filter(x -> x.id().equals(id)).map(PasskeyRecord.class::cast)
                .findFirst().orElseThrow()) {
            return new Snap(r.title(), r.accountName(), r.displayName(), r.signCount(),
                    HexFormat.of().formatHex(r.credentialId()), HexFormat.of().formatHex(r.userHandle()), r.created());
        }
    }

    /** A closed-over copy of a passkey view's public fields. */
    private record Snap(String title, String accountName, String displayName, long signCount, String credentialId,
                        String userHandle, Instant created) {
    }

    @Test
    void enrollmentSavesTheRecordAndReturnsOnlyPublicMaterial() throws PasskeyException, VaultException, CryptoException {
        PasskeyCreated created;
        try (Vault v = fresh()) {
            created = v.createPasskey("Example", "example.com", USER, "alice", "Alice A");
            assertEquals("example.com", created.rpId());
            assertEquals(32, created.credentialId().length);
            assertEquals(CoseKey.EC2_BYTES, created.cosePublicKey().length);
            assertTrue(created.toString().contains("example.com"));
            assertFalse(created.toString().contains("credential"));
            // Copies out.
            created.credentialId()[0] ^= 1;
            created.cosePublicKey()[0] ^= 1;
            assertEquals(HexFormat.of().formatHex(created.credentialId()), stored(v, created.id()).credentialId());
        }
        // Saved before return: a fresh unlock sees it with counter 0 and a key that signs.
        try (Vault v = reopen()) {
            Snap r = stored(v, created.id());
            assertEquals(0, r.signCount());
            assertEquals("Example", r.title());
            assertEquals("alice", r.accountName());
            assertEquals("Alice A", r.displayName());
            assertEquals(HexFormat.of().formatHex(USER), r.userHandle());
            assertEquals(Fixtures.T0, r.created());
            PasskeyAssertion a = v.signWithPasskey(created.id(), CLIENT_DATA_HASH,
                    p -> authData(p.rpId(), p.signCount()));
            assertEquals(1, a.signCount());
            assertTrue(Es256.verify(created.cosePublicKey(), a.authenticatorData(), CLIENT_DATA_HASH,
                    a.signature()));
        }
    }

    @Test
    void twoEnrollmentsGetDistinctIdsCredentialsAndKeys() throws PasskeyException, VaultException, IOException {
        try (Vault v = fresh()) {
            PasskeyCreated a = v.createPasskey("A", "example.com", USER, "alice", "");
            PasskeyCreated b = v.createPasskey("B", "example.com", USER, "alice", "");
            assertNotEquals(a.id(), b.id());
            assertFalse(ConstantTime.equals(a.credentialId(), b.credentialId()));
            assertFalse(ConstantTime.equals(a.cosePublicKey(), b.cosePublicKey()));
        }
    }

    @Test
    void badFieldsAreRefusedAndNothingChanges() throws PasskeyException, VaultException, IOException {
        try (Vault v = fresh()) {
            PasskeyException ip = assertThrows(PasskeyException.class,
                    () -> v.createPasskey("t", "Example.COM", USER, "alice", ""));
            assertEquals(PasskeyException.Code.BAD_INPUT, ip.code());
            assertInstanceOf(IllegalArgumentException.class, ip.getCause());
            PasskeyException handle = assertThrows(PasskeyException.class,
                    () -> v.createPasskey("t", "example.com", new byte[0], "alice", ""));
            assertEquals(PasskeyException.Code.BAD_INPUT, handle.code());
            assertTrue(v.records().isEmpty());
        }
    }

    @Test
    void lockedAndReentrantCallsAreRefused() throws PasskeyException, VaultException, IOException {
        try (Vault v = fresh()) {
            refuseReentrantAndLocked(v);
        }
    }

    private static void refuseReentrantAndLocked(Vault v) throws PasskeyException {
        PasskeyCreated created = v.createPasskey("t", "example.com", USER, "alice", "");
        AtomicReference<PasskeyException> inner = new AtomicReference<>();
        AtomicReference<PasskeyException> edit = new AtomicReference<>();
        AtomicReference<PasskeyException> rename = new AtomicReference<>();
        v.signWithPasskey(created.id(), CLIENT_DATA_HASH, p -> {
            inner.set(assertThrows(PasskeyException.class,
                    () -> v.createPasskey("t2", "example.com", USER, "bob", "")));
            edit.set(assertThrows(PasskeyException.class,
                    () -> v.editPasskey(created.id(), "x", "mallory", "Mallory")));
            rename.set(assertThrows(PasskeyException.class, () -> v.renamePasskey(created.id(), "x")));
            return authData(p.rpId(), p.signCount());
        });
        assertEquals(PasskeyException.Code.REENTRANT, inner.get().code());
        assertEquals(PasskeyException.Code.REENTRANT, edit.get().code());
        assertEquals(PasskeyException.Code.REENTRANT, rename.get().code());
        refuseMutationsInsideThePort(v, created.id());
        assertEquals(1, v.records().size());
        Snap kept = stored(v, created.id());
        assertEquals("t", kept.title());
        assertEquals("alice", kept.accountName());
        assertEquals("", kept.displayName());
        closeNow(v);
        PasskeyException locked = assertThrows(PasskeyException.class,
                () -> v.createPasskey("t", "example.com", USER, "alice", ""));
        assertEquals(PasskeyException.Code.LOCKED, locked.code());
    }

    /**
     * Inside the port, put, remove, save and close are refused with {@code REENTRANT} on the
     * signing thread: the signature still comes back, the record is kept and the vault stays open.
     * Another thread's call waits instead: {@code PasskeyCounterTest}.
     */
    private static void refuseMutationsInsideThePort(Vault v, UUID id) throws PasskeyException {
        List<String> refused = new ArrayList<>();
        PasskeyAssertion a = v.signWithPasskey(id, CLIENT_DATA_HASH, p -> {
            try (VaultRecord view = v.records().get(0)) {
                refused.add(assertThrows(IllegalStateException.class, () -> v.put(view)).getMessage());
            }
            refused.add(assertThrows(IllegalStateException.class, () -> v.remove(id)).getMessage());
            refused.add(assertThrows(IllegalStateException.class, v::save).getMessage());
            refused.add(assertThrows(IllegalStateException.class, v::close).getMessage());
            assertFalse(v.isLocked());
            return authData(p.rpId(), p.signCount());
        });
        assertTrue(a.signature().length > 0);
        assertEquals(List.of("REENTRANT", "REENTRANT", "REENTRANT", "REENTRANT"), refused);
        assertFalse(v.isLocked());
        assertEquals(id, v.records().get(0).id());
    }

    @Test
    void aStorageFailureEnrollsNothing() throws PasskeyException, VaultException, IOException {
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
        try (Vault v = fresh()) {
            byte[] before = Files.readAllBytes(dir.resolve("vault.pmv"));
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("r-x------"));
            PasskeyException e = assertThrows(PasskeyException.class,
                    () -> v.createPasskey("t", "example.com", USER, "alice", ""));
            assertEquals(PasskeyException.Code.SAVE_FAILED, e.code());
            assertInstanceOf(VaultException.class, e.getCause());
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
            assertTrue(v.records().isEmpty());
            assertArrayEquals(before, Files.readAllBytes(dir.resolve("vault.pmv")));
        }
    }

    @Test
    void aCodecFailureEnrollsNothingAndKeepsPendingEdits() throws PasskeyException, VaultException, IOException {
        try (Vault v = fresh()) {
            v.put(Fixtures.login("pending", "u", "p"));
            codec.fail = true;
            PasskeyException e = assertThrows(PasskeyException.class,
                    () -> v.createPasskey("t", "example.com", USER, "alice", ""));
            assertEquals(PasskeyException.Code.SAVE_FAILED, e.code());
            assertInstanceOf(IllegalStateException.class, e.getCause());
            codec.fail = false;
            assertEquals(1, v.records().size());
            v.save();
        }
        try (Vault v = reopen()) {
            assertEquals(List.of("pending"), v.records().stream().map(VaultRecord::title).toList());
        }
    }

    @Test
    void editsChangeTheNamesOnlyAndReachDiskOnSave() throws PasskeyException, VaultException, CryptoException {
        PasskeyCreated created;
        try (Vault v = fresh()) {
            created = v.createPasskey("Old", "example.com", USER, "alice", "A");
            v.signWithPasskey(created.id(), CLIENT_DATA_HASH, p -> authData(p.rpId(), p.signCount()));
            assertTrue(v.editPasskey(created.id(), "New", "alice2", "Alice Two"));
            assertTrue(v.renamePasskey(created.id(), "Newer"));
            Snap r = stored(v, created.id());
            assertEquals("Newer", r.title());
            assertEquals("alice2", r.accountName());
            assertEquals("Alice Two", r.displayName());
            assertEquals(1, r.signCount());
            assertEquals(HexFormat.of().formatHex(created.credentialId()), r.credentialId());
            assertThrows(IllegalArgumentException.class,
                    () -> v.editPasskey(created.id(), "x".repeat(PasskeyRecord.MAX_NAME_CHARS + 1), "a", ""));
            assertEquals("Newer", stored(v, created.id()).title());
            v.save();
        }
        try (Vault v = reopen()) {
            Snap r = stored(v, created.id());
            assertEquals("Newer", r.title());
            assertEquals(1, r.signCount());
            // The key survived the edits.
            PasskeyAssertion a = v.signWithPasskey(created.id(), CLIENT_DATA_HASH,
                    p -> authData(p.rpId(), p.signCount()));
            assertTrue(Es256.verify(created.cosePublicKey(), a.authenticatorData(), CLIENT_DATA_HASH,
                    a.signature()));
        }
    }

    @Test
    void editsOfMissingOrNonPasskeyRecordsChangeNothing() throws PasskeyException, VaultException, IOException {
        try (Vault v = fresh()) {
            v.put(Fixtures.login("login", "u", "p"));
            UUID login = v.records().get(0).id();
            assertFalse(v.editPasskey(UUID.randomUUID(), "t", "a", ""));
            assertFalse(v.editPasskey(login, "t", "a", ""));
            assertFalse(v.renamePasskey(UUID.randomUUID(), "t"));
            assertFalse(v.renamePasskey(login, "t"));
            assertEquals("login", v.records().get(0).title());
        }
        try (Vault closed = reopen()) {
            closeNow(closed);
            UUID any = UUID.randomUUID();
            assertThrows(IllegalStateException.class, () -> closed.editPasskey(any, "t", "a", ""));
            assertThrows(IllegalStateException.class, () -> closed.renamePasskey(any, "t"));
        }
    }

    /** Locks a vault that a try-with-resources block will close again. */
    private static void closeNow(Vault v) {
        v.close();
    }

    /** Assertion authenticator data bound to the record: rpIdHash, UP|BE|BS, the persisted counter. */
    static byte[] authData(String rpId, long count) {
        byte[] out = new byte[COUNTER_OFFSET + 4];
        System.arraycopy(Hash.sha256(rpId.getBytes(StandardCharsets.US_ASCII)), 0, out, 0, 32);
        out[32] = 0x19;
        for (int i = 0; i < 4; i++) {
            out[COUNTER_OFFSET + i] = (byte) (count >>> (24 - 8 * i));
        }
        return out;
    }

    /** The production codec with a switchable encode failure. */
    private static final class FailingCodec implements PayloadCodec {
        volatile boolean fail;

        @Override
        public SecretBytes encode(List<VaultRecord> records) {
            if (fail) {
                throw new IllegalStateException("injected encode failure");
            }
            return PayloadCodec.RECORDS.encode(records);
        }

        @Override
        public List<VaultRecord> decode(SecretBytes plaintext) throws RecordException {
            return PayloadCodec.RECORDS.decode(plaintext);
        }
    }
}
