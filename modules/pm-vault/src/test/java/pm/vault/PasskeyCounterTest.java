package pm.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.Argon2Params;
import pm.crypto.CryptoException;
import pm.crypto.Hash;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.crypto.passkey.Es256;
import pm.crypto.passkey.PasskeyKey;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.record.PasskeyFixtures;
import pm.vault.record.PasskeyRecord;
import pm.vault.record.VaultRecord;

/**
 * The passkey counter operation (M6.2, ADR 0016 addendum, SR-087, SR-088, SR-401): the advanced
 * counter is on disk before the assertion exists, a failed save releases nothing, concurrent
 * signers get distinct increasing values, a crash after the save never lets the counter go back,
 * and the counter stops at 2^32 - 1. Storage faults are injected with a read-only directory and a
 * failing payload codec.
 */
@Tag("T-PK-02")
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: the concurrency test runs signers on a fixed pool
final class PasskeyCounterTest {
    private static final UUID PK_ID = UUID.fromString("55555555-5555-4555-8555-555555555555");
    private static final byte[] CLIENT_DATA_HASH = Hash.sha256("client-data".getBytes(StandardCharsets.UTF_8));
    private static final byte[] RP_ID_HASH = Hash.sha256("example.com".getBytes(StandardCharsets.UTF_8));
    private static final int FLAGS_UP_UV = 0x05;
    private static final int COUNTER_OFFSET = 33;
    private static final int THREADS = 4;
    private static final int SIGNS_PER_THREAD = 10;

    @TempDir
    Path dir;

    private final AtomicInteger copies = new AtomicInteger();
    private VaultFileStore store;
    private FaultyCodec codec;
    private VaultService service;
    private byte[] cosePublicKey;

    @BeforeEach
    void open() throws StorageException {
        store = VaultFileStore.open(dir.resolve("vault.pmv"));
        codec = new FaultyCodec();
        service = new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR, codec);
    }

    @AfterEach
    void closeStore() throws IOException {
        if (Files.exists(dir)) {
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        }
        store.close();
    }

    @Test
    void theCounterIsOnDiskBeforeTheAssertionIsReleased() throws PasskeyException, VaultException, IOException, StorageException, InterruptedException,
            CryptoException {
        AtomicReference<byte[]> fileWhileSigning = new AtomicReference<>();
        try (Vault v = vaultWithPasskey(0)) {
            PasskeyAssertion first = v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, persisted -> {
                fileWhileSigning.set(readVaultFileUnchecked());
                return authenticatorData(persisted.signCount());
            });
            assertEquals(1, first.signCount());
            assertEquals(1, counterIn(first.authenticatorData()));
            assertTrue(Es256.verify(cosePublicKey, first.authenticatorData(), CLIENT_DATA_HASH, first.signature()));
            PasskeyAssertion second = v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, PasskeyCounterTest::port);
            assertEquals(2, second.signCount());
            assertTrue(Es256.verify(cosePublicKey, second.authenticatorData(), CLIENT_DATA_HASH, second.signature()));
            assertEquals(Fixtures.T0, stored(v).lastUsed());
        }
        // The file as it was when the port ran already carries counter 1.
        assertEquals(1, countInFile(fileWhileSigning.get()));
        assertEquals(2, countOnDisk());
    }

    @Test
    void aFailedSaveReleasesNothingAndTheCounterNeverGoesBack() throws PasskeyException, VaultException, IOException, StorageException, InterruptedException,
            CryptoException {
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
        AtomicInteger portCalls = new AtomicInteger();
        try (Vault v = vaultWithPasskey(0)) {
            v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, PasskeyCounterTest::port);
            byte[] before = readVaultFile();
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("r-x------"));
            PasskeyException e = assertThrows(PasskeyException.class,
                    () -> v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, persisted -> {
                        portCalls.incrementAndGet();
                        return authenticatorData(persisted.signCount());
                    }));
            assertEquals(PasskeyException.Code.SAVE_FAILED, e.code());
            assertEquals("SAVE_FAILED", e.getMessage());
            VaultException cause = assertInstanceOf(VaultException.class, e.getCause());
            assertEquals(VaultException.Code.STORAGE, cause.code());
            assertEquals(0, portCalls.get());
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
            assertArrayEquals(before, readVaultFile());

            // Value 2 was burnt; the next assertion carries 3 and is saved before release.
            PasskeyAssertion next = v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, PasskeyCounterTest::port);
            assertEquals(3, next.signCount());
            assertEquals(3, countInFile(readVaultFile()));
        }
    }

    @Test
    void aCodecFailureDuringTheSaveReleasesNothing() throws PasskeyException, VaultException, IOException, StorageException, InterruptedException,
            CryptoException {
        AtomicInteger portCalls = new AtomicInteger();
        try (Vault v = vaultWithPasskey(4)) {
            codec.failEncode = true;
            PasskeyException e = assertCode(PasskeyException.Code.SAVE_FAILED,
                    () -> v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, persisted -> {
                        portCalls.incrementAndGet();
                        return authenticatorData(persisted.signCount());
                    }));
            assertInstanceOf(IllegalStateException.class, e.getCause());
            assertEquals(0, portCalls.get());
            codec.failEncode = false;
            assertEquals(6, v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, PasskeyCounterTest::port).signCount());
        }
        assertEquals(6, countOnDisk());
    }

    @Test
    void aCrashAfterTheSaveNeverLetsTheCounterGoBack() throws PasskeyException, VaultException, IOException, StorageException, InterruptedException,
            CryptoException {
        try (Vault v = vaultWithPasskey(10)) {
            PasskeyException e = assertCode(PasskeyException.Code.SIGN_FAILED,
                    () -> v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, persisted -> {
                        throw new SimulatedCrash();
                    }));
            assertInstanceOf(SimulatedCrash.class, e.getCause());
        }
        // "Restart": the counter that might have been signed is on disk.
        assertEquals(11, countOnDisk());
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault reopened = service.unlockWithPassphrase(pw)) {
            assertEquals(12, reopened.signWithPasskey(PK_ID, CLIENT_DATA_HASH, PasskeyCounterTest::port).signCount());
        }
    }

    @Test
    void concurrentSignersGetDistinctIncreasingCounters() throws PasskeyException, VaultException, IOException, StorageException, InterruptedException,
            CryptoException {
        ConcurrentLinkedQueue<Long> seen = new ConcurrentLinkedQueue<>();
        try (Vault v = vaultWithPasskey(0);
             ExecutorService pool = Executors.newFixedThreadPool(THREADS)) {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<List<Long>>> results = new ArrayList<>();
            for (int t = 0; t < THREADS; t++) {
                results.add(pool.submit(() -> {
                    start.await();
                    List<Long> mine = new ArrayList<>();
                    for (int i = 0; i < SIGNS_PER_THREAD; i++) {
                        PasskeyAssertion a = v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, persisted -> {
                            seen.add(persisted.signCount());
                            return authenticatorData(persisted.signCount());
                        });
                        assertEquals(a.signCount(), counterIn(a.authenticatorData()));
                        mine.add(a.signCount());
                    }
                    return mine;
                }));
            }
            start.countDown();
            Set<Long> all = new HashSet<>();
            for (Future<List<Long>> f : results) {
                List<Long> mine = get(f);
                for (int i = 1; i < mine.size(); i++) {
                    assertTrue(mine.get(i) > mine.get(i - 1), "per-thread order");
                }
                all.addAll(mine);
            }
            pool.shutdown();
            assertTrue(pool.awaitTermination(1, TimeUnit.MINUTES));
            int total = THREADS * SIGNS_PER_THREAD;
            assertEquals(total, all.size(), "no counter value was handed out twice");
            for (long c = 1; c <= total; c++) {
                assertTrue(all.contains(c), "counter " + c);
            }
            List<Long> order = new ArrayList<>(seen);
            for (int i = 1; i < order.size(); i++) {
                assertEquals(order.get(i - 1) + 1, order.get(i), "signing order is the counter order");
            }
            assertEquals(total, stored(v).signCount());
        }
        assertEquals(THREADS * SIGNS_PER_THREAD, countOnDisk());
    }

    @Test
    void theCounterStopsAtTwoToTheThirtyTwoMinusOne() throws PasskeyException, VaultException, IOException, StorageException, InterruptedException,
            CryptoException {
        try (Vault v = vaultWithPasskey(PasskeyRecord.MAX_SIGN_COUNT - 1)) {
            PasskeyAssertion last = v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, PasskeyCounterTest::port);
            assertEquals(PasskeyRecord.MAX_SIGN_COUNT, last.signCount());
            assertEquals(PasskeyRecord.MAX_SIGN_COUNT, counterIn(last.authenticatorData()));
            assertTrue(Es256.verify(cosePublicKey, last.authenticatorData(), CLIENT_DATA_HASH, last.signature()));
            long seq = v.header().saveSeq();
            byte[] file = readVaultFile();
            AtomicInteger portCalls = new AtomicInteger();
            PasskeyException e = assertThrows(PasskeyException.class,
                    () -> v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, persisted -> {
                        portCalls.incrementAndGet();
                        return authenticatorData(persisted.signCount());
                    }));
            assertEquals(PasskeyException.Code.COUNTER_EXHAUSTED, e.code());
            assertEquals(0, portCalls.get());
            assertEquals(seq, v.header().saveSeq());
            assertArrayEquals(file, readVaultFile());
            assertEquals(PasskeyRecord.MAX_SIGN_COUNT, stored(v).signCount());
        }
        assertEquals(PasskeyRecord.MAX_SIGN_COUNT, countOnDisk());
    }

    @Test
    void refusalsBeforeTheAdvanceChangeNothing() throws PasskeyException, VaultException, IOException, StorageException, InterruptedException,
            CryptoException {
        try (Vault v = vaultWithPasskey(3)) {
            v.put(Fixtures.login("mail", "bob", "pw2"));
            v.save();
            long seq = v.header().saveSeq();
            UUID loginId = v.records().stream().filter(r -> !(r instanceof PasskeyRecord))
                    .map(VaultRecord::id).findFirst().orElseThrow();
            assertCode(PasskeyException.Code.BAD_INPUT,
                    () -> v.signWithPasskey(PK_ID, new byte[Es256.CLIENT_DATA_HASH_BYTES - 1], PasskeyCounterTest::port));
            assertCode(PasskeyException.Code.BAD_INPUT,
                    () -> v.signWithPasskey(PK_ID, new byte[Es256.CLIENT_DATA_HASH_BYTES + 1], PasskeyCounterTest::port));
            assertCode(PasskeyException.Code.NOT_FOUND,
                    () -> v.signWithPasskey(loginId, CLIENT_DATA_HASH, PasskeyCounterTest::port));
            assertCode(PasskeyException.Code.NOT_FOUND,
                    () -> v.signWithPasskey(UUID.randomUUID(), CLIENT_DATA_HASH, PasskeyCounterTest::port));
            assertThrows(NullPointerException.class, () -> v.signWithPasskey(null, CLIENT_DATA_HASH, PasskeyCounterTest::port));
            assertThrows(NullPointerException.class, () -> v.signWithPasskey(PK_ID, null, PasskeyCounterTest::port));
            assertThrows(NullPointerException.class, () -> v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, null));
            assertEquals(seq, v.header().saveSeq());
            assertEquals(3, stored(v).signCount());
            closeNow(v);
            assertCode(PasskeyException.Code.LOCKED,
                    () -> v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, PasskeyCounterTest::port));
        }
        assertEquals(3, countOnDisk());
    }

    @Test
    void failuresAfterTheAdvanceKeepTheSavedCounter() throws PasskeyException, VaultException, IOException, StorageException, InterruptedException,
            CryptoException {
        try (Vault v = vaultWithPasskey(0)) {
            assertCode(PasskeyException.Code.SIGN_FAILED,
                    () -> v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, persisted -> new byte[Es256.MIN_AUTHENTICATOR_DATA_BYTES - 1]));
            assertEquals(1, countInFile(readVaultFile()));
            AtomicReference<byte[]> nothing = new AtomicReference<>();
            assertCode(PasskeyException.Code.SIGN_FAILED,
                    () -> v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, persisted -> nothing.get()));
            assertEquals(2, countInFile(readVaultFile()));
            // A key that does not load never gets in: put refuses it and the caller keeps it.
            UUID broken = UUID.fromString("66666666-6666-4666-8666-666666666666");
            try (PasskeyRecord bad = PasskeyFixtures.withBrokenKey(broken)) {
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> v.put(bad));
                assertEquals("BAD_KEY", e.getMessage());
            }
            assertCode(PasskeyException.Code.NOT_FOUND,
                    () -> v.signWithPasskey(broken, CLIENT_DATA_HASH, PasskeyCounterTest::port));
            assertEquals(3, v.signWithPasskey(PK_ID, CLIENT_DATA_HASH, PasskeyCounterTest::port).signCount());
        }
        assertEquals(3, countOnDisk());
    }

    @Test
    void theAssertionAndTheRecordHideSecretsAndCopyArrays() throws PasskeyException, VaultException, IOException, StorageException, InterruptedException,
            CryptoException {
        try (Vault v = vaultWithPasskey(0)) {
            byte[] hash = CLIENT_DATA_HASH.clone();
            PasskeyAssertion a = v.signWithPasskey(PK_ID, hash, PasskeyCounterTest::port);
            hash[0] ^= 1;
            assertTrue(Es256.verify(cosePublicKey, a.authenticatorData(), CLIENT_DATA_HASH, a.signature()));
            a.signature()[0] ^= 1;
            a.authenticatorData()[0] ^= 1;
            assertTrue(Es256.verify(cosePublicKey, a.authenticatorData(), CLIENT_DATA_HASH, a.signature()));
            assertEquals("PasskeyAssertion[signCount=1]", a.toString());
        }
    }

    // ---- helpers -------------------------------------------------------------------------------

    /** Creates a vault holding one passkey with counter {@code count}, saved to disk, and unlocks it. */
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

    /** Locks a vault that a try-with-resources block will close again (javac's try lint). */
    private static void closeNow(Vault v) {
        v.close();
    }

    private static byte[] port(PasskeyRecord persisted) {
        return authenticatorData(persisted.signCount());
    }

    /** {@code rpIdHash || flags || signCount (u32 big-endian)}. */
    private static byte[] authenticatorData(long signCount) {
        byte[] out = new byte[Es256.MIN_AUTHENTICATOR_DATA_BYTES];
        System.arraycopy(RP_ID_HASH, 0, out, 0, RP_ID_HASH.length);
        out[RP_ID_HASH.length] = (byte) FLAGS_UP_UV;
        for (int i = 0; i < Integer.BYTES; i++) {
            out[COUNTER_OFFSET + i] = (byte) (signCount >>> (Byte.SIZE * (Integer.BYTES - 1 - i)));
        }
        return out;
    }

    private static long counterIn(byte[] authenticatorData) {
        long value = 0;
        for (int i = 0; i < Integer.BYTES; i++) {
            value = (value << Byte.SIZE) | (authenticatorData[COUNTER_OFFSET + i] & 0xFF);
        }
        return value;
    }

    private static PasskeyRecord stored(Vault v) {
        return v.records().stream().filter(r -> r.id().equals(PK_ID)).map(PasskeyRecord.class::cast)
                .findFirst().orElseThrow();
    }

    private byte[] readVaultFile() throws IOException {
        return Files.readAllBytes(dir.resolve("vault.pmv"));
    }

    private byte[] readVaultFileUnchecked() {
        try {
            return readVaultFile();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** The counter in the vault file as last saved, read by a fresh unlock. */
    private long countOnDisk() throws VaultException {
        try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault reopened = service.unlockWithPassphrase(pw)) {
            return stored(reopened).signCount();
        }
    }

    /** The counter in {@code file}, a copy of a vault file, unlocked from another directory. */
    private long countInFile(byte[] file) throws IOException, StorageException, VaultException {
        Path copyDir = Files.createDirectory(dir.resolve("copy-" + copies.incrementAndGet()));
        Path copy = copyDir.resolve("vault.pmv");
        Files.write(copy, file);
        Files.setPosixFilePermissions(copy, PosixFilePermissions.fromString("rw-------"));
        Files.setPosixFilePermissions(copyDir, PosixFilePermissions.fromString("rwx------"));
        try (VaultFileStore other = VaultFileStore.open(copy);
             SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
             Vault reopened = new VaultService(other, Fixtures.CLOCK, Argon2Params.FLOOR).unlockWithPassphrase(pw)) {
            return stored(reopened).signCount();
        }
    }

    private static <T> T get(Future<T> f) throws InterruptedException {
        try {
            return f.get(1, TimeUnit.MINUTES);
        } catch (ExecutionException | java.util.concurrent.TimeoutException e) {
            throw new AssertionError(e);
        }
    }

    private static PasskeyException assertCode(PasskeyException.Code code, SignCall call) {
        PasskeyException e = assertThrows(PasskeyException.class, call::run);
        assertEquals(code, e.code());
        assertEquals(code.name(), e.getMessage());
        return e;
    }

    /** One call to {@code signWithPasskey}. */
    @FunctionalInterface
    private interface SignCall {
        void run() throws PasskeyException;
    }

    /** Stands in for the process dying between the save and the signature. */
    private static final class SimulatedCrash extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    /** The production codec, with an encode failure that can be switched on. */
    private static final class FaultyCodec implements PayloadCodec {
        volatile boolean failEncode;

        @Override
        public SecretBytes encode(List<VaultRecord> records) {
            if (failEncode) {
                throw new IllegalStateException("injected encode failure");
            }
            return PayloadCodec.RECORDS.encode(records);
        }

        @Override
        public List<VaultRecord> decode(SecretBytes plaintext) throws pm.vault.record.RecordException {
            return PayloadCodec.RECORDS.decode(plaintext);
        }
    }
}
