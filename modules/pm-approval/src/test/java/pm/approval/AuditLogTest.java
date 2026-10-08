package pm.approval;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** approval-model §7: append-only, 0600, chained; tampering and truncation report the entry number. */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: TPS00-J executors; PMD 7 flags executors too
class AuditLogTest {
    private static final Instant T0 = Instant.parse("2026-10-03T12:00:00Z");

    @TempDir
    Path dir;

    private Path log() {
        return dir.resolve("audit.log");
    }

    private void write(int n) throws AuditException {
        try (AuditLog a = AuditLog.open(log(), new TestClock(T0))) {
            for (int i = 0; i < n; i++) {
                a.record(AuditEvent.of(i % 2 == 0 ? "unlock" : "lock"));
            }
        }
    }

    private List<String> lines() throws IOException {
        return new ArrayList<>(Files.readAllLines(log(), StandardCharsets.US_ASCII));
    }

    private void rewrite(List<String> lines) throws IOException {
        Files.writeString(log(), lines.isEmpty() ? "" : String.join("\n", lines) + "\n", StandardCharsets.US_ASCII);
    }

    private AuditException.Code failure(long[] entry) {
        AuditException e = assertThrows(AuditException.class, () -> AuditLog.check(log()));
        entry[0] = e.entry();
        return e.code();
    }

    @Test
    void createsOwnerOnlyFilesAndReopensAcrossSessions() throws IOException, AuditException {
        write(3);
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(log())));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(AuditLog.headOf(log()))));
        write(2);
        assertEquals(5, AuditLog.check(log()));
        try (AuditLog a = AuditLog.open(log(), new TestClock(T0))) {
            assertEquals(5, a.entries());
        }
    }

    @Test
    void editedEntryIsReportedWithItsNumber() throws IOException, AuditException {
        write(5);
        List<String> l = lines();
        byte[] entry = Base64.getDecoder().decode(l.get(2));
        entry[entry.length - 1] ^= 1; // "unlock" -> "unlocj", or similar: still CBOR, wrong hash
        l.set(2, Base64.getEncoder().encodeToString(entry));
        rewrite(l);
        long[] at = new long[1];
        assertEquals(AuditException.Code.TAMPERED, failure(at));
        assertEquals(2, at[0], "entries 1 and 2 are intact; 3 is bad");
    }

    @Test
    void removedMiddleEntryBreaksTheChain() throws IOException, AuditException {
        write(5);
        List<String> l = lines();
        l.remove(1);
        rewrite(l);
        long[] at = new long[1];
        assertEquals(AuditException.Code.TAMPERED, failure(at));
        assertEquals(1, at[0]);
    }

    @Test
    void cutTailIsTruncation() throws IOException, AuditException {
        write(5);
        List<String> l = lines();
        rewrite(l.subList(0, 3));
        long[] at = new long[1];
        assertEquals(AuditException.Code.TRUNCATED, failure(at));
        assertEquals(3, at[0]);
        AuditException e = assertThrows(AuditException.class, () -> AuditLog.open(log(), new TestClock(T0)));
        assertEquals("audit log tampered or truncated after entry 3", e.userMessage());
    }

    @Test
    void cutMidLineIsTruncation() throws IOException, AuditException {
        write(3);
        byte[] all = Files.readAllBytes(log());
        Files.write(log(), java.util.Arrays.copyOf(all, all.length - 5));
        long[] at = new long[1];
        assertEquals(AuditException.Code.TRUNCATED, failure(at));
        assertEquals(2, at[0]);
    }

    @Test
    void deletedLogWithHeadIsTruncation() throws IOException, AuditException {
        write(2);
        Files.delete(log());
        long[] at = new long[1];
        assertEquals(AuditException.Code.TRUNCATED, failure(at));
        assertEquals(0, at[0]);
        // m712-004: a writer reports the same and creates nothing that a later 'mv' could put over the archive.
        AuditException append = assertThrows(AuditException.class,
                () -> AuditLog.append(log(), new TestClock(T0), AuditEvent.of("export")));
        assertEquals(AuditException.Code.TRUNCATED, append.code());
        AuditException open = assertThrows(AuditException.class, () -> AuditLog.open(log(), new TestClock(T0)));
        assertEquals("audit log tampered or truncated after entry 0", open.userMessage());
        assertFalse(Files.exists(log()), "no empty log is created in place of the missing one");
    }

    @Test
    void aFailedHeadWriteLeavesNoEntryAndTheLogStaysUsable() throws IOException, AuditException {
        // m712-001: a full disk fails the head's new file while the short log line still fits.
        write(3);
        byte[] before = Files.readAllBytes(log());
        String head = Files.readString(AuditLog.headOf(log()), StandardCharsets.US_ASCII);
        AuditLog.HeadWriter full = (file, n, hash) -> {
            throw new IOException("ENOSPC");
        };
        for (int attempt = 0; attempt < 2; attempt++) {
            AuditException e = assertThrows(AuditException.class, () -> AuditLog.append(log(), new TestClock(T0),
                    AuditEvent.of("export"), AuditLog.LOCK_WAIT, full));
            assertEquals(AuditException.Code.IO, e.code());
            assertArrayEquals(before, Files.readAllBytes(log()), "the refused export left no entry");
            assertEquals(head, Files.readString(AuditLog.headOf(log()), StandardCharsets.US_ASCII));
            assertEquals(3, AuditLog.check(log()));
        }
        AuditLog.append(log(), new TestClock(T0), AuditEvent.of("export"));
        assertEquals(4, AuditLog.check(log()), "once the disk has room, appends go on");
    }

    @Test
    void aFailedRollbackLeavesTheHeadOneBehindAndTheNextAppendCatchesUp() throws IOException, AuditException {
        write(3);
        // Interrupting closes the channel, so the cut after the failed head write fails too.
        AuditLog.HeadWriter interrupted = (file, n, hash) -> {
            Thread.currentThread().interrupt();
            throw new IOException("sharing violation");
        };
        AuditException e;
        try {
            e = assertThrows(AuditException.class, () -> AuditLog.append(log(), new TestClock(T0),
                    AuditEvent.of("export"), AuditLog.LOCK_WAIT, interrupted));
        } finally {
            assertTrue(Thread.interrupted(), "clears the flag the head writer set");
        }
        assertEquals(AuditException.Code.IO, e.code());
        assertTrue(Arrays.stream(e.getSuppressed()).map(Throwable::getMessage)
                .anyMatch(ClosedByInterruptException.class.getName()::equals), "the failed cut is kept");
        assertEquals(4, lines().size(), "the cut failed, so the entry stayed");
        assertTrue(Files.readString(AuditLog.headOf(log()), StandardCharsets.US_ASCII).startsWith("3 "));
        assertEquals(4, AuditLog.check(log()), "a head one behind is accepted");
        // The lagging head is brought up to date before anything is written; if that fails, nothing is.
        AuditLog.HeadWriter full = (file, n, hash) -> {
            throw new IOException("ENOSPC");
        };
        assertThrows(AuditException.class, () -> AuditLog.append(log(), new TestClock(T0),
                AuditEvent.of("export"), AuditLog.LOCK_WAIT, full));
        assertEquals(4, lines().size());
        AuditLog.append(log(), new TestClock(T0), AuditEvent.of("export"));
        assertEquals(5, AuditLog.check(log()));
        assertTrue(Files.readString(AuditLog.headOf(log()), StandardCharsets.US_ASCII).startsWith("5 "));
    }

    @Test
    void aLogHeldElsewhereInThisJvmIsBusyAfterTheWait() throws IOException, AuditException, InterruptedException, ExecutionException, TimeoutException {
        // m712-003: the file lock and the JVM-wide turn are both polled up to a deadline, then BUSY.
        write(1);
        Duration wait = Duration.ofMillis(200);
        try (FileChannel channel = FileChannel.open(log(), StandardOpenOption.READ, StandardOpenOption.WRITE);
                FileLock held = channel.lock();
                ExecutorService pool = Executors.newSingleThreadExecutor()) {
            assertTrue(held.isValid());
            long start = System.nanoTime();
            AuditException append = assertThrows(AuditException.class, () -> AuditLog.append(log(),
                    new TestClock(T0), AuditEvent.of("export"), wait, AuditLog::writeHead));
            assertEquals(AuditException.Code.BUSY, append.code());
            assertTrue(System.nanoTime() - start >= wait.toNanos());
            assertEquals(AuditException.Code.BUSY,
                    assertThrows(AuditException.class, () -> AuditLog.check(log(), wait)).code());
            // A writer that waits holds this JVM's turn; a reader meanwhile waits for that turn, then gives up.
            AtomicReference<Thread> writer = new AtomicReference<>();
            Future<?> waiting = pool.submit(() -> {
                writer.set(Thread.currentThread());
                AuditLog.append(log(), new TestClock(T0), AuditEvent.of("export"), Duration.ofSeconds(60),
                        AuditLog::writeHead);
                return null;
            });
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
            while (writer.get() == null || writer.get().getState() != Thread.State.TIMED_WAITING) {
                assertTrue(System.nanoTime() - until < 0, "the writer starts waiting");
                Thread.sleep(1);
            }
            assertEquals(AuditException.Code.BUSY,
                    assertThrows(AuditException.class, () -> AuditLog.check(log(), wait)).code());
            held.release();
            waiting.get(60, TimeUnit.SECONDS);
        }
        assertEquals(2, AuditLog.check(log()), "the waiting writer got its turn once the lock was free");
    }

    @Test
    void aLogArchivedWhileAWriterWaitsIsNotWrittenTo() throws IOException, AuditException, InterruptedException, ExecutionException, TimeoutException {
        // approval-model §7: the user moves both files away while a writer waits for the lock. The
        // writer opened the old file before the move; it must not append to the archived copy.
        write(2);
        Path archive = Files.createDirectory(dir.resolve("archive"));
        try (FileChannel channel = FileChannel.open(log(), StandardOpenOption.READ, StandardOpenOption.WRITE);
                FileLock held = channel.lock();
                ExecutorService pool = Executors.newSingleThreadExecutor()) {
            AtomicReference<Thread> writer = new AtomicReference<>();
            Future<?> waiting = pool.submit(() -> {
                writer.set(Thread.currentThread());
                AuditLog.append(log(), new TestClock(T0), AuditEvent.of("export"), Duration.ofSeconds(60),
                        AuditLog::writeHead);
                return null;
            });
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
            while (writer.get() == null || writer.get().getState() != Thread.State.TIMED_WAITING) {
                assertTrue(System.nanoTime() - until < 0, "the writer starts waiting");
                Thread.sleep(1);
            }
            Files.move(log(), archive.resolve(AuditLog.FILE_NAME));
            Files.move(AuditLog.headOf(log()), archive.resolve(AuditLog.FILE_NAME + ".head"));
            held.release();
            ExecutionException e = assertThrows(ExecutionException.class, () -> waiting.get(60, TimeUnit.SECONDS));
            assertEquals(AuditException.Code.IO, assertInstanceOf(AuditException.class, e.getCause()).code());
        }
        assertEquals(2, AuditLog.check(archive.resolve(AuditLog.FILE_NAME)), "the archived log is unchanged");
        assertFalse(Files.exists(log()));
        AuditLog.append(log(), new TestClock(T0), AuditEvent.of("export"));
        assertEquals(1, AuditLog.check(log()), "a new chain");
    }

    @Test
    void headLaggingByOneAfterACrashIsAccepted() throws IOException, AuditException {
        write(2);
        String head = Files.readString(AuditLog.headOf(log()), StandardCharsets.US_ASCII);
        write(1);
        Files.writeString(AuditLog.headOf(log()), head, StandardCharsets.US_ASCII);
        assertEquals(3, AuditLog.check(log()));
    }

    @Test
    void groupReadableOrLinkedLogIsRefused() throws IOException, AuditException {
        write(1);
        Files.setPosixFilePermissions(log(), PosixFilePermissions.fromString("rw-r-----"));
        assertEquals(AuditException.Code.UNSAFE_FILE, failure(new long[1]));
        Path link = dir.resolve("link.log");
        Files.createSymbolicLink(link, log());
        AuditException e = assertThrows(AuditException.class, () -> AuditLog.open(link, new TestClock(T0)));
        assertEquals(AuditException.Code.UNSAFE_FILE, e.code());
        assertEquals("audit log is a link or is readable by other users", e.userMessage());
    }

    @Test
    void brokerDecisionsLandInTheLogWithoutArgv() throws IOException, AuditException {
        try (AuditLog a = AuditLog.open(log(), new TestClock(T0))) {
            ApprovalBroker broker = new ApprovalBroker(new TestClock(T0), a, PolicyStore.inMemory(), "alice");
            broker.unlock();
            byte[] token = broker.withToken(byte[]::clone);
            CompletableFuture<Outcome> f = broker.submit(Requests.inject(T0, "app", "dev", "DB"), token, Optional.empty());
            broker.pending().get(0).approveOnce();
            assertTrue(f.join().decision().allowed());
            assertEquals(3, a.entries(), "unlock, prompt, approval");
        }
        String text = String.join("", lines().stream()
                .map(s -> new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8)).toList());
        assertTrue(text.contains("ALLOWED_ONCE"));
        assertTrue(text.contains("env"));
        assertFalse(text.contains("npm"), "never the full argv");
    }

    @Test
    void unknownKindIsRefused() throws AuditException {
        try (AuditLog a = AuditLog.open(log(), new TestClock(T0))) {
            assertThrows(IllegalArgumentException.class, () -> a.record(AuditEvent.of("party")));
        }
    }

    @Test
    void lockedAppendsFromManyWritersKeepOneValidChain() throws AuditException {
        write(2); // an existing log, written by a long-lived instance
        try (ExecutorService pool = Executors.newFixedThreadPool(4)) {
            List<Future<?>> done = new ArrayList<>();
            for (int t = 0; t < 4; t++) {
                done.add(pool.submit(() -> {
                    for (int i = 0; i < 10; i++) {
                        try {
                            AuditLog.append(log(), new TestClock(T0), AuditEvent.of("export"));
                        } catch (AuditException e) {
                            throw new IllegalStateException(e.code().name(), e);
                        }
                    }
                }));
            }
            done.forEach(f -> assertDoesNotThrow(() -> f.get()));
        }
        assertEquals(42, AuditLog.check(log()));
        AuditLog.append(dir.resolve("fresh.log"), new TestClock(T0), AuditEvent.of("export"));
        assertEquals(1, AuditLog.check(dir.resolve("fresh.log")), "append creates a missing log");
        assertThrows(IllegalArgumentException.class,
                () -> AuditLog.append(log(), new TestClock(T0), AuditEvent.of("party")));
    }

    @Test
    void readersWritersAndInstancesInOneJvmKeepOneChain() throws AuditException {
        // SR-150: a check closes its own descriptor of the log; it must never do so while another
        // thread holds the file lock, and an open instance must not append from a stale tail.
        try (AuditLog instance = AuditLog.open(log(), new TestClock(T0));
                ExecutorService pool = Executors.newFixedThreadPool(3)) {
            List<Future<?>> done = new ArrayList<>();
            done.add(pool.submit(() -> {
                for (int i = 0; i < 20; i++) {
                    instance.record(AuditEvent.of("lock"));
                }
            }));
            done.add(pool.submit(() -> {
                for (int i = 0; i < 20; i++) {
                    try {
                        AuditLog.append(log(), new TestClock(T0), AuditEvent.of("export"));
                    } catch (AuditException e) {
                        throw new IllegalStateException(e.code().name(), e);
                    }
                }
            }));
            done.add(pool.submit(() -> {
                for (int i = 0; i < 20; i++) {
                    try {
                        assertTrue(AuditLog.check(log()) >= 0);
                    } catch (AuditException e) {
                        throw new IllegalStateException(e.code().name(), e);
                    }
                }
            }));
            done.forEach(f -> assertDoesNotThrow(() -> f.get()));
            assertTrue(instance.entries() >= 20, "the instance counts entries others wrote too");
        }
        assertEquals(40, AuditLog.check(log()));
    }

    @Test
    void anInstanceContinuesTheChainOthersExtended() throws IOException, AuditException {
        try (AuditLog instance = AuditLog.open(log(), new TestClock(T0))) {
            instance.record(AuditEvent.of("unlock"));
            AuditLog.append(log(), new TestClock(T0), AuditEvent.of("pair")); // another writer
            instance.record(AuditEvent.of("lock"));
            assertEquals(3, instance.entries());
            assertEquals(3, AuditLog.check(log()));
            List<String> l = lines();
            l.remove(1);
            rewrite(l);
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> instance.record(AuditEvent.of("lock")));
            assertEquals("AUDIT_WRITE", e.getMessage(), "a broken chain is never extended");
        }
    }

    @Test
    void absentLogChecksAsEmptyAndOversizedOrUnwritableLogsAreRefused() throws IOException, AuditException {
        assertEquals(0, AuditLog.check(dir.resolve("none.log")), "no log and no head: nothing written yet");
        assertFalse(Files.exists(dir.resolve("none.log")), "checking never creates the log");
        write(1);
        try (java.nio.channels.FileChannel ch = java.nio.channels.FileChannel.open(log(),
                java.nio.file.StandardOpenOption.WRITE)) {
            ch.write(java.nio.ByteBuffer.wrap(new byte[] {'\n'}), AuditLog.MAX_FILE_BYTES); // sparse
        }
        AuditException large = assertThrows(AuditException.class, () -> AuditLog.check(log()));
        assertEquals(AuditException.Code.TOO_LARGE, large.code());
        assertEquals("audit log is too large; archive it", large.userMessage());
        Path directory = Files.createDirectory(dir.resolve("dir.log"));
        AuditException e = assertThrows(AuditException.class,
                () -> AuditLog.append(directory, new TestClock(T0), AuditEvent.of("export")));
        assertEquals(AuditException.Code.IO, e.code());
        assertEquals("audit log could not be read or written", e.userMessage());
    }
}
