package pm.approval;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
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
}
