package pm.approval;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.approval.run.EnvRunner;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;
import pm.vault.cbor.CborValue;

/**
 * approval-model §7, SR-150: writers in separate processes (the TUI's broker and CLI commands, or
 * two CLI commands on vaults in one folder) keep one chain in a shared audit log. Every child is a
 * real JVM running {@link AuditAppendChild}. It is started through {@link EnvRunner}, the one class
 * allowed to spawn processes: SR-100's ArchUnit rule skips test classes, but the semgrep rule
 * IDS07-J forbids {@code new ProcessBuilder} in tests too, and the runner is the sanctioned path.
 */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: a millisecond poll for the children's ready files
class AuditLogProcessTest {
    private static final int WRITERS = 4;
    private static final int APPENDS = 25;
    private static final long WAIT_SECONDS = 60;
    private static final Instant T0 = Instant.parse("2026-10-06T12:00:00Z");

    @TempDir
    Path dir;

    private static Optional<Path> javaLauncher() {
        Path bin = Path.of(System.getProperty("java.home"), "bin");
        return List.of(bin.resolve("java"), bin.resolve("java.exe")).stream().filter(Files::isExecutable).findFirst();
    }

    /** The test JVM's own class path (and module path, if any) as one argument file for the children. */
    private Path argFile() throws IOException {
        StringBuilder cp = new StringBuilder(System.getProperty("java.class.path", ""));
        String modules = System.getProperty("jdk.module.path", "");
        if (!modules.isEmpty()) {
            cp.append(File.pathSeparatorChar).append(modules);
        }
        String quoted = cp.toString().replace("\\", "\\\\").replace("\"", "\\\"");
        Path args = dir.resolve("child.args");
        Files.writeString(args, "-cp \"" + quoted + "\"\n", StandardCharsets.UTF_8);
        return args;
    }

    private static ApprovalRequest command(List<String> argv) {
        return new ApprovalRequest(UUID.randomUUID(), new ApprovalRequest.Requester(ApprovalRequest.Kind.CLI, "test"),
                ApprovalRequest.Operation.ENV_INJECT, new ApprovalRequest.Scope("app", "dev", Optional.empty(), List.of()),
                Duration.ZERO, new ApprovalRequest.Display(argv, Optional.empty(), ApprovalRequest.Effect.INJECT), T0);
    }

    private void awaitReady(List<Path> ready) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS);
        while (!ready.stream().allMatch(Files::exists)) {
            assertTrue(System.nanoTime() - deadline < 0, "every child starts");
            Thread.sleep(1);
        }
    }

    @Test
    void writersInSeparateProcessesKeepOneChain()
            throws IOException, InterruptedException, AuditException, CborException {
        Optional<Path> java = javaLauncher();
        assumeTrue(java.isPresent(), "needs the test JVM's java launcher for the child processes");
        Path log = dir.resolve(AuditLog.FILE_NAME);
        AuditLog.append(log, Clock.fixed(T0, ZoneOffset.UTC), AuditEvent.of("unlock")); // an existing log
        Path args = argFile();
        Path go = dir.resolve("go");
        List<Process> children = new ArrayList<>();
        List<Path> ready = new ArrayList<>();
        List<Path> outputs = new ArrayList<>();
        for (int i = 0; i < WRITERS; i++) {
            ready.add(dir.resolve("ready-" + i));
            outputs.add(dir.resolve("out-" + i));
            List<String> argv = List.of(java.orElseThrow().toString(), "@" + args, AuditAppendChild.class.getName(),
                    log.toString(), Integer.toString(APPENDS), ready.get(i).toString(), go.toString());
            children.add(EnvRunner.start(command(argv), new TreeMap<>(), Set.of(), dir,
                    ProcessBuilder.Redirect.to(outputs.get(i).toFile())));
        }
        try {
            awaitReady(ready);
            Files.createFile(go); // all children append at once
            for (Process child : children) {
                assertTrue(child.waitFor(WAIT_SECONDS, TimeUnit.SECONDS), "every child finishes");
                assertEquals(0, child.exitValue());
            }
        } finally {
            children.forEach(Process::destroyForcibly); // none outlives the test, even when it fails
        }
        List<String> said = new ArrayList<>();
        for (Path out : outputs) {
            said.add(Files.readString(out, StandardCharsets.UTF_8).strip());
        }
        List<String> lines = Files.readAllLines(log, StandardCharsets.US_ASCII);
        assertEquals(lines.size(), distinctSeqs(lines), "a seq appears twice, so the chain forked; children: " + said);
        assertEquals(Collections.nCopies(WRITERS, "OK " + APPENDS), said,
                "no child saw a broken chain or failed to write");
        assertEquals(1 + WRITERS * APPENDS, AuditLog.check(log), "one chain, no fork");
    }

    @Test
    void aLogHeldByAnotherProcessIsBusyAfterTheWaitAndNothingIsWritten()
            throws IOException, InterruptedException, AuditException {
        // m712-003: a pm process stopped while holding the lock (Ctrl-Z) must not hang every other one.
        Optional<Path> java = javaLauncher();
        assumeTrue(java.isPresent(), "needs the test JVM's java launcher for the child process");
        Path log = dir.resolve(AuditLog.FILE_NAME);
        Clock clock = Clock.fixed(T0, ZoneOffset.UTC);
        AuditLog.append(log, clock, AuditEvent.of("unlock"));
        byte[] before = Files.readAllBytes(log);
        Path ready = dir.resolve("ready-holder");
        Path release = dir.resolve("release");
        List<String> argv = List.of(java.orElseThrow().toString(), "@" + argFile(), AuditAppendChild.class.getName(),
                log.toString(), AuditAppendChild.HOLD, ready.toString(), release.toString());
        Process holder = EnvRunner.start(command(argv), new TreeMap<>(), Set.of(), dir,
                ProcessBuilder.Redirect.to(dir.resolve("out-holder").toFile()));
        try {
            awaitReady(List.of(ready));
            Duration wait = Duration.ofMillis(300);
            long start = System.nanoTime();
            AuditException append = assertThrows(AuditException.class,
                    () -> AuditLog.append(log, clock, AuditEvent.of("export"), wait, AuditLog::writeHead));
            assertEquals(AuditException.Code.BUSY, append.code());
            assertTrue(System.nanoTime() - start >= wait.toNanos(), "it waited the whole time first");
            assertEquals("the audit log is in use by another pm process; try again", append.userMessage());
            AuditException check = assertThrows(AuditException.class, () -> AuditLog.check(log, wait));
            assertEquals(AuditException.Code.BUSY, check.code());
            Files.createFile(release);
            assertTrue(holder.waitFor(WAIT_SECONDS, TimeUnit.SECONDS), "the holder lets go");
        } finally {
            holder.destroyForcibly();
        }
        assertEquals("RELEASED", Files.readString(dir.resolve("out-holder"), StandardCharsets.UTF_8).strip());
        // Read only once the holder is gone: a Windows file lock is mandatory, so reading the locked
        // log fails there. The holder writes nothing, so any change would be from the refused calls.
        assertArrayEquals(before, Files.readAllBytes(log), "nothing was written while busy");
        AuditLog.append(log, clock, AuditEvent.of("export"));
        assertEquals(2, AuditLog.check(log), "the log is usable again once the holder is gone");
    }

    private static int distinctSeqs(List<String> lines) throws CborException {
        Set<Long> seqs = new HashSet<>();
        for (String line : lines) {
            CborValue.MapV entry = (CborValue.MapV) CborReader.decode(Base64.getDecoder().decode(line),
                    new CborLimits(4, 64, 1024, 8 * 1024));
            seqs.add(((CborValue.UInt) entry.entries().get("seq")).value());
        }
        return seqs.size();
    }
}
