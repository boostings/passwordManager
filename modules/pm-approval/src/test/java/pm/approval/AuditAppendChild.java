package pm.approval;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * The child program of {@link AuditLogProcessTest}: one separate JVM that appends to a shared audit
 * log, as a {@code pm} CLI command does next to the TUI's broker. It announces itself with a ready
 * file, waits for the go file so that every child appends at the same moment, then appends and
 * prints {@code OK <n>} or {@code FAILED <code> <entry> <i>} on its standard output.
 *
 * <p>Arguments: the log, the number of appends, the ready file, the go file. With {@code hold}
 * instead of a number, it takes the log's exclusive lock, as a pm process stopped in the middle of
 * an append would hold it, creates the ready file, and keeps the lock until the go file appears.
 */
public final class AuditAppendChild {
    /** The second argument that makes the child hold the log's lock instead of appending. */
    static final String HOLD = "hold";
    private static final long WAIT_NANOS = TimeUnit.SECONDS.toNanos(60);

    private AuditAppendChild() {
    }

    /**
     * Runs one writer, or one holder of the lock.
     *
     * @param args the log, the number of appends or {@code hold}, the ready file and the go file
     * @throws IOException if the ready file cannot be created or the log cannot be locked
     * @throws InterruptedException if interrupted while waiting for the go file
     */
    public static void main(String[] args) throws IOException, InterruptedException {
        Path log = Path.of(args[0]);
        if (HOLD.equals(args[1])) {
            try (FileChannel channel = FileChannel.open(log, StandardOpenOption.READ, StandardOpenOption.WRITE);
                    FileLock held = channel.lock()) {
                Objects.requireNonNull(held); // held until the go file appears
                Files.createFile(Path.of(args[2]));
                System.out.println(awaitGo(Path.of(args[3])) ? "RELEASED" : "FAILED NO_GO 0 0");
            }
            return;
        }
        int appends = Integer.parseInt(args[1]);
        Files.createFile(Path.of(args[2]));
        if (!awaitGo(Path.of(args[3]))) {
            System.out.println("FAILED NO_GO 0 0");
            return;
        }
        Clock clock = Clock.fixed(Instant.parse("2026-10-06T12:00:00Z"), ZoneOffset.UTC);
        for (int i = 0; i < appends; i++) {
            try {
                AuditLog.append(log, clock, AuditEvent.of("pair"));
            } catch (AuditException e) {
                System.out.println("FAILED " + e.code() + " " + e.entry() + " " + i);
                return;
            }
        }
        System.out.println("OK " + appends);
    }

    @SuppressWarnings("PMD.DoNotUseThreads") // CE-002: a millisecond poll for the go file; no thread is created
    private static boolean awaitGo(Path go) throws InterruptedException {
        long deadline = System.nanoTime() + WAIT_NANOS;
        while (!Files.exists(go)) {
            if (System.nanoTime() - deadline > 0) {
                return false;
            }
            Thread.sleep(1);
        }
        return true;
    }
}
