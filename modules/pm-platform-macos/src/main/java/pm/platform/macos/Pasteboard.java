package pm.platform.macos;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * The macOS general pasteboard, through {@code /usr/bin/pbcopy} and {@code /usr/bin/pbpaste}
 * (SR-503). Process adapters live in the platform modules (plan.md §10; ArchUnit
 * {@code onlyTheEnvRunnerSpawnsProcesses}). The tools are started by absolute path with a fixed
 * argument list, never through a shell or {@code PATH}, and with {@code LC_ALL=en_US.UTF-8} so that
 * both read and write UTF-8 text. Every call has a deadline, after which the tool is killed; the
 * caller's thread never waits longer.
 *
 * <p>Secret residue: the bytes written to {@code pbcopy} pass through the JDK's buffered pipe
 * stream, and the bytes read from {@code pbpaste} through its pipe buffer; neither buffer can be
 * zeroed from here (R-003, ADR 0008). Every array this class allocates itself is zeroed.
 */
public final class Pasteboard {
    /**
     * Most bytes {@link #read} returns: one more than the largest secret a record holds (64 KiB),
     * so a pasteboard that returns this many holds something pm did not put there.
     */
    public static final int MAX_READ = 64 * 1024 + 1;

    static final Path PBCOPY = Path.of("/usr/bin/pbcopy");
    static final Path PBPASTE = Path.of("/usr/bin/pbpaste");
    static final Duration DEADLINE = Duration.ofSeconds(3);
    private static final String UTF8_LOCALE = "en_US.UTF-8";
    private static final long POLL_MILLIS = 10;

    private final List<String> copyCommand;
    private final List<String> pasteCommand;
    private final Duration deadline;

    Pasteboard(List<String> copyCommand, List<String> pasteCommand, Duration deadline) {
        this.copyCommand = List.copyOf(copyCommand);
        this.pasteCommand = List.copyOf(pasteCommand);
        this.deadline = Objects.requireNonNull(deadline, "deadline");
    }

    /** The general pasteboard, when both tools are installed (they ship with macOS). */
    public static Optional<Pasteboard> system() {
        if (Files.isExecutable(PBCOPY) && Files.isExecutable(PBPASTE)) {
            return Optional.of(new Pasteboard(List.of(PBCOPY.toString()), List.of(PBPASTE.toString()), DEADLINE));
        }
        return Optional.empty();
    }

    /**
     * Replaces the pasteboard's contents with {@code utf8} as text.
     *
     * @param utf8 the text; not kept, and not zeroed (the caller owns it)
     * @return whether {@code pbcopy} took it and exited with 0 before the deadline
     */
    public boolean copy(byte[] utf8) {
        Objects.requireNonNull(utf8, "utf8");
        Process process;
        try {
            process = start(copyCommand, ProcessBuilder.Redirect.DISCARD);
        } catch (IOException e) {
            return false;
        }
        try (OutputStream in = process.getOutputStream()) {
            in.write(utf8);
        } catch (IOException e) {
            process.destroyForcibly();
            return false;
        }
        return exitedCleanly(process);
    }

    /** Empties the pasteboard, by copying no text. Returns whether that worked. */
    public boolean clear() {
        return copy(new byte[0]);
    }

    /**
     * The pasteboard's text: at most {@link #MAX_READ} bytes, which the caller zeroes. Empty when
     * {@code pbpaste} cannot be started, fails, or does not finish before the deadline. A
     * pasteboard without text reads as zero bytes.
     */
    public Optional<byte[]> read() {
        Process process;
        try {
            process = start(pasteCommand, ProcessBuilder.Redirect.PIPE);
            process.getOutputStream().close();
        } catch (IOException e) {
            return Optional.empty();
        }
        byte[] buffer = new byte[MAX_READ];
        try {
            return collect(process, buffer);
        } catch (IOException e) {
            process.destroyForcibly();
            return Optional.empty();
        } finally {
            Arrays.fill(buffer, (byte) 0);
        }
    }

    /** Reads what the tool writes while it runs, so a full pipe never stalls it. */
    @SuppressWarnings("PMD.DoNotUseThreads") // CE-088: reads the interrupt flag; no thread is made
    private Optional<byte[]> collect(Process process, byte[] buffer) throws IOException {
        long end = System.nanoTime() + deadline.toNanos();
        try (InputStream out = process.getInputStream()) {
            int filled = 0;
            while (true) {
                filled += out.readNBytes(buffer, filled, Math.min(out.available(), buffer.length - filled));
                if (filled == buffer.length) {
                    process.destroyForcibly(); // more than any secret: not pm's copy
                    return Optional.of(Arrays.copyOf(buffer, filled));
                }
                if (waitFor(process, POLL_MILLIS)) {
                    filled += out.readNBytes(buffer, filled, buffer.length - filled);
                    return process.exitValue() == 0 ? Optional.of(Arrays.copyOf(buffer, filled)) : Optional.empty();
                }
                if (Thread.currentThread().isInterrupted() || System.nanoTime() - end > 0) {
                    process.destroyForcibly();
                    return Optional.empty();
                }
            }
        }
    }

    private boolean exitedCleanly(Process process) {
        if (waitFor(process, deadline.toMillis())) {
            return process.exitValue() == 0;
        }
        process.destroyForcibly();
        return false;
    }

    /** Waits up to {@code millis} for {@code process}; an interrupt kills it and is kept. */
    @SuppressWarnings("PMD.DoNotUseThreads") // CE-088: re-asserts the interrupt flag; no thread is made
    private static boolean waitFor(Process process, long millis) {
        try {
            return process.waitFor(millis, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return false;
        }
    }

    private static Process start(List<String> command, ProcessBuilder.Redirect output) throws IOException {
        ProcessBuilder builder = new ProcessBuilder(command)
                .redirectOutput(output)
                .redirectError(ProcessBuilder.Redirect.DISCARD);
        builder.environment().put("LC_ALL", UTF8_LOCALE);
        return builder.start();
    }
}
