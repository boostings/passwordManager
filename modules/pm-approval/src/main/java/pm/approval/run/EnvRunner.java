package pm.approval.run;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.SortedMap;
import pm.approval.ApprovalRequest;
import pm.crypto.SecretBoundary;
import pm.crypto.SecretBytes;

/**
 * Runs the command of an approved {@code env-inject} request (approval-model §6, SR-102). The argv
 * comes only from {@link ApprovalRequest.Display#argv()}, the same list the prompt showed, and goes
 * straight to {@link ProcessBuilder}: no shell, no temp file. The child gets the parent environment
 * minus the scrubbed names, plus the approved variables.
 *
 * <p>This is the one class in the code base that builds processes (M2.7 ArchUnit rule).
 */
public final class EnvRunner {
    /** Exit code when the command could not be started (as a shell reports "not found"). */
    public static final int NOT_STARTED = 127;
    /** Exit code when pm was interrupted while waiting (as a shell reports SIGINT). */
    public static final int INTERRUPTED = 130;

    private EnvRunner() {
    }

    /**
     * Starts the request's command with {@code vars} injected. Values become {@code String}s only
     * inside {@link ProcessBuilder#environment()}, which takes nothing else (documented secret
     * boundary, R-009); the builder is unreachable once this returns.
     *
     * @param scrub parent variables to remove first (the profile's names)
     * @param dir working directory of the child
     * @param stdout where the child's standard output goes; stdin and stderr are inherited
     * @throws IllegalArgumentException {@code NOT_ENV_INJECT} for another operation,
     *     {@code NOT_APPROVED} if {@code vars} names a variable outside the request's scope
     * @throws IOException if the program cannot be started
     */
    @SecretBoundary(reason = "ProcessBuilder.environment() is a Map<String, String>; an injected "
            + "variable can only reach the child as a String (approval-model §6, R-009). The Strings "
            + "live in the builder's map, which nothing references after start() returns.")
    public static Process start(ApprovalRequest request, SortedMap<String, SecretBytes> vars, Set<String> scrub,
            Path dir, ProcessBuilder.Redirect stdout) throws IOException {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(vars, "vars");
        Objects.requireNonNull(scrub, "scrub");
        Objects.requireNonNull(dir, "dir");
        Objects.requireNonNull(stdout, "stdout");
        if (request.operation() != ApprovalRequest.Operation.ENV_INJECT) {
            throw new IllegalArgumentException("NOT_ENV_INJECT");
        }
        boolean inScope = request.scope().vars().map(approved -> approved.containsAll(vars.keySet())).orElse(true);
        if (!inScope) {
            throw new IllegalArgumentException("NOT_APPROVED");
        }
        ProcessBuilder builder = new ProcessBuilder(request.display().argv());
        builder.directory(dir.toFile());
        Map<String, String> env = builder.environment();
        scrub.forEach(env::remove);
        vars.forEach((name, value) -> env.put(name, value.apply(b -> new String(b, StandardCharsets.UTF_8))));
        builder.redirectInput(ProcessBuilder.Redirect.INHERIT);
        builder.redirectError(ProcessBuilder.Redirect.INHERIT);
        builder.redirectOutput(stdout);
        return builder.start();
    }

    /**
     * Runs the command attached to this terminal and returns its exit code: the child's own,
     * {@link #NOT_STARTED} or {@link #INTERRUPTED}.
     */
    @SuppressWarnings("PMD.DoNotUseThreads") // CE-002: re-asserting the interrupt flag is not thread creation
    public static int run(ApprovalRequest request, SortedMap<String, SecretBytes> vars, Set<String> scrub, Path dir) {
        Process child;
        try {
            child = start(request, vars, scrub, dir, ProcessBuilder.Redirect.INHERIT);
        } catch (IOException e) {
            return NOT_STARTED;
        }
        try {
            return child.waitFor();
        } catch (InterruptedException e) {
            child.destroy();
            Thread.currentThread().interrupt();
            return INTERRUPTED;
        }
    }
}
