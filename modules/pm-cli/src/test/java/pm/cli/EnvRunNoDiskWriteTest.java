package pm.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.approval.AuditLog;
import pm.crypto.Argon2Params;
import pm.crypto.Csprng;
import pm.domain.env.Env;

/**
 * plan.md §13 M2 exit criterion "env run never writes to disk", over the real vault stack: a
 * file-backed vault holds a profile, then {@code pm env run} injects it into a child. Every file
 * under the test's home, repository and vault directories is fingerprinted before and after the
 * run. The only change allowed is the audit log entry (the log and its head sidecar), and no file anywhere under those roots, or
 * created in {@code java.io.tmpdir} during the run, may contain the injected value. The CI Linux job
 * repeats this test under {@code strace} ({@code tools/ci/env-run-trace.sh}) to catch files that
 * are created and deleted again, which a before/after snapshot cannot see.
 */
class EnvRunNoDiskWriteTest {
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final String UNLOCK_PHRASE = "no-disk-write unlock phrase";
    private static final String SH = "/bin/sh";
    /** Fails unless the injected variable has exactly the imported length; prints nothing. */
    private static final String CHECK = "[ \"${#DB_TOKEN}\" -eq \"$1\" ]";
    private static final int SECRET_HEX_BYTES = 16;
    /** Marker the CI trace script looks for, so it can bound the run phase in the syscall log. */
    static final String TRACE_MARKER = "pm-env-run-trace-marker";

    @TempDir
    Path tmp;

    @Test
    void envRunChangesNothingOnDiskButOneAuditEntry() throws IOException, NoSuchAlgorithmException, UsageException {
        assumeTrue(Files.isExecutable(Path.of(SH)), "needs /bin/sh as the child program");
        String injected = "nodisk-" + HexFormat.of().formatHex(Csprng.bytes(SECRET_HEX_BYTES));
        Path home = Files.createDirectory(tmp.resolve("home"));
        Path repo = Files.createDirectory(tmp.resolve("repo")).toRealPath();
        Files.writeString(repo.resolve(".gitignore"), "*.env\n", StandardCharsets.UTF_8);

        assertEquals(ExitCodes.OK, run(home, repo, new FakeConsoleIo().secret(UNLOCK_PHRASE).secret(UNLOCK_PHRASE), "init"));
        assertEquals(ExitCodes.OK, run(home, repo, unlocking(), "project", "add", "app"));
        Path source = Files.writeString(repo.resolve("dev.env"), "DB_TOKEN=" + injected + "\n", StandardCharsets.UTF_8);
        assertEquals(ExitCodes.OK, run(home, repo, unlocking(), "env", "import", source.toString(), "--profile", "dev"));
        Files.delete(source); // the plaintext the user imported is not the runner's doing

        Path vaultDir = Objects.requireNonNull(VaultPaths.defaultPath(props(home, repo)::get).getParent(), "vault dir");
        // The log and its head sidecar (a hash of the last entry, AuditLog) take the run's entry.
        Set<Path> audit = Set.of(vaultDir.resolve(AuditLog.FILE_NAME), vaultDir.resolve(AuditLog.FILE_NAME + ".head"));
        SortedMap<Path, String> before = fingerprints(tmp);
        Instant started = Instant.now();
        mark(".start");

        FakeConsoleIo io = unlocking().line("y");
        int code = run(home, repo, io, "env", "run", "--profile", "dev", "--", SH, "-c", CHECK, SH,
                Integer.toString(injected.length()));

        mark(".end");
        assertEquals(0, code, io.errText());
        SortedMap<Path, String> after = fingerprints(tmp);
        Set<Path> changed = Stream.concat(before.keySet().stream(), after.keySet().stream())
                .filter(p -> !Objects.equals(before.get(p), after.get(p)))
                .collect(Collectors.toSet());
        assertEquals(audit, changed, "only the audit log may change");
        assertNoFileContains(tmp, injected);
        assertNoNewTempFileContains(Path.of(System.getProperty("java.io.tmpdir")), started, injected);
        assertFalse(io.outText().contains(injected) || io.errText().contains(injected), "the terminal shows no value");
    }

    /** Creates and removes a marker file, so the trace shows where the run starts and ends. */
    private void mark(String suffix) throws IOException {
        Files.delete(Files.writeString(tmp.resolve(TRACE_MARKER + suffix), "", StandardCharsets.US_ASCII));
    }

    private static Map<String, String> props(Path home, Path cwd) {
        return Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, home.toString(),
                "user.dir", cwd.toString(), "user.name", "alice");
    }

    private static FakeConsoleIo unlocking() {
        return new FakeConsoleIo().secret(UNLOCK_PHRASE);
    }

    /** One invocation through a new {@link Cli} and a new real file-backed port. */
    private static int run(Path home, Path cwd, FakeConsoleIo io, String... args) {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        Cli cli = new Cli(props(home, cwd)::get, clock, p -> { }).withEnvironment(Env.of(Map.of()));
        return cli.run(args, io,
                (path, creating) -> new FileVaultPort(path, clock, Cli.kdfFor(creating, () -> Argon2Params.FLOOR)));
    }

    private static SortedMap<Path, String> fingerprints(Path root) throws IOException, NoSuchAlgorithmException {
        SortedMap<Path, String> out = new TreeMap<>();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        try (Stream<Path> files = Files.walk(root)) {
            for (Path p : files.filter(Files::isRegularFile).toList()) {
                out.put(p, HexFormat.of().formatHex(sha.digest(Files.readAllBytes(p))));
            }
        }
        return out;
    }

    private static void assertNoFileContains(Path root, String injected) throws IOException {
        try (Stream<Path> files = Files.walk(root)) {
            for (Path p : files.filter(Files::isRegularFile).toList()) {
                assertFalse(contains(p, injected), () -> p + " holds the secret");
            }
        }
    }

    private static void assertNoNewTempFileContains(Path dir, Instant since, String injected) throws IOException {
        try (Stream<Path> files = Files.list(dir)) {
            for (Path p : files.filter(Files::isRegularFile).filter(Files::isReadable).toList()) {
                assertFalse(newAndContains(p, since, injected), () -> p + " holds the secret");
            }
        }
    }

    /**
     * Whether {@code p} was written at or after {@code since} and holds {@code injected}. The temp
     * directory is shared with every other process of the user, which create and delete short-lived
     * files there (a JVM attach handshake leaves {@code .attach_pid<n>} for a moment); one that is
     * gone by the time it is read cannot be a file this run left behind.
     */
    private static boolean newAndContains(Path p, Instant since, String injected) throws IOException {
        try {
            return !Files.getLastModifiedTime(p).toInstant().isBefore(since) && contains(p, injected);
        } catch (NoSuchFileException e) {
            return false;
        }
    }

    private static boolean contains(Path p, String injected) throws IOException {
        return new String(Files.readAllBytes(p), StandardCharsets.ISO_8859_1).contains(injected);
    }
}
