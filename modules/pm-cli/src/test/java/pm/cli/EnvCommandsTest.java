package pm.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.locks.LockSupport;
import pm.approval.ApprovalBroker;
import pm.approval.AuditException;
import pm.approval.PendingApproval;
import pm.approval.PolicyStore;
import pm.approval.ipc.BrokerServer;
import pm.approval.ipc.IpcException;
import pm.approval.ipc.RunDir;
import pm.approval.run.EnvRelease;
import pm.domain.env.Env;
import pm.approval.AuditLog;
import pm.crypto.SecretBytes;
import pm.domain.env.DotEnv;
import pm.domain.env.DotEnvException;
import pm.domain.env.EnvEntry;
import pm.domain.env.ProjectEnv;
import pm.vault.record.ProjectRecord;

/** plan.md §13 M2: project and env commands, and the git leakage warnings. */
@SuppressWarnings("PMD.CloseResource") // records stay owned by FakeVaultPort; parsed entries are closed in finally
class EnvCommandsTest {
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final String UNLOCK_PHRASE = "correct horse";
    private static final String VALUE = "pa$$\"word\nline2";

    @TempDir
    Path tmp;

    private Path home;
    private Path repo;
    private final FakeVaultPort port = new FakeVaultPort().withVault(UNLOCK_PHRASE);

    @BeforeEach
    void layout() throws IOException, UsageException {
        home = Files.createDirectory(tmp.resolve("home"));
        // FakeVaultPort writes nothing; a real vault's directory exists once init has run.
        Files.createDirectories(vaultDir());
        repo = Files.createDirectory(tmp.resolve("repo")).toRealPath();
        Files.createDirectory(repo.resolve(".git"));
        Files.writeString(repo.resolve(".git").resolve("config"),
                "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = git@example.com:team/app.git\n",
                StandardCharsets.UTF_8);
    }

    private Path vaultDir() throws UsageException {
        return VaultPaths.defaultPath(Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, home.toString())::get)
                .getParent();
    }

    private int run(FakeConsoleIo io, String... args) {
        return run(repo, io, args);
    }

    private int run(Path cwd, FakeConsoleIo io, String... args) {
        Map<String, String> props = Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, home.toString(),
                "user.dir", cwd.toString(), "user.name", "alice");
        Cli cli = new Cli(props::get, Clock.fixed(NOW, ZoneOffset.UTC), p -> { }).withEnvironment(environment);
        return cli.run(args, io, (path, creating) -> port);
    }

    /** No XDG_RUNTIME_DIR: the run directory would be next to the vault, where no broker is running. */
    private Env environment = Env.of(Map.of());

    private FakeConsoleIo unlocking() {
        return new FakeConsoleIo().secret(UNLOCK_PHRASE);
    }

    private ProjectRecord onlyProject() {
        return ProjectEnv.projects(port.stored).findFirst().orElseThrow();
    }

    private void addProject() {
        assertEquals(ExitCodes.OK, run(unlocking(), "project", "add", "app"));
    }

    private Path envFile(String name, String text) throws IOException {
        return Files.writeString(repo.resolve(name), text, StandardCharsets.UTF_8);
    }

    @Test
    void projectAddRecordsCanonicalDirectoryAndGitRemote() {
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "project", "add", "app"));
        ProjectRecord p = onlyProject();
        assertEquals("app", p.title());
        assertEquals(repo.toString(), p.canonicalPath());
        assertEquals("git@example.com:team/app.git", p.gitRemote());
        assertTrue(io.outText().contains(Messages.PROJECT_ADDED.text() + "app"));
        assertEquals(ExitCodes.USAGE, run(unlocking(), "project", "add", "app"), "duplicate title");
        assertEquals(ExitCodes.USAGE, run(unlocking(), "project", "add", "other"), "same directory twice");
    }

    @Test
    void projectListShowsProfilesNotValues() throws IOException {
        addProject();
        Files.writeString(repo.resolve(".gitignore"), ".env\n", StandardCharsets.UTF_8);
        run(unlocking(), "env", "import", envFile(".env", "DB=" + "sekrit\n").toString(), "--profile", "dev");
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "project", "list"));
        assertTrue(io.outText().contains("app  " + repo + "  dev"));
        assertFalse(io.outText().contains("sekrit"));
    }

    @Test
    void importFindsTheProjectFromASubdirectoryAndListsNamesOnly() throws IOException {
        addProject();
        Files.writeString(repo.resolve(".gitignore"), "*.env\n", StandardCharsets.UTF_8);
        Path sub = Files.createDirectory(repo.resolve("src"));
        Path file = envFile("local.env", "DB_URL=postgres://x\nAPI_KEY=\"" + "abc\"\n");
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(sub, io, "env", "import", file.toString()));
        assertTrue(io.outText().contains(Messages.ENV_IMPORTED.text() + "2 -> app/default"));
        assertFalse(io.errText().contains(Messages.WARN_GIT_NOT_IGNORED.text()), "ignored by *.env");
        assertTrue(io.errText().contains(Messages.WARN_PLAINTEXT_LEFT.text()));

        FakeConsoleIo list = unlocking();
        assertEquals(ExitCodes.OK, run(sub, list, "env", "list"));
        assertTrue(list.outText().contains("API_KEY"));
        assertTrue(list.outText().contains("DB_URL"));
        assertFalse(list.outText().contains("abc"));
        assertFalse(list.outText().contains("postgres"));
    }

    @Test
    void importIntoAGitTreeWithoutAnIgnoreRuleWarns() throws IOException {
        addProject();
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "env", "import", envFile(".env", "A=1\n").toString()));
        assertTrue(io.errText().contains(Messages.WARN_GIT_NOT_IGNORED.text()));
    }

    @Test
    void rejectedFileReportsCodeAndLineButNoContent() throws IOException {
        addProject();
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(io, "env", "import", envFile(".env", "OK=1\nbad line sekrit\n").toString()));
        assertEquals(Messages.ENV_REJECTED.text() + "BAD_NAME at line 2", io.errText().strip());
        assertFalse(io.errText().contains("sekrit"));
    }

    @Test
    void reimportReplacesOnlyThatProfile() throws IOException {
        addProject();
        run(unlocking(), "env", "import", envFile("a.env", "A=1\nB=2\n").toString(), "--profile", "dev");
        run(unlocking(), "env", "import", envFile("b.env", "C=3\n").toString(), "--profile", "prod");
        run(unlocking(), "env", "import", envFile("c.env", "D=4\n").toString(), "--profile", "dev");
        assertEquals(java.util.Set.of("D"), ProjectEnv.variables(onlyProject(), "dev").keySet());
        assertEquals(java.util.Set.of("C"), ProjectEnv.variables(onlyProject(), "prod").keySet());
    }

    @Test
    void exportNeedsPlaintextFlagAndNeverOverwrites() throws IOException {
        addProject();
        Files.writeString(repo.resolve(".gitignore"), "/out/\n", StandardCharsets.UTF_8);
        run(unlocking(), "env", "import", envFile("in.env", "A=1\n").toString());
        Path out = Files.createDirectory(repo.resolve("out")).resolve("x.env");
        FakeConsoleIo refused = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(refused, "env", "export", out.toString()));
        assertEquals(Messages.EXPORT_NEEDS_PLAINTEXT.text(), refused.errText().strip());
        assertFalse(Files.exists(out));

        Files.writeString(out, "keep", StandardCharsets.UTF_8);
        assertEquals(ExitCodes.USAGE, run(new FakeConsoleIo(), "env", "export", out.toString(), "--plaintext"));
        assertEquals("keep", Files.readString(out, StandardCharsets.UTF_8));
    }

    @Test
    void exportRoundTripsEveryByteWithOwnerOnlyModeAndAnAuditEntry() throws IOException, DotEnvException,
            AuditException, UsageException {
        addProject();
        Files.writeString(repo.resolve(".gitignore"), "*.env\n", StandardCharsets.UTF_8);
        String tricky = "A=\"" + VALUE.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$")
                .replace("\n", "\\n") + "\"\nB=plain\n";
        assertEquals(ExitCodes.OK, run(unlocking(), "env", "import", envFile("in.env", tricky).toString()));
        Path out = repo.resolve("out.env");
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "env", "export", out.toString(), "--plaintext"), io.errText());
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(out)));
        assertFalse(io.errText().contains(Messages.WARN_GIT_NOT_IGNORED.text()));
        java.util.List<EnvEntry> back = DotEnv.parse(Files.readAllBytes(out));
        try {
            assertEquals(2, back.size());
            back.get(0).value().withBytes(v -> assertArrayEquals(VALUE.getBytes(StandardCharsets.UTF_8), v));
        } finally {
            back.forEach(EnvEntry::close);
        }
        assertEquals(1, AuditLog.check(vaultDir().resolve(EnvCommands.AUDIT_FILE)));
    }

    @Test
    void anExportRefusedByTheAuditLogSaysWhy() throws IOException, UsageException {
        // m712-002/-003/-004: each audit failure is named; only a plain I/O error keeps the generic text.
        addProject();
        Files.writeString(repo.resolve(".gitignore"), "*.env\n", StandardCharsets.UTF_8);
        assertEquals(ExitCodes.OK, run(unlocking(), "env", "import", envFile("in.env", "A=1\n").toString()));
        Path log = vaultDir().resolve(EnvCommands.AUDIT_FILE);
        Path head = vaultDir().resolve(EnvCommands.AUDIT_FILE + ".head");
        assertEquals(ExitCodes.OK, run(unlocking(), "env", "export", repo.resolve("1.env").toString(), "--plaintext"));
        assertEquals(ExitCodes.OK, run(unlocking(), "env", "export", repo.resolve("2.env").toString(), "--plaintext"));
        Files.writeString(log, Files.readAllLines(log, StandardCharsets.US_ASCII).get(0) + "\n",
                StandardCharsets.US_ASCII); // the last entry cut off
        String broken = exportRefused();
        assertEquals(UsageException.brokenLog(1), broken);
        assertTrue(broken.startsWith("audit log tampered or truncated after entry 1,"), broken);

        Path archive = Files.createDirectory(tmp.resolve("archive")).resolve(EnvCommands.AUDIT_FILE);
        Files.move(log, archive); // only the log, not its head
        assertEquals(UsageException.brokenLog(0), exportRefused());
        assertFalse(Files.exists(log), "no empty log that a second 'mv' could put over the archive");

        Files.delete(head);
        Files.createDirectory(log);
        assertEquals(Messages.AUDIT_UNAVAILABLE.text(), exportRefused(), "a plain I/O failure");
        Files.delete(log);
        Files.writeString(log, "", StandardCharsets.US_ASCII); // the umask's mode, readable by others
        Files.setPosixFilePermissions(log, mode("rw-r--r--"));
        assertEquals(Messages.AUDIT_UNSAFE.text(), exportRefused());
        Files.setPosixFilePermissions(log, PosixFilePermissions.fromString("rw-------"));
        try (FileChannel channel = FileChannel.open(log, StandardOpenOption.WRITE)) {
            channel.write(ByteBuffer.wrap(new byte[] {'\n'}), AuditLog.MAX_FILE_BYTES); // sparse
        }
        assertEquals(Messages.AUDIT_TOO_LARGE.text(), exportRefused());
        Files.writeString(log, "", StandardCharsets.US_ASCII);
        try (FileChannel channel = FileChannel.open(log, StandardOpenOption.READ, StandardOpenOption.WRITE);
                FileLock held = channel.lock()) {
            assertTrue(held.isValid());
            assertEquals(Messages.AUDIT_BUSY.text(), exportRefused(), "after waiting AuditLog.LOCK_WAIT");
        }
        assertEquals(ExitCodes.OK, run(unlocking(), "env", "export", repo.resolve("3.env").toString(), "--plaintext"));
    }

    /** Runs an export the audit log refuses and returns what the user was told. */
    private String exportRefused() {
        Path out = repo.resolve("refused.env");
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.USAGE, run(io, "env", "export", out.toString(), "--plaintext"), io::errText);
        assertFalse(Files.exists(out), "no audit, no export");
        return io.errText().strip();
    }

    @Test
    void noProjectForTheDirectoryIsAUsageError() throws IOException {
        FakeConsoleIo io = new FakeConsoleIo().secret(UNLOCK_PHRASE);
        assertEquals(ExitCodes.USAGE, run(io, "env", "list"));
        assertEquals(Messages.NO_PROJECT_HERE.text(), io.errText().strip());
        assertEquals(ExitCodes.USAGE, run(new FakeConsoleIo().secret(UNLOCK_PHRASE), "env", "list", "--project", "nope"));
        assertEquals(ExitCodes.USAGE, run(new FakeConsoleIo(), "env", "list", "--profile", "Bad Name"));
        assertEquals(ExitCodes.USAGE, run(new FakeConsoleIo(), "env", "frobnicate"));
    }

    @Test
    void writerOutputParsesBackToTheSameValues() throws DotEnvException {
        SortedMap<String, SecretBytes> vars = new TreeMap<>();
        byte[] ascii = new byte[0x7f - 0x20 + 3];
        for (int i = 0; i < 0x7f - 0x20; i++) {
            ascii[i] = (byte) (0x20 + i);
        }
        ascii[ascii.length - 3] = '\t';
        ascii[ascii.length - 2] = '\n';
        ascii[ascii.length - 1] = '\r';
        vars.put("ASCII", SecretBytes.copyOf(ascii));
        vars.put("UNI", SecretBytes.copyOf("h\u00e9llo w\u00f6rld \u2713".getBytes(StandardCharsets.UTF_8)));
        vars.put("EMPTY", SecretBytes.copyOf(new byte[0]));
        try (SecretBytes file = DotEnvWriter.format(vars)) {
            java.util.List<EnvEntry> back = file.apply(EnvCommandsTest::parseOrFail);
            try {
                assertEquals(3, back.size());
                for (EnvEntry e : back) {
                    e.value().withBytes(v -> vars.get(e.name()).withBytes(w -> assertArrayEquals(w, v, e.name())));
                }
            } finally {
                back.forEach(EnvEntry::close);
            }
        } finally {
            vars.values().forEach(SecretBytes::close);
        }
    }

    @Test
    void writerRefusesBytesTheParserCannotReadBack() {
        SortedMap<String, SecretBytes> vars = new TreeMap<>();
        vars.put("BELL", SecretBytes.copyOf(new byte[] {'a', 0x07}));
        try {
            assertThrows(IllegalArgumentException.class, () -> DotEnvWriter.format(vars).close());
        } finally {
            vars.values().forEach(SecretBytes::close);
        }
    }

    private static java.util.List<EnvEntry> parseOrFail(byte[] b) {
        try {
            return DotEnv.parse(b);
        } catch (DotEnvException e) {
            throw new IllegalStateException(e.code().name() + "@" + e.line(), e);
        }
    }

    // ---- env run ----------------------------------------------------------------------------

    private static final String SH = "/bin/sh";
    private static final String PRINT_DB = "printf '%s' \"$DB\" > \"$0\"";

    private void importDev() throws IOException {
        addProject();
        Files.writeString(repo.resolve(".gitignore"), "*.env\n", StandardCharsets.UTF_8);
        run(unlocking(), "env", "import", envFile("dev.env", "DB=from-vault\nOTHER=x\n").toString(), "--profile", "dev");
    }

    @Test
    void standaloneRunShowsTheExactArgvAndRunsItAfterY() throws IOException {
        assumeTrue(Files.isExecutable(Path.of(SH)), "needs /bin/sh as the child program");
        importDev();
        Path out = repo.resolve("db.txt");
        FakeConsoleIo io = unlocking().line("y");
        int code = run(io, "env", "run", "--profile", "dev", "--only", "DB", "--", SH, "-c", PRINT_DB, out.toString());
        assertEquals(0, code, io.errText());
        assertEquals("from-vault", Files.readString(out, StandardCharsets.UTF_8));
        String shown = io.outText();
        assertTrue(shown.contains("  \"" + SH + "\"\n  \"-c\"\n  \"" + PRINT_DB + "\"\n  \"" + out + "\""), shown);
        assertTrue(shown.contains(Messages.RUN_VARIABLES.text() + "DB\n"));
        assertFalse(shown.contains("from-vault"));
    }

    @Test
    void standaloneRunWithoutYRunsNothing() throws IOException {
        importDev();
        Path out = repo.resolve("db.txt");
        FakeConsoleIo io = unlocking().line("yes");
        assertEquals(ExitCodes.DENIED, run(io, "env", "run", "--profile", "dev", "--", SH, "-c", PRINT_DB, out.toString()));
        assertFalse(Files.exists(out));
        assertEquals(ExitCodes.USAGE, run(new FakeConsoleIo(), "env", "run", "--profile", "dev"), "no command");
        assertEquals(ExitCodes.USAGE, run(unlocking(), "env", "run", "--profile", "dev", "--only", "NOPE", "--", SH),
                "--only names a missing variable");
    }

    @Test
    void runThroughARunningBrokerUsesTheApprovedArgv() throws IOException, IpcException, UsageException {
        assumeTrue(Files.isExecutable(Path.of(SH)), "needs /bin/sh as the child program");
        importDev();
        Path xdg = Files.createDirectory(tmp.resolve("xdg"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        environment = Env.of(Map.of("XDG_RUNTIME_DIR", xdg.toString()));
        RunDir dir = RunDir.prepare(RunDir.locate(environment, vaultDir()));
        ApprovalBroker broker = new ApprovalBroker(Clock.fixed(NOW, ZoneOffset.UTC), e -> { }, PolicyStore.inMemory(),
                System.getProperty("user.name"));
        Path out = repo.resolve("db.txt");
        List<String> argv = List.of(SH, "-c", PRINT_DB, out.toString());
        try (BrokerServer server = BrokerServer.start(dir, broker, g -> EnvRelease.release(g, List.copyOf(port.stored)))) {
            server.unlocked();
            FakeConsoleIo io = new FakeConsoleIo(); // no passphrase: the TUI holds the unlocked vault
            List<String> args = new java.util.ArrayList<>(List.of("env", "run", "--project", "app", "--profile", "dev",
                    "--"));
            args.addAll(argv);
            CompletableFuture<Integer> code = CompletableFuture.supplyAsync(() -> run(io, args.toArray(String[]::new)));
            long deadline = System.nanoTime() + java.time.Duration.ofSeconds(10).toNanos();
            while (broker.pending().isEmpty()) {
                assertTrue(System.nanoTime() < deadline, "no prompt arrived");
                LockSupport.parkNanos(java.time.Duration.ofMillis(10).toNanos());
            }
            PendingApproval prompt = broker.pending().get(0);
            assertEquals(argv, prompt.request().display().argv(), "the prompt shows the command line as typed");
            prompt.approveOnce();
            assertEquals(0, code.join(), io.errText());
        }
        assertEquals("from-vault", Files.readString(out, StandardCharsets.UTF_8));
    }

    @Test
    void deniedBrokerRequestRunsNothing() throws IOException, IpcException, UsageException {
        importDev();
        Path xdg = Files.createDirectory(tmp.resolve("xdg"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        environment = Env.of(Map.of("XDG_RUNTIME_DIR", xdg.toString()));
        RunDir dir = RunDir.prepare(RunDir.locate(environment, vaultDir()));
        ApprovalBroker broker = new ApprovalBroker(Clock.fixed(NOW, ZoneOffset.UTC), e -> { }, PolicyStore.inMemory(),
                System.getProperty("user.name"));
        Path out = repo.resolve("db.txt");
        try (BrokerServer server = BrokerServer.start(dir, broker, g -> EnvRelease.release(g, List.copyOf(port.stored)))) {
            server.unlocked();
            FakeConsoleIo io = new FakeConsoleIo();
            CompletableFuture<Integer> code = CompletableFuture.supplyAsync(() -> run(io, "env", "run", "--project", "app",
                    "--profile", "dev", "--", SH, "-c", PRINT_DB, out.toString()));
            long deadline = System.nanoTime() + java.time.Duration.ofSeconds(10).toNanos();
            while (broker.pending().isEmpty()) {
                assertTrue(System.nanoTime() < deadline, "no prompt arrived");
                LockSupport.parkNanos(java.time.Duration.ofMillis(10).toNanos());
            }
            broker.pending().get(0).deny();
            assertEquals(ExitCodes.DENIED, code.join());
            assertEquals(Messages.RUN_DENIED.text() + "DENIED", io.errText().strip());
        }
        assertFalse(Files.exists(out));
    }

    @Test
    void gitignoreRulesAreMatchedLikeGit() {
        Path root = Path.of("/r");
        assertTrue(GitGuard.matches(".env", Path.of("a/b/.env")));
        assertTrue(GitGuard.matches("*.env", Path.of("x.env")));
        assertTrue(GitGuard.matches("secrets/", Path.of("secrets/x.env")));
        assertFalse(GitGuard.matches("secrets/", Path.of("secrets")), "dir-only rule vs a file");
        assertTrue(GitGuard.matches("/out", Path.of("out/x.env")));
        assertFalse(GitGuard.matches("/out", Path.of("a/out/x.env")), "anchored at the ignore file's directory");
        assertFalse(GitGuard.matches(".env", Path.of(".env.example")));
        assertEquals(root, root.resolve("x").getParent());
    }

    /** A mode from its text; the audit log tests need a loose one on purpose. */
    private static java.util.Set<java.nio.file.attribute.PosixFilePermission> mode(String mode) {
        return PosixFilePermissions.fromString(mode);
    }
}
