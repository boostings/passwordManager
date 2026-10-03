package pm.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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
import pm.approval.AuditException;
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
        Cli cli = new Cli(props::get, Clock.fixed(NOW, ZoneOffset.UTC), p -> { });
        return cli.run(args, io, (path, creating) -> port);
    }

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
}
