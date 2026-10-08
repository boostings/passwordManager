package pm.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.approval.AuditLog;
import pm.domain.env.Env;
import pm.tui.SshActions;
import pm.vault.record.SshKeyRecord;

/**
 * plan.md §13 M4.4: {@code pm ssh import/list/add/remove/export} against a test ssh-agent on a
 * Unix socket in an owner-only directory, with keys generated per run. Every release of a private
 * key (agent or file) is audited first, with the key's public fingerprint and never its title; a
 * release that fails is audited again as {@code FAILED}.
 */
@SuppressWarnings("PMD.CloseResource") // CE-045: records stay owned by FakeVaultPort, which closes them on lock
class SshCommandsTest {
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final String UNLOCK_PHRASE = "correct horse";
    private static final String TITLE = "deploy key";

    @TempDir
    Path tmp;

    private Path home;
    private Path work;
    private Path sock;
    private TestSshAgent agent;
    private final FakeVaultPort port = new FakeVaultPort().withVault(UNLOCK_PHRASE);
    private final SshTestKeys.Key key = SshTestKeys.ed25519("alice@laptop");

    @BeforeEach
    void layout() throws IOException, UsageException {
        home = Files.createDirectory(tmp.resolve("home"));
        Files.createDirectories(java.util.Objects.requireNonNull(vaultPath().getParent()));
        work = Files.createDirectory(tmp.resolve("work")).toRealPath();
        Path dir = Files.createDirectory(tmp.resolve("a"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        sock = dir.resolve("s");
        agent = TestSshAgent.start(sock);
        Files.write(work.resolve("id_ed25519"), key.file());
    }

    @AfterEach
    void stop() throws IOException {
        agent.close();
        assertEquals(List.of(), agent.errors);
    }

    private Path vaultPath() throws UsageException {
        return VaultPaths.defaultPath(props()::get);
    }

    private Map<String, String> props() {
        return Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, home.toString(),
                "user.dir", work == null ? home.toString() : work.toString(), "user.name", "alice");
    }

    private Env env() {
        Map<String, String> vars = new HashMap<>();
        vars.put("SSH_AUTH_SOCK", sock.toString());
        return Env.of(vars);
    }

    private int run(Env env, FakeConsoleIo io, String... args) {
        Cli cli = new Cli(props()::get, Clock.fixed(NOW, ZoneOffset.UTC), p -> { }).withEnvironment(env);
        return cli.run(args, io, (path, creating) -> port);
    }

    private int run(FakeConsoleIo io, String... args) {
        return run(env(), io, args);
    }

    private FakeConsoleIo unlocking() {
        return new FakeConsoleIo().secret(UNLOCK_PHRASE);
    }

    private SshKeyRecord imported() {
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "ssh", "import", "id_ed25519", "--title", TITLE), io::errText);
        return (SshKeyRecord) port.stored.get(port.stored.size() - 1);
    }

    private String audit() throws IOException, UsageException {
        Path log = java.util.Objects.requireNonNull(vaultPath().getParent()).resolve(AuditLog.FILE_NAME);
        if (!Files.exists(log)) {
            return "";
        }
        // Entries are base64 CBOR; decode each field so field values can be searched.
        StringBuilder text = new StringBuilder();
        for (String field : Files.readString(log, StandardCharsets.US_ASCII).split("[\\s:,]+", -1)) {
            try {
                text.append(new String(java.util.Base64.getDecoder().decode(field), StandardCharsets.ISO_8859_1))
                        .append('\n');
            } catch (IllegalArgumentException e) {
                text.append(field).append('\n');
            }
        }
        return text.toString();
    }

    @Test
    void importStoresTheKeyAndRefusesADuplicate() {
        SshKeyRecord record = imported();
        assertEquals(TITLE, record.title());
        assertEquals("ssh-ed25519", record.keyType());
        assertTrue(record.fingerprint().startsWith("SHA256:"), record.fingerprint());
        assertEquals("alice@laptop", record.comment());
        assertTrue(record.publicKey().startsWith("ssh-ed25519 "), record.publicKey());
        FakeConsoleIo again = unlocking();
        assertEquals(ExitCodes.USAGE, run(again, "ssh", "import", "id_ed25519"));
        assertTrue(again.errText().contains(Messages.SSH_KEY_EXISTS.text()), again::errText);
        assertEquals(1, port.stored.size());
    }

    @Test
    void importDefaultsTheTitleToTheComment() throws IOException {
        Files.setPosixFilePermissions(work.resolve("id_ed25519"), PosixFilePermissions.fromString("rw-------"));
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "ssh", "import", "id_ed25519"), io::errText);
        assertEquals("alice@laptop", port.stored.get(0).title());
        assertTrue(io.outText().contains(Messages.SSH_IMPORTED.text() + "alice@laptop  SHA256:"), io::outText);
        assertTrue(io.errText().contains(Messages.SSH_DELETE_ORIGINAL.text()), io::errText);
        assertFalse(io.errText().contains(Messages.SSH_KEY_FILE_SHARED.text()), "an owner-only file draws no warning");
    }

    @Test
    void importWarnsWhenOthersCanReadTheKeyFile() throws IOException {
        Files.setPosixFilePermissions(work.resolve("id_ed25519"), PosixFilePermissions.fromString("rw-r-----"));
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "ssh", "import", "id_ed25519"), io::errText);
        assertTrue(io.errText().contains(Messages.SSH_KEY_FILE_SHARED.text()), io::errText);
    }

    @Test
    void importRefusesDirectoriesAndOversizedFiles() throws IOException {
        Files.createDirectory(work.resolve("dir"));
        FakeConsoleIo dir = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(dir, "ssh", "import", "dir"));
        assertTrue(dir.errText().contains(Messages.SSH_KEY_FILE_UNREADABLE.text()), dir::errText);

        Files.write(work.resolve("big"), new byte[pm.crypto.ssh.SshKey.MAX_FILE_BYTES + 1]);
        FakeConsoleIo big = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(big, "ssh", "import", "big"));
        assertTrue(big.errText().contains(Messages.SSH_KEY_FILE_UNREADABLE.text()), big::errText);

        Files.write(work.resolve("exact"), new byte[pm.crypto.ssh.SshKey.MAX_FILE_BYTES]);
        FakeConsoleIo exact = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(exact, "ssh", "import", "exact"));
        assertTrue(exact.errText().contains(Messages.SSH_MALFORMED_KEY.text()), "read in full, then parsed");
        assertTrue(port.stored.isEmpty());
    }

    @Test
    void importRefusesMalformedMissingAndLinkedFiles() throws IOException {
        Files.writeString(work.resolve("junk"), "not a key\n", StandardCharsets.US_ASCII);
        FakeConsoleIo junk = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(junk, "ssh", "import", "junk"));
        assertTrue(junk.errText().contains(Messages.SSH_MALFORMED_KEY.text()), junk::errText);
        assertEquals(0, junk.secretsRead(), "a bad key is refused before the vault is unlocked");

        FakeConsoleIo missing = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(missing, "ssh", "import", "absent"));
        assertTrue(missing.errText().contains(Messages.SSH_KEY_FILE_UNREADABLE.text()), missing::errText);

        Files.createSymbolicLink(work.resolve("link"), work.resolve("id_ed25519"));
        FakeConsoleIo link = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(link, "ssh", "import", "link"));
        assertTrue(link.errText().contains(Messages.SSH_KEY_FILE_UNREADABLE.text()), link::errText);
        assertTrue(port.stored.isEmpty());
    }

    @Test
    void addWithConstraintsThenListThenRemove() throws IOException, UsageException {
        SshKeyRecord record = imported();
        FakeConsoleIo add = unlocking();
        assertEquals(ExitCodes.OK, run(add, "ssh", "add", TITLE, "--lifetime", "1h", "--confirm"), add::errText);
        assertTrue(add.outText().contains(Messages.SSH_ADDED.text() + TITLE), add::outText);
        assertEquals(1, agent.held.size());
        TestSshAgent.Held held = agent.held.get(0);
        assertArrayEquals(key.blob(), held.blob());
        assertEquals(3600, held.lifetime());
        assertTrue(held.confirm());
        assertEquals(List.of(TestSshAgent.ADD_CONSTRAINED), agent.requestTypes);

        FakeConsoleIo list = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(list, "ssh", "list"), list::errText);
        assertTrue(list.outText().contains(record.fingerprint()), list::outText);
        assertTrue(list.outText().contains("alice@laptop"), list::outText);
        assertEquals(0, list.secretsRead(), "listing the agent does not unlock the vault");

        FakeConsoleIo remove = unlocking();
        assertEquals(ExitCodes.OK, run(remove, "ssh", "remove", record.id().toString()), remove::errText);
        assertTrue(agent.held.isEmpty());
        FakeConsoleIo again = unlocking();
        assertEquals(ExitCodes.USAGE, run(again, "ssh", "remove", TITLE));
        assertTrue(again.errText().contains(Messages.SSH_NOT_IN_AGENT.text()), again::errText);

        FakeConsoleIo empty = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(empty, "ssh", "list"));
        assertTrue(empty.outText().contains(Messages.SSH_AGENT_EMPTY.text()), empty::outText);

        String log = audit();
        assertTrue(log.contains("ssh-agent " + record.fingerprint()), "the audit tells keys apart: " + log);
        assertTrue(log.contains(SshCommands.RELEASED), log);
        assertFalse(log.contains(TITLE), log);
    }

    @Test
    void agentFieldsArePrintedSafely() {
        byte[] blob = new SshTestKeys.W().str("ssh-\u001b[2J\u001b]0;PWNED\u0007").str(new byte[32]).bytes();
        agent.held.add(new TestSshAgent.Held(blob, new byte[0], "evil\u001b[31m", 0, false));
        FakeConsoleIo list = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(list, "ssh", "list"), list::errText);
        assertFalse(list.outText().chars().anyMatch(c -> c == 0x1b || c == 0x07), list::outText);
        assertTrue(list.outText().contains("PWNED"), list::outText);
    }

    @Test
    void aStalledAgentEndsInABoundedError() throws IOException, UsageException, pm.vault.VaultException {
        Path dir = Files.createDirectory(tmp.resolve("b"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path stalled = dir.resolve("s");
        try (ServerSocketChannel silent = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            silent.bind(UnixDomainSocketAddress.of(stalled)); // never accepts, never answers
            SshCommands commands = new SshCommands(props()::get, Clock.fixed(NOW, ZoneOffset.UTC),
                    Env.of(Map.of("SSH_AUTH_SOCK", stalled.toString())), Duration.ofMillis(200));
            FakeConsoleIo io = new FakeConsoleIo();
            long start = System.nanoTime();
            assertEquals(ExitCodes.EXTERNAL, commands.run(List.of("list"), port, io, vaultPath()));
            assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(5)) < 0);
            assertTrue(io.errText().contains(Messages.SSH_TIMEOUT.text()), io::errText);

            SshKeyRecord record = imported();
            CliSshActions actions = new CliSshActions(commands, vaultPath());
            assertEquals(SshActions.Outcome.AGENT_TIMEOUT, actions.add(record.privateKey(), Duration.ZERO, false));
            String log = audit();
            assertTrue(log.contains(SshCommands.RELEASE_FAILED), "a release that did not happen says so: " + log);
        }
    }

    @Test
    void plainAddSendsNoConstraintsAndRemoveAllClearsTheAgent() {
        imported();
        FakeConsoleIo add = unlocking();
        assertEquals(ExitCodes.OK, run(add, "ssh", "add", TITLE), add::errText);
        assertEquals(List.of(TestSshAgent.ADD_IDENTITY), agent.requestTypes);
        FakeConsoleIo all = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(all, "ssh", "remove", "--all"), all::errText);
        assertTrue(all.outText().contains(Messages.SSH_REMOVED_ALL.text()));
        assertTrue(agent.held.isEmpty());
        assertEquals(ExitCodes.USAGE, run(new FakeConsoleIo(), "ssh", "remove", "--all", TITLE));
    }

    @Test
    void lifetimesAreParsedStrictly() throws UsageException {
        assertEquals(Duration.ofSeconds(90), SshCommands.constraints(java.util.Optional.of("90"), false).lifetime());
        assertEquals(Duration.ofMinutes(5), SshCommands.constraints(java.util.Optional.of("5m"), false).lifetime());
        assertEquals(Duration.ofDays(2), SshCommands.constraints(java.util.Optional.of("2d"), true).lifetime());
        imported();
        for (String bad : List.of("0", "1w", "-5", "99999999999", "1.5h", "30000d")) {
            FakeConsoleIo io = unlocking();
            assertEquals(ExitCodes.USAGE, run(io, "ssh", "add", TITLE, "--lifetime", bad), bad);
            assertTrue(io.errText().contains(Messages.SSH_BAD_LIFETIME.text()), bad);
        }
        assertTrue(agent.held.isEmpty());
    }

    @Test
    void unknownAndAmbiguousItemsAreRefused() {
        imported();
        FakeConsoleIo none = unlocking();
        assertEquals(ExitCodes.USAGE, run(none, "ssh", "add", "nope"));
        assertTrue(none.errText().contains(Messages.SSH_NO_SUCH_KEY.text()), none::errText);
        SshKeyRecord first = (SshKeyRecord) port.stored.get(0);
        SshTestKeys.Key other = SshTestKeys.ed25519("bob@desk");
        port.stored.add(new SshKeyRecord(java.util.UUID.randomUUID(), TITLE, "ssh-ed25519",
                pm.crypto.SecretBytes.copyOf(other.file()), first.publicKey(), "SHA256:other", "bob@desk",
                List.of(), NOW, NOW));
        FakeConsoleIo two = unlocking();
        assertEquals(ExitCodes.USAGE, run(two, "ssh", "add", TITLE));
        assertTrue(two.errText().contains(Messages.SSH_AMBIGUOUS_KEY.text()), two::errText);
        FakeConsoleIo byId = unlocking();
        assertEquals(ExitCodes.OK, run(byId, "ssh", "add", first.id().toString()), byId::errText);
    }

    @Test
    void noAgentIsReportedClearly() {
        Env unset = Env.of(Map.of());
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.EXTERNAL, run(unset, io, "ssh", "list"), "unset is the same failure as absent");
        assertTrue(io.errText().contains(Messages.SSH_NO_AGENT.text()), io::errText);

        Env gone = Env.of(Map.of("SSH_AUTH_SOCK", sock.resolveSibling("missing").toString()));
        FakeConsoleIo none = new FakeConsoleIo();
        assertEquals(ExitCodes.EXTERNAL, run(gone, none, "ssh", "list"));
        assertTrue(none.errText().contains(Messages.SSH_NO_AGENT.text()), none::errText);
    }

    @Test
    void exportWritesAnOwnerOnlyFileAndNeverOverwrites() throws IOException, UsageException {
        imported();
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "ssh", "export", TITLE, "out_key"), io::errText);
        Path out = work.resolve("out_key");
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(out)));
        assertTrue(Files.readString(out, StandardCharsets.US_ASCII).startsWith("-----BEGIN " + SshTestKeys.ARMOUR_KIND),
                "an OpenSSH private key file");
        assertTrue(io.outText().contains("0600"), io::outText);
        assertTrue(audit().contains("ssh-key-file SHA256:"));
        assertFalse(audit().contains(SshCommands.RELEASE_FAILED));

        byte[] before = Files.readAllBytes(out);
        FakeConsoleIo again = unlocking();
        assertEquals(ExitCodes.USAGE, run(again, "ssh", "export", TITLE, "out_key"));
        assertTrue(again.errText().contains(Messages.SSH_EXPORT_EXISTS.text()), again::errText);
        assertEquals(0, again.secretsRead(), "refused before unlocking");
        assertArrayEquals(before, Files.readAllBytes(out));
        Files.delete(out);
    }

    @Test
    void exportToAMissingFolderIsAUsageErrorBeforeUnlocking() throws IOException, UsageException {
        imported();
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.USAGE, run(io, "ssh", "export", TITLE, "nowhere/out_key"));
        assertTrue(io.errText().contains(Messages.SSH_EXPORT_NO_DIR.text()), io::errText);
        assertEquals(0, io.secretsRead());
        assertFalse(audit().contains("ssh-key-file"), "nothing was released, so nothing is audited");
    }

    @Test
    void anExportRefusedByABrokenAuditLogSaysWhereItBroke() throws IOException, UsageException {
        // m712-002: the specific reason, with the last intact entry, instead of the generic text.
        imported();
        Path log = java.util.Objects.requireNonNull(vaultPath().getParent()).resolve(AuditLog.FILE_NAME);
        Files.writeString(log, "not a log\n", StandardCharsets.US_ASCII);
        Files.setPosixFilePermissions(log, PosixFilePermissions.fromString("rw-------"));
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.USAGE, run(io, "ssh", "export", TITLE, "out_key"));
        assertEquals(UsageException.brokenLog(0), io.errText().strip());
        assertFalse(Files.exists(work.resolve("out_key")), "no audit, no export");
    }

    @Test
    void aFailedExportIsAuditedAsFailed() throws IOException, UsageException {
        imported();
        Path locked = Files.createDirectory(work.resolve("ro"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("r-x------")));
        FakeConsoleIo io = unlocking();
        int exit = run(io, "ssh", "export", TITLE, "ro/out_key");
        assertTrue(exit == ExitCodes.EXTERNAL || exit == ExitCodes.USAGE, io::errText);
        assertFalse(Files.exists(locked.resolve("out_key")));
        String log = audit();
        assertTrue(log.contains(SshCommands.RELEASED) && log.contains(SshCommands.RELEASE_FAILED), log);
    }

    @Test
    void wrongShapesAreUsageErrors() {
        for (String[] args : new String[][] {{"ssh"}, {"ssh", "frob"}, {"ssh", "add"}, {"ssh", "list", "x"},
            {"ssh", "export", TITLE}, {"ssh", "add", TITLE, "--lifetime"}, {"ssh", "import", "a", "b"}}) {
            FakeConsoleIo io = new FakeConsoleIo();
            assertEquals(ExitCodes.USAGE, run(io, args), String.join(" ", args));
        }
        assertTrue(agent.requestTypes.isEmpty());
    }

    @Test
    void tuiAdapterMapsEveryOutcome() throws IOException, UsageException {
        SshKeyRecord record = imported();
        SshCommands commands = new SshCommands(props()::get, Clock.fixed(NOW, ZoneOffset.UTC), env());
        CliSshActions actions = new CliSshActions(commands, vaultPath());
        assertEquals(SshActions.Outcome.ADDED, actions.add(record.privateKey(), Duration.ofHours(1), true));
        assertEquals(3600, agent.held.get(0).lifetime());
        assertEquals(SshActions.Outcome.REMOVED, actions.remove(record.privateKey()));
        assertEquals(SshActions.Outcome.NOT_IN_AGENT, actions.remove(record.privateKey()));
        assertEquals(SshActions.Outcome.AGENT_FAILED, actions.add(record.privateKey(), Duration.ofSeconds(-1), false));
        assertTrue(actions.executor() != null);

        SshKeyRecord broken = new SshKeyRecord(java.util.UUID.randomUUID(), "broken", "ssh-ed25519",
                pm.crypto.SecretBytes.copyOf("junk".getBytes(StandardCharsets.US_ASCII)), record.publicKey(),
                "SHA256:x", "", List.of(), NOW, NOW);
        assertEquals(SshActions.Outcome.BAD_KEY, actions.add(broken.privateKey(), Duration.ZERO, false));
        broken.close();

        CliSshActions unset = new CliSshActions(
                new SshCommands(props()::get, Clock.fixed(NOW, ZoneOffset.UTC), Env.of(Map.of())), vaultPath());
        assertEquals(SshActions.Outcome.NO_AGENT, unset.add(record.privateKey(), Duration.ZERO, false));
        assertEquals(SshActions.Outcome.NO_AGENT, unset.remove(record.privateKey()));
        assertTrue(audit().contains("TUI"), "the TUI release is audited");
    }

    @Test
    void everySshFailureHasAMessageAndAnExitCode() {
        for (pm.crypto.ssh.SshException.Code code : pm.crypto.ssh.SshException.Code.values()) {
            assertFalse(SshCommands.messageFor(code).text().isEmpty(), code::name);
            int exit = SshCommands.exitFor(code);
            assertTrue(exit == ExitCodes.USAGE || exit == ExitCodes.EXTERNAL, code::name);
            CliSshActions.outcome(code);
        }
    }
}
