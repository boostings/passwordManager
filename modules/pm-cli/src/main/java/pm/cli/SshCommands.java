package pm.cli;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import pm.approval.AuditEvent;
import pm.approval.AuditException;
import pm.approval.AuditLog;
import pm.crypto.Csprng;
import pm.crypto.SecretBytes;
import pm.crypto.ssh.AgentConstraints;
import pm.crypto.ssh.AgentIdentity;
import pm.crypto.ssh.SshAgentClient;
import pm.crypto.ssh.SshException;
import pm.crypto.ssh.SshKey;
import pm.crypto.ssh.SshKeyExport;
import pm.domain.env.Env;
import pm.tui.Session;
import pm.tui.VaultPort;
import pm.vault.VaultException;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;

/**
 * {@code pm ssh ...} (plan.md §13 M4.4, ADR 0013): SSH keys stored in the vault reach SSH through
 * the user's own {@code ssh-agent}.
 *
 * <pre>
 * pm ssh import &lt;file&gt; [--title T]     store an unencrypted OpenSSH key as an SSH key item
 * pm ssh list                            identities the agent holds
 * pm ssh add &lt;item&gt; [--lifetime 1h] [--confirm]
 * pm ssh remove &lt;item&gt; | --all
 * pm ssh export &lt;item&gt; &lt;file&gt;           explicit fallback: an owner-only (0600) key file
 * </pre>
 *
 * <p>An item is an SSH key record named by its exact title or its id. Private key bytes are only
 * ever handled by {@code pm.crypto.ssh} ({@link SshKey}, {@link SshAgentClient},
 * {@link SshKeyExport}), which only {@code pm.cli} may use (SR-060). The agent socket comes from
 * {@code SSH_AUTH_SOCK} through {@link Env} and is checked by the client (SR-061); an unset
 * {@code SSH_AUTH_SOCK} is the same "no agent" failure (exit 9) as a socket nobody listens on. Every
 * agent call has the client's deadline ({@link SshAgentClient#DEFAULT_TIMEOUT}), so a stalled agent
 * ends in exit 9, not a hang. Adding a key to the agent and exporting it are audited before the key
 * leaves the vault; no audit, no release (approval-model §7). A release that then fails is audited
 * again with the decision {@code FAILED}. Messages are catalogue entries; everything the agent
 * sends and every title is passed through {@link Cli#displaySafe} before it is printed (SR-501).
 */
@SuppressWarnings("PMD.CloseResource") // CE-045: records stay owned by the session, which closes them on lock (ADR 0008)
final class SshCommands {
    static final String TITLE = "--title";
    static final String LIFETIME = "--lifetime";
    static final String CONFIRM = "--confirm";
    static final String ALL = "--all";
    static final String AUDIT_TARGET_AGENT = "ssh-agent";
    static final String AUDIT_TARGET_FILE = "ssh-key-file";
    static final String RELEASED = "ALLOWED_ONCE";
    static final String RELEASE_FAILED = "FAILED";

    private static final String GAP = "  ";
    private static final long SECONDS_PER_MINUTE = 60;
    private static final long SECONDS_PER_HOUR = 3_600;
    private static final long SECONDS_PER_DAY = 86_400;
    /** Seconds, or a number with an s, m, h or d unit, as {@code ssh-add -t} takes it. */
    private static final Pattern LIFETIME_FORMAT = Pattern.compile("([0-9]{1,10})([smhd]?)");

    private final UnaryOperator<String> properties;
    private final Clock clock;
    private final Env environment;
    private final Duration agentTimeout;

    SshCommands(UnaryOperator<String> properties, Clock clock, Env environment) {
        this(properties, clock, environment, SshAgentClient.DEFAULT_TIMEOUT);
    }

    /** As above, with the agent deadline given (tests use a short one). */
    SshCommands(UnaryOperator<String> properties, Clock clock, Env environment, Duration agentTimeout) {
        this.properties = Objects.requireNonNull(properties, "properties");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.environment = Objects.requireNonNull(environment, "environment");
        this.agentTimeout = Objects.requireNonNull(agentTimeout, "agentTimeout");
    }

    /** Runs {@code pm ssh <sub>}; the vault is opened only by subcommands that need it. */
    int run(List<String> sub, VaultPort port, ConsoleIo io, Path vaultPath) throws UsageException, VaultException {
        if (sub.isEmpty()) {
            throw new UsageException(Messages.WRONG_ARG_COUNT);
        }
        List<String> rest = sub.subList(1, sub.size());
        try {
            return switch (sub.get(0)) {
                case "import" -> importKey(CommandArgs.parse(rest, Set.of(), Set.of(TITLE)).arity(1), port, io);
                case "list" -> {
                    CommandArgs.parse(rest, Set.of(), Set.of()).arity(0);
                    yield list(io);
                }
                case "add" -> add(CommandArgs.parse(rest, Set.of(CONFIRM), Set.of(LIFETIME)).arity(1), port, io,
                        vaultPath);
                case "remove" -> remove(CommandArgs.parse(rest, Set.of(ALL), Set.of()), port, io);
                case "export" -> export(CommandArgs.parse(rest, Set.of(), Set.of()).arity(2), port, io, vaultPath);
                default -> throw new UsageException(Messages.UNKNOWN_COMMAND);
            };
        } catch (SshException e) {
            io.err().println(messageFor(e.code()).text());
            return exitFor(e.code());
        }
    }

    // ---- subcommands -------------------------------------------------------------------------

    private int importKey(CommandArgs args, VaultPort port, ConsoleIo io)
            throws UsageException, VaultException, SshException {
        SshKeyRecord record = newRecord(args.value(TITLE), readKeyFile(resolve(args.operand(0)), io));
        try (Session session = Cli.unlock(port, io)) {
            store(session, record);
        } catch (UsageException | VaultException | RuntimeException e) {
            record.close(); // idempotent; a record the session took is closed again on lock
            throw e;
        }
        io.out().println(Messages.SSH_IMPORTED.text() + Cli.displaySafe(record.title()) + GAP + record.fingerprint());
        io.err().println(Messages.SSH_DELETE_ORIGINAL.text());
        return ExitCodes.OK;
    }

    /**
     * Parses {@code text} as a key (refusing encrypted, unsupported and malformed files) and builds
     * the record around it. The record owns {@code text}; on any failure it is closed here.
     */
    private SshKeyRecord newRecord(Optional<String> title, SecretBytes text) throws UsageException, SshException {
        try (SshKey key = SshKey.parse(text)) {
            String name = title.orElse(key.comment().isEmpty() ? key.fingerprint() : key.comment()).strip();
            Instant now = clock.instant();
            return new SshKeyRecord(Csprng.uuid(), name, key.type().wireName(), text,
                    key.publicKeyLine(), key.fingerprint(), key.comment(), List.of(), now, now);
        } catch (IllegalArgumentException e) {
            text.close();
            throw new UsageException(Messages.INVALID_RECORD);
        } catch (SshException e) {
            text.close();
            throw e;
        }
    }

    /** Puts and saves {@code record} unless a key with its fingerprint is already stored. */
    private static void store(Session session, SshKeyRecord record) throws UsageException, VaultException {
        boolean duplicate = session.records().stream().filter(SshKeyRecord.class::isInstance)
                .map(SshKeyRecord.class::cast).anyMatch(k -> k.fingerprint().equals(record.fingerprint()));
        if (duplicate) {
            throw new UsageException(Messages.SSH_KEY_EXISTS);
        }
        session.put(record);
        session.save();
    }

    private int list(ConsoleIo io) throws UsageException, SshException {
        try (SshAgentClient agent = connect()) {
            List<AgentIdentity> ids = agent.list();
            io.out().println(Messages.SSH_LIST_HEADER.text());
            for (AgentIdentity id : ids) {
                io.out().println(String.join(GAP, Cli.displaySafe(id.fingerprint()), Cli.displaySafe(id.type()),
                        Cli.displaySafe(id.comment())));
            }
            if (ids.isEmpty()) {
                io.out().println(Messages.SSH_AGENT_EMPTY.text());
            }
        }
        return ExitCodes.OK;
    }

    private int add(CommandArgs args, VaultPort port, ConsoleIo io, Path vaultPath)
            throws UsageException, VaultException, SshException {
        AgentConstraints constraints = constraints(args.value(LIFETIME), args.has(CONFIRM));
        try (SshAgentClient agent = connect(); Session session = Cli.unlock(port, io)) {
            SshKeyRecord record = find(session.records(), args.operand(0));
            try (SshKey key = SshKey.parse(record.privateKey())) {
                release(vaultPath, "CLI", AUDIT_TARGET_AGENT, key.fingerprint(), () -> agent.add(key, constraints));
                io.out().println(Messages.SSH_ADDED.text() + Cli.displaySafe(record.title()) + GAP + key.fingerprint());
            }
        }
        return ExitCodes.OK;
    }

    private int remove(CommandArgs args, VaultPort port, ConsoleIo io)
            throws UsageException, VaultException, SshException {
        if (args.has(ALL)) {
            args.arity(0);
            try (SshAgentClient agent = connect()) {
                agent.removeAll();
            }
            io.out().println(Messages.SSH_REMOVED_ALL.text());
            return ExitCodes.OK;
        }
        args.arity(1);
        try (SshAgentClient agent = connect(); Session session = Cli.unlock(port, io)) {
            SshKeyRecord record = find(session.records(), args.operand(0));
            try (SshKey key = SshKey.parse(record.privateKey())) {
                agent.remove(key);
            } catch (SshException e) {
                if (e.code() == SshException.Code.AGENT_REFUSED) {
                    throw new UsageException(Messages.SSH_NOT_IN_AGENT);
                }
                throw e;
            }
            io.out().println(Messages.SSH_REMOVED.text() + Cli.displaySafe(record.title()));
        }
        return ExitCodes.OK;
    }

    private int export(CommandArgs args, VaultPort port, ConsoleIo io, Path vaultPath)
            throws UsageException, VaultException, SshException {
        Path target = resolve(args.operand(1));
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new UsageException(Messages.SSH_EXPORT_EXISTS);
        }
        Path folder = target.getParent();
        if (folder == null || !Files.isDirectory(folder)) {
            throw new UsageException(Messages.SSH_EXPORT_NO_DIR);
        }
        try (Session session = Cli.unlock(port, io)) {
            SshKeyRecord record = find(session.records(), args.operand(0));
            try (SshKey key = SshKey.parse(record.privateKey())) {
                release(vaultPath, "CLI", AUDIT_TARGET_FILE, key.fingerprint(), () -> SshKeyExport.write(key, target));
            }
        }
        io.out().println(Messages.SSH_EXPORTED.text());
        if (GitGuard.atRisk(target)) {
            io.err().println(Messages.WARN_GIT_NOT_IGNORED.text());
        }
        return ExitCodes.OK;
    }

    // ---- shared with the TUI adapter ---------------------------------------------------------

    /**
     * Connects to the agent named by {@code SSH_AUTH_SOCK}; the client checks the socket (SR-061).
     * An unset variable is {@link SshException.Code#NO_AGENT}, like a socket nobody listens on.
     */
    SshAgentClient connect() throws SshException {
        Optional<Path> socket = environment.path(Env.Var.SSH_AUTH_SOCK);
        if (socket.isEmpty()) {
            throw new SshException(SshException.Code.NO_AGENT);
        }
        return SshAgentClient.connect(socket.get(), agentTimeout);
    }

    /** One release of a private key: to the agent or to a file. */
    @FunctionalInterface
    interface Release {
        /** Sends the key on its way. */
        void run() throws SshException;
    }

    /**
     * Audits, then runs {@code release}; an audit failure stops the release (approval-model §7). If
     * the release then fails, a second entry with the decision {@code FAILED} records that the key
     * did not go out, and the release's own failure is rethrown.
     */
    void release(Path vaultPath, String requester, String target, String fingerprint, Release release)
            throws UsageException, SshException {
        audit(vaultPath, requester, target, fingerprint, RELEASED);
        try {
            release.run();
        } catch (SshException | RuntimeException e) {
            try {
                audit(vaultPath, requester, target, fingerprint, RELEASE_FAILED);
            } catch (UsageException auditFailed) {
                e.addSuppressed(auditFailed); // the release's own failure is what the user sees
            }
            throw e;
        }
    }

    /**
     * Appends an {@code export} entry. The schema has no field for a key, so {@code argv0} carries
     * where the key went and its public SHA-256 fingerprint ({@code "ssh-agent SHA256:..."}): enough
     * to tell keys apart, and not secret. No title, comment or private byte is logged.
     */
    void audit(Path vaultPath, String requester, String target, String fingerprint, String decision)
            throws UsageException {
        Path dir = Objects.requireNonNull(vaultPath.toAbsolutePath().getParent(), "vault dir");
        try {
            AuditLog.append(dir.resolve(AuditLog.FILE_NAME), clock, new AuditEvent("export", Optional.empty(),
                    Optional.of(requester), Optional.ofNullable(properties.apply("user.name")), Optional.empty(),
                    Optional.empty(), 1, Optional.of(decision), Optional.of(target + " " + fingerprint)));
        } catch (AuditException e) {
            throw new UsageException(Messages.AUDIT_UNAVAILABLE);
        }
    }

    /**
     * The SSH key record named {@code item}: its id, or else its exact title.
     *
     * @throws UsageException if none or more than one matches
     */
    static SshKeyRecord find(List<VaultRecord> records, String item) throws UsageException {
        List<SshKeyRecord> keys = records.stream().filter(SshKeyRecord.class::isInstance)
                .map(SshKeyRecord.class::cast).toList();
        List<SshKeyRecord> byId = keys.stream().filter(k -> k.id().toString().equals(item)).toList();
        List<SshKeyRecord> matches = byId.isEmpty() ? keys.stream().filter(k -> k.title().equals(item)).toList() : byId;
        if (matches.isEmpty()) {
            throw new UsageException(Messages.SSH_NO_SUCH_KEY);
        }
        List<SshKeyRecord> others = matches.subList(1, matches.size());
        if (!others.isEmpty()) {
            throw new UsageException(Messages.SSH_AMBIGUOUS_KEY);
        }
        return matches.get(0);
    }

    /**
     * Agent constraints from {@code --lifetime} ({@code 90}, {@code 90s}, {@code 15m}, {@code 8h},
     * {@code 1d}) and {@code --confirm}; at most {@link AgentConstraints#MAX_LIFETIME_SECONDS}.
     */
    static AgentConstraints constraints(Optional<String> lifetime, boolean confirm) throws UsageException {
        Duration life = Duration.ZERO;
        if (lifetime.isPresent()) {
            life = Duration.ofSeconds(lifetimeSeconds(lifetime.get()));
        }
        return new AgentConstraints(life, confirm);
    }

    private static long lifetimeSeconds(String text) throws UsageException {
        Matcher m = LIFETIME_FORMAT.matcher(text.strip());
        if (!m.matches()) {
            throw new UsageException(Messages.SSH_BAD_LIFETIME);
        }
        long unit = switch (m.group(2)) {
            case "m" -> SECONDS_PER_MINUTE;
            case "h" -> SECONDS_PER_HOUR;
            case "d" -> SECONDS_PER_DAY;
            default -> 1;
        };
        long seconds = Long.parseLong(m.group(1)) * unit; // at most 10 digits times 86,400: no overflow
        if (seconds < 1 || seconds > AgentConstraints.MAX_LIFETIME_SECONDS) {
            throw new UsageException(Messages.SSH_BAD_LIFETIME);
        }
        return seconds;
    }

    /** Catalogue text for an SSH failure; never the exception's own message (SR-501). */
    static Messages messageFor(SshException.Code code) {
        return switch (code) {
            case MALFORMED_KEY -> Messages.SSH_MALFORMED_KEY;
            case ENCRYPTED_KEY -> Messages.SSH_ENCRYPTED_KEY;
            case UNSUPPORTED_KEY -> Messages.SSH_UNSUPPORTED_KEY;
            case NO_AGENT -> Messages.SSH_NO_AGENT;
            case UNSAFE_SOCKET -> Messages.SSH_UNSAFE_SOCKET;
            case AGENT_REFUSED -> Messages.SSH_AGENT_REFUSED;
            case BAD_REPLY -> Messages.SSH_BAD_REPLY;
            case TIMEOUT -> Messages.SSH_TIMEOUT;
            case TARGET_EXISTS -> Messages.SSH_EXPORT_EXISTS;
            case UNSAFE_TARGET -> Messages.SSH_UNSAFE_TARGET;
            case IO -> Messages.SSH_IO;
        };
    }

    /** Key and target problems are the user's input (2); agent and I/O failures are external (9). */
    static int exitFor(SshException.Code code) {
        return switch (code) {
            case MALFORMED_KEY, ENCRYPTED_KEY, UNSUPPORTED_KEY, TARGET_EXISTS, UNSAFE_TARGET -> ExitCodes.USAGE;
            case NO_AGENT, UNSAFE_SOCKET, AGENT_REFUSED, BAD_REPLY, TIMEOUT, IO -> ExitCodes.EXTERNAL;
        };
    }

    // ---- files -------------------------------------------------------------------------------

    private Path resolve(String arg) throws UsageException {
        try {
            Path cwd = Path.of(Objects.requireNonNull(properties.apply("user.dir"), "user.dir"));
            return cwd.resolve(arg).toAbsolutePath().normalize();
        } catch (InvalidPathException e) {
            throw new UsageException(Messages.INVALID_TEXT);
        }
    }

    /**
     * Reads a key file of at most {@link SshKey#MAX_FILE_BYTES} into a secret. The file must be a
     * regular file, not a link; it is opened once without following a final link
     * ({@code O_NOFOLLOW}) and read through that one channel, capped whatever it grows to. The JDK
     * has no {@code fstat} on a channel, so the opened file is tied to the checked one by its
     * (device, inode) key, read before and after the open: a swap in between is refused. Warns when
     * group or others can read the file.
     */
    private static SecretBytes readKeyFile(Path file, ConsoleIo io) throws UsageException {
        try {
            PosixFileAttributes before = posix(file);
            if (!before.isRegularFile()) {
                throw new UsageException(Messages.SSH_KEY_FILE_UNREADABLE); // not a FIFO, device or link
            }
            try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                PosixFileAttributes after = posix(file);
                Object inodeBefore = before.fileKey(); // (device, inode): public file identity, not a secret
                Object inodeAfter = after.fileKey();
                if (!after.isRegularFile() || !Objects.equals(inodeBefore, inodeAfter)) {
                    throw new UsageException(Messages.SSH_KEY_FILE_UNREADABLE);
                }
                Set<PosixFilePermission> perms = after.permissions();
                if (perms.contains(PosixFilePermission.GROUP_READ) || perms.contains(PosixFilePermission.OTHERS_READ)) {
                    io.err().println(Messages.SSH_KEY_FILE_SHARED.text());
                }
                return readCapped(ch);
            }
        } catch (IOException | UnsupportedOperationException e) {
            throw new UsageException(Messages.SSH_KEY_FILE_UNREADABLE); // missing, a link (ELOOP), no access
        }
    }

    private static PosixFileAttributes posix(Path file) throws IOException {
        return Files.readAttributes(file, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    }

    /** Reads at most {@link SshKey#MAX_FILE_BYTES}; one byte more means the file is too large. */
    private static SecretBytes readCapped(FileChannel ch) throws IOException, UsageException {
        ByteBuffer buf = ByteBuffer.allocate(SshKey.MAX_FILE_BYTES + 1);
        int n;
        do {
            n = ch.read(buf);
        } while (n >= 0 && buf.hasRemaining());
        byte[] backing = buf.array();
        try {
            if (buf.position() > SshKey.MAX_FILE_BYTES) {
                throw new UsageException(Messages.SSH_KEY_FILE_UNREADABLE);
            }
            return SecretBytes.takeOwnership(Arrays.copyOf(backing, buf.position()));
        } finally {
            Arrays.fill(backing, (byte) 0);
        }
    }
}
