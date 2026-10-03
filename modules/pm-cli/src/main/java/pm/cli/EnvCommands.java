package pm.cli;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.SortedMap;
import java.util.function.UnaryOperator;
import pm.approval.AuditEvent;
import pm.approval.AuditException;
import pm.approval.AuditLog;
import pm.crypto.Csprng;
import pm.crypto.SecretBytes;
import pm.domain.env.DotEnv;
import pm.domain.env.DotEnvException;
import pm.domain.env.EnvEntry;
import pm.domain.env.ProjectEnv;
import pm.storage.OwnerOnly;
import pm.storage.StorageException;
import pm.tui.Session;
import pm.tui.VaultPort;
import pm.vault.VaultException;
import pm.vault.record.ProjectRecord;
import pm.vault.record.VaultRecord;

/**
 * {@code pm project ...} and {@code pm env ...} (plan.md §13 M2): register a project directory,
 * import a {@code .env} file into a profile, list variable names, and export a profile as a
 * plaintext file only when {@code --plaintext} says so. Values are never printed. Plaintext files
 * that git could pick up draw a warning ({@link GitGuard}).
 */
@SuppressWarnings("PMD.CloseResource") // project records stay owned by the session, which closes them on lock (ADR 0008)
final class EnvCommands {
    static final String PROJECT_OPTION = "--project";
    static final String PROFILE_OPTION = "--profile";
    static final String DIR_OPTION = "--dir";
    static final String PLAINTEXT_OPTION = "--plaintext";
    static final String AUDIT_FILE = "audit.log";

    private final UnaryOperator<String> properties;
    private final Clock clock;

    EnvCommands(UnaryOperator<String> properties, Clock clock) {
        this.properties = Objects.requireNonNull(properties, "properties");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Parsed {@code [operand] [--project T] [--profile P] [--dir D] [--plaintext]}. */
    record Args(List<String> operands, Optional<String> project, String profile, Optional<String> dir,
            boolean plaintext) {

        static Args parse(List<String> raw) throws UsageException {
            Deque<String> in = new ArrayDeque<>(raw);
            List<String> operands = new java.util.ArrayList<>();
            Optional<String> project = Optional.empty();
            Optional<String> profile = Optional.empty();
            Optional<String> dir = Optional.empty();
            boolean plaintext = false;
            while (!in.isEmpty()) {
                String a = in.removeFirst();
                switch (a) {
                    case PROJECT_OPTION -> project = Optional.of(value(in, project));
                    case PROFILE_OPTION -> profile = Optional.of(value(in, profile));
                    case DIR_OPTION -> dir = Optional.of(value(in, dir));
                    case PLAINTEXT_OPTION -> plaintext = true;
                    default -> {
                        if (a.startsWith("-")) {
                            throw new UsageException(Messages.UNKNOWN_OPTION);
                        }
                        operands.add(a);
                    }
                }
            }
            String p = profile.orElse(ProjectEnv.DEFAULT_PROFILE);
            if (!ProjectEnv.isValidProfile(p)) {
                throw new UsageException(Messages.BAD_PROFILE);
            }
            return new Args(List.copyOf(operands), project, p, dir, plaintext);
        }

        private static String value(Deque<String> in, Optional<String> already) throws UsageException {
            if (already.isPresent() || in.isEmpty() || in.peekFirst().startsWith("-")) {
                throw new UsageException(Messages.WRONG_ARG_COUNT);
            }
            String v = in.removeFirst().strip();
            if (v.isEmpty() || Cli.hasUnsafeChars(v)) {
                throw new UsageException(Messages.INVALID_TEXT);
            }
            return v;
        }
    }

    // ---- project ---------------------------------------------------------------------------

    int project(List<String> sub, VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        if (sub.isEmpty()) {
            throw new UsageException(Messages.WRONG_ARG_COUNT);
        }
        Args args = Args.parse(sub.subList(1, sub.size()));
        return switch (sub.get(0)) {
            case "add" -> projectAdd(args, port, io);
            case "list" -> {
                arity(args, 0);
                yield projectList(port, io);
            }
            default -> throw new UsageException(Messages.UNKNOWN_COMMAND);
        };
    }

    private int projectAdd(Args args, VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        arity(args, 1);
        String title = args.operands().get(0);
        Path dir = realDirectory(args.dir().isPresent() ? resolve(args.dir().get()) : cwd());
        String remote = GitRemote.origin(dir).orElse("");
        try (Session session = Cli.unlock(port, io)) {
            List<VaultRecord> records = session.records();
            if (ProjectEnv.byTitle(records, title).isPresent()) {
                throw new UsageException(Messages.PROJECT_EXISTS);
            }
            boolean pathTaken = ProjectEnv.projects(records).anyMatch(p -> p.canonicalPath().equals(dir.toString()));
            if (pathTaken) {
                throw new UsageException(Messages.PROJECT_EXISTS);
            }
            ProjectRecord project;
            try {
                project = ProjectEnv.newProject(Csprng.uuid(), title, dir, remote, clock.instant());
            } catch (IllegalArgumentException e) {
                throw new UsageException(Messages.INVALID_RECORD);
            }
            session.put(project);
            session.save();
            io.out().println(Messages.PROJECT_ADDED.text() + Cli.displaySafe(title));
        }
        return ExitCodes.OK;
    }

    private static int projectList(VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        try (Session session = Cli.unlock(port, io)) {
            io.out().println(Messages.PROJECT_HEADER.text());
            ProjectEnv.projects(session.records()).forEach(p -> io.out().println(String.join("  ",
                    Cli.displaySafe(p.title()), Cli.displaySafe(p.canonicalPath()),
                    String.join(",", ProjectEnv.profiles(p)))));
        }
        return ExitCodes.OK;
    }

    // ---- env -------------------------------------------------------------------------------

    int env(List<String> sub, VaultPort port, ConsoleIo io, Path vaultPath) throws UsageException, VaultException {
        if (sub.isEmpty()) {
            throw new UsageException(Messages.WRONG_ARG_COUNT);
        }
        Args args = Args.parse(sub.subList(1, sub.size()));
        return switch (sub.get(0)) {
            case "list" -> envList(args, port, io);
            case "import" -> envImport(args, port, io);
            case "export" -> envExport(args, port, io, vaultPath);
            default -> throw new UsageException(Messages.UNKNOWN_COMMAND);
        };
    }

    private int envList(Args args, VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        arity(args, 0);
        try (Session session = Cli.unlock(port, io)) {
            ProjectRecord project = target(session.records(), args);
            io.out().println(Messages.ENV_HEADER.text() + Cli.displaySafe(project.title()) + "/" + args.profile());
            ProjectEnv.variables(project, args.profile()).keySet().forEach(io.out()::println);
        }
        return ExitCodes.OK;
    }

    private int envImport(Args args, VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        arity(args, 1);
        Path file = resolve(args.operands().get(0));
        byte[] bytes = readEnvFile(file);
        List<EnvEntry> entries;
        try {
            entries = DotEnv.parse(bytes);
        } catch (DotEnvException e) {
            io.err().println(Messages.ENV_REJECTED.text() + e.code().name() + " at line " + e.line());
            return ExitCodes.USAGE;
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
        try (Session session = Cli.unlock(port, io)) {
            ProjectRecord project = target(session.records(), args);
            ProjectRecord updated;
            try {
                updated = ProjectEnv.withProfile(project, args.profile(), entries, clock.instant());
            } catch (IllegalArgumentException e) {
                throw new UsageException(Messages.INVALID_RECORD);
            }
            entries = List.of(); // values now belong to the updated record
            session.put(updated);
            session.save();
            io.out().println(Messages.ENV_IMPORTED.text() + ProjectEnv.variables(updated, args.profile()).size()
                    + " -> " + Cli.displaySafe(project.title()) + "/" + args.profile());
        } finally {
            entries.forEach(EnvEntry::close);
        }
        warnPlaintext(io.err(), file);
        io.err().println(Messages.WARN_PLAINTEXT_LEFT.text());
        return ExitCodes.OK;
    }

    private int envExport(Args args, VaultPort port, ConsoleIo io, Path vaultPath)
            throws UsageException, VaultException {
        arity(args, 1);
        if (!args.plaintext()) {
            throw new UsageException(Messages.EXPORT_NEEDS_PLAINTEXT);
        }
        Path file = resolve(args.operands().get(0));
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new UsageException(Messages.EXPORT_EXISTS);
        }
        try (Session session = Cli.unlock(port, io)) {
            ProjectRecord project = target(session.records(), args);
            SortedMap<String, SecretBytes> vars = ProjectEnv.variables(project, args.profile());
            SecretBytes content;
            try {
                content = DotEnvWriter.format(vars);
            } catch (IllegalArgumentException e) {
                throw new UsageException(Messages.EXPORT_UNREPRESENTABLE);
            }
            try (content) {
                audit(vaultPath, project, args.profile(), vars.size());
                writeOwnerOnly(file, content);
            }
            io.out().println(Messages.ENV_EXPORTED.text() + vars.size());
        }
        warnPlaintext(io.err(), file);
        return ExitCodes.OK;
    }

    // ---- helpers ---------------------------------------------------------------------------

    private static void arity(Args args, int n) throws UsageException {
        if (args.operands().size() != n) {
            throw new UsageException(Messages.WRONG_ARG_COUNT);
        }
    }

    private ProjectRecord target(List<VaultRecord> records, Args args) throws UsageException {
        if (args.project().isPresent()) {
            return ProjectEnv.byTitle(records, args.project().get())
                    .orElseThrow(() -> new UsageException(Messages.NO_SUCH_PROJECT));
        }
        Path here;
        try {
            here = cwd().toRealPath();
        } catch (IOException e) {
            throw new UsageException(Messages.NO_PROJECT_HERE);
        }
        return ProjectEnv.forDirectory(records, here).orElseThrow(() -> new UsageException(Messages.NO_PROJECT_HERE));
    }

    private Path cwd() {
        return Path.of(Objects.requireNonNull(properties.apply("user.dir"), "user.dir")).toAbsolutePath().normalize();
    }

    private Path resolve(String arg) throws UsageException {
        try {
            return cwd().resolve(arg).toAbsolutePath().normalize();
        } catch (InvalidPathException e) {
            throw new UsageException(Messages.INVALID_TEXT);
        }
    }

    private static Path realDirectory(Path dir) throws UsageException {
        try {
            Path real = dir.toRealPath();
            if (!Files.isDirectory(real)) {
                throw new UsageException(Messages.NOT_A_DIRECTORY);
            }
            return real;
        } catch (IOException | InvalidPathException e) {
            throw new UsageException(Messages.NOT_A_DIRECTORY);
        }
    }

    private static byte[] readEnvFile(Path file) throws UsageException {
        try {
            if (!Files.isRegularFile(file) || Files.size(file) > DotEnv.MAX_INPUT_BYTES) {
                throw new UsageException(Messages.ENV_FILE_UNREADABLE);
            }
            return Files.readAllBytes(file);
        } catch (IOException | InvalidPathException e) {
            throw new UsageException(Messages.ENV_FILE_UNREADABLE);
        }
    }

    private static void writeOwnerOnly(Path file, SecretBytes content) throws UsageException {
        try {
            Path parent = Objects.requireNonNull(file.getParent(), "parent");
            boolean posix = Files.getFileStore(parent).supportsFileAttributeView("posix");
            FileChannel ch = posix
                    ? FileChannel.open(file, java.util.Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                            LinkOption.NOFOLLOW_LINKS),
                            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                    : FileChannel.open(file, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                            LinkOption.NOFOLLOW_LINKS);
            try (ch) {
                if (!posix) {
                    OwnerOnly.apply(file);
                }
                content.withBytes(b -> write(ch, b));
                ch.force(true);
            }
        } catch (FileAlreadyExistsException e) {
            throw new UsageException(Messages.EXPORT_EXISTS);
        } catch (IOException | StorageException | java.io.UncheckedIOException e) {
            throw new UsageException(Messages.EXPORT_FAILED);
        }
    }

    private static void write(FileChannel ch, byte[] b) {
        try {
            ByteBuffer buf = ByteBuffer.wrap(b);
            while (buf.hasRemaining()) {
                ch.write(buf);
            }
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    /** Records the export before any byte is written; no audit, no export. */
    private void audit(Path vaultPath, ProjectRecord project, String profile, int count) throws UsageException {
        Path dir = Objects.requireNonNull(vaultPath.toAbsolutePath().getParent(), "vault dir");
        try (AuditLog log = AuditLog.open(dir.resolve(AUDIT_FILE), clock)) {
            log.record(new AuditEvent("export", Optional.empty(), Optional.of("CLI"),
                    Optional.ofNullable(properties.apply("user.name")), Optional.of(project.title()),
                    Optional.of(profile), count, Optional.of("ALLOWED_ONCE"), Optional.of("pm")));
        } catch (AuditException | IllegalStateException e) {
            throw new UsageException(Messages.AUDIT_UNAVAILABLE);
        }
    }

    private static void warnPlaintext(PrintWriter err, Path file) {
        if (GitGuard.atRisk(file)) {
            err.println(Messages.WARN_GIT_NOT_IGNORED.text());
        }
    }
}
