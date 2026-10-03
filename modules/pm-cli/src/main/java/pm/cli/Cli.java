package pm.cli;

import com.googlecode.lanterna.terminal.DefaultTerminalFactory;
import com.googlecode.lanterna.terminal.Terminal;
import java.io.Console;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
import pm.crypto.Argon2Params;
import pm.crypto.Csprng;
import pm.crypto.Kdf;
import pm.crypto.SecretBoundary;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.tui.CreatedSession;
import pm.tui.Session;
import pm.tui.TuiApp;
import pm.tui.VaultPort;
import pm.vault.VaultException;
import pm.vault.record.LoginRecord;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/**
 * The CLI behind {@link Main} (plan.md §13 M1): hand-rolled argument parsing, the {@code init},
 * {@code add-login}, {@code list}, {@code search} and {@code tui} commands, the bare {@code pm}
 * that opens the whole app (creating the vault first when there is none), and the mapping from
 * failures to {@link ExitCodes}. Every line printed comes from {@link Messages} or is non-secret
 * record metadata (SR-501); passphrases live only in {@link SecretChars} and are zeroed after use
 * (SR-500, ADR 0008).
 */
final class Cli {
    /** Production KDF tuning target (ADR 0007). */
    private static final Duration KDF_TARGET = Duration.ofMillis(500);
    private static final Pattern LIST_SEPARATOR = Pattern.compile(",");
    private static final String COLUMN_GAP = "  ";
    private static final String VAULT_OPTION = "--vault";
    private static final String END_OF_OPTIONS = "--";
    private static final String OPTION_PREFIX = "-";
    private static final String INIT_COMMAND = "init";

    private final UnaryOperator<String> properties;
    private final Clock clock;
    private final TuiLauncher tuiLauncher;
    private final Predicate<Path> vaultExists;

    /** Production wiring: real system properties, UTC clock, Lanterna terminal, real file system. */
    Cli() {
        this(System::getProperty, Clock.systemUTC(), Cli::launchLanterna, Files::exists);
    }

    /** Test wiring: injected property lookup, clock and TUI launcher; the real file system. */
    Cli(UnaryOperator<String> properties, Clock clock, TuiLauncher tuiLauncher) {
        this(properties, clock, tuiLauncher, Files::exists);
    }

    /**
     * Test wiring with an injected vault-existence check, used only by the bare {@code pm} command
     * to choose between first-run setup and opening the app.
     */
    Cli(UnaryOperator<String> properties, Clock clock, TuiLauncher tuiLauncher, Predicate<Path> vaultExists) {
        this.properties = Objects.requireNonNull(properties, "properties");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.tuiLauncher = Objects.requireNonNull(tuiLauncher, "tuiLauncher");
        this.vaultExists = Objects.requireNonNull(vaultExists, "vaultExists");
    }

    /** Production entry: requires an interactive console (passphrases are never read from a pipe). */
    int run(String[] args) {
        // JDK 21 (the pinned toolchain) returns no console when stdin/stdout is not a terminal.
        // JDK 22+ always returns one: moving past 21 must add a Console.isTerminal() check here.
        Optional<Console> console = Optional.ofNullable(System.console());
        if (console.isEmpty()) {
            System.err.println(Messages.NO_TERMINAL.text());
            System.err.flush();
            return ExitCodes.USAGE;
        }
        return run(args, new SystemConsoleIo(console.get()),
                (path, creating) -> new FileVaultPort(path, clock, kdfFor(creating, () -> Kdf.tune(KDF_TARGET))));
    }

    /**
     * Last-resort report for a failure that escaped {@link #run(String[])}: the catalogue text only,
     * never the exception, its message or a stack trace (SR-501, ERR01-J).
     */
    static void reportInternalError(PrintStream err) {
        err.println(Messages.ERR_INTERNAL.text());
        err.flush();
    }

    /**
     * Argon2id parameters handed to the vault service (ADR 0007). The service uses them only to
     * create a vault; unlock reads the stored parameters from the header. So the machine-specific
     * benchmark ({@code tuner}, about 500 ms) runs only for {@code init}, and every other command
     * passes the floor, which is never used.
     */
    static Argon2Params kdfFor(boolean creating, Supplier<Argon2Params> tuner) {
        return creating ? tuner.get() : Argon2Params.FLOOR;
    }

    /**
     * Runs one invocation and returns its exit code. An unexpected {@link RuntimeException} (a bug)
     * becomes exit {@link ExitCodes#INTERNAL} with only the catalogue text "internal error": no
     * exception message or stack trace reaches the terminal (SR-501, ERR01-J).
     *
     * @param opener builds the vault port for the resolved vault path; called only by commands that
     *     touch the vault
     */
    int run(String[] args, ConsoleIo io, VaultOpener opener) {
        Objects.requireNonNull(args, "args");
        Objects.requireNonNull(io, "io");
        Objects.requireNonNull(opener, "opener");
        try {
            return dispatch(args, io, opener);
        } catch (UsageException e) {
            io.err().println(e.reason().text());
            return ExitCodes.USAGE;
        } catch (VaultException e) {
            io.err().println(ExitCodes.messageFor(e).text());
            return ExitCodes.of(e.code());
        } catch (IOException e) {
            io.err().println(Messages.ERR_TERMINAL.text());
            return ExitCodes.STORAGE;
        } catch (RuntimeException e) {
            // ERR08-J-EX0: catch-all at the trust boundary so the exception text never reaches the
            // terminal (SR-501). Secrets in flight were already closed by try-with-resources.
            io.err().println(Messages.ERR_INTERNAL.text());
            return ExitCodes.INTERNAL;
        } finally {
            io.out().flush();
            io.err().flush();
        }
    }

    private int dispatch(String[] args, ConsoleIo io, VaultOpener opener)
            throws UsageException, VaultException, IOException {
        Deque<String> remaining = new ArrayDeque<>(List.of(args));
        String vaultArg = null;
        List<String> positional = new ArrayList<>();
        while (!remaining.isEmpty()) {
            String arg = remaining.removeFirst();
            switch (arg) {
                case VAULT_OPTION -> {
                    if (vaultArg != null) {
                        throw new UsageException(Messages.DUPLICATE_VAULT_OPTION);
                    }
                    if (remaining.isEmpty() || remaining.peekFirst().startsWith(OPTION_PREFIX)) {
                        // "--vault --help" is a forgotten path, not a file named "--help".
                        throw new UsageException(Messages.MISSING_VAULT_PATH);
                    }
                    vaultArg = remaining.removeFirst();
                }
                case END_OF_OPTIONS -> {
                    // POSIX end of options: everything after "--" is an operand ("search -- -foo").
                    positional.addAll(remaining);
                    remaining.clear();
                }
                case "-h", "--help", "help" -> {
                    io.out().println(Messages.USAGE.text());
                    return ExitCodes.OK;
                }
                default -> {
                    if (arg.startsWith(OPTION_PREFIX)) {
                        throw new UsageException(Messages.UNKNOWN_OPTION);
                    }
                    positional.add(arg);
                }
            }
        }
        Path vaultPath = vaultArg == null
                ? VaultPaths.defaultPath(properties)
                : VaultPaths.fromArgument(vaultArg);
        if (positional.isEmpty()) {
            return openApp(vaultPath, io, opener);
        }
        String command = positional.get(0);
        List<String> operands = positional.subList(1, positional.size());
        int arity = switch (command) {
            case INIT_COMMAND, "add-login", "list", "tui" -> 0;
            case "search" -> 1;
            default -> {
                io.err().println(Messages.USAGE.text());
                throw new UsageException(Messages.UNKNOWN_COMMAND);
            }
        };
        if (operands.size() != arity) {
            throw new UsageException(Messages.WRONG_ARG_COUNT);
        }
        String query = arity == 0 ? null : validQuery(operands.get(0));
        VaultPort port = opener.open(vaultPath, INIT_COMMAND.equals(command));
        return switch (command) {
            case INIT_COMMAND -> init(port, io);
            case "add-login" -> addLogin(port, io);
            case "list" -> list(port, io);
            case "search" -> search(port, io, query);
            default -> tui(port);
        };
    }

    // ---- commands ----------------------------------------------------------------------------

    private static int init(VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        try (SecretChars first = readSecret(io, Messages.PROMPT_NEW_PASSPHRASE, Messages.EMPTY_PASSPHRASE);
                SecretChars second = readSecret(io, Messages.PROMPT_REPEAT_PASSPHRASE, Messages.EMPTY_PASSPHRASE)) {
            if (!sameSecret(first, second)) {
                throw new UsageException(Messages.PASSPHRASE_MISMATCH);
            }
            CreatedSession created = port.create(first);
            Session session = created.session();
            SecretChars recoveryKey = created.recoveryKey();
            try (session; recoveryKey) {
                io.out().println(Messages.VAULT_CREATED.text());
                displayRecoveryKeyOnce(recoveryKey, io.out());
            }
        }
        // PrintWriter swallows IOException: without this check a closed pipe or full disk would lose
        // the only copy of the recovery key while reporting success (ADR 0004, FIO02-J).
        if (io.out().checkError()) {
            io.err().println(Messages.ERR_RECOVERY_NOT_SHOWN.text());
            return ExitCodes.RECOVERY_NOT_SHOWN;
        }
        return ExitCodes.OK;
    }

    private int addLogin(VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        try (Session session = unlock(port, io)) {
            String title = readText(io, Messages.PROMPT_TITLE);
            if (title.isEmpty()) {
                throw new UsageException(Messages.EMPTY_TITLE);
            }
            String username = readText(io, Messages.PROMPT_USERNAME);
            UUID id = Csprng.uuid();
            try (SecretChars typed = readSecret(io, Messages.PROMPT_LOGIN_PASSWORD, Messages.EMPTY_PASSWORD)) {
                handOver(session, newLogin(io, id, title, username, utf8(typed)));
            }
            session.save();
            io.out().println(Messages.LOGIN_ADDED.text() + id);
        }
        return ExitCodes.OK;
    }

    /**
     * Reads the remaining fields and builds the record around {@code loginPassword}, which it owns:
     * on any failure the password is closed before the exception propagates.
     */
    private LoginRecord newLogin(ConsoleIo io, UUID id, String title, String username, SecretBytes loginPassword)
            throws UsageException {
        try {
            List<String> urls = splitList(readText(io, Messages.PROMPT_URLS));
            List<String> tags = splitList(readText(io, Messages.PROMPT_TAGS));
            Instant now = clock.instant();
            return new LoginRecord(id, title, username, loginPassword, urls, "", tags, now, now, now);
        } catch (UsageException e) {
            loginPassword.close();
            throw e;
        } catch (IllegalArgumentException e) {
            loginPassword.close(); // record bounds (Lane D) rejected the input
            throw new UsageException(Messages.INVALID_RECORD);
        }
    }

    /**
     * Passes {@code record}, and the secrets it owns, to the session, which closes it on lock
     * (ADR 0008). If the session refuses it, the record is closed here so its password buffer is
     * zeroed rather than left to the garbage collector (SR-505).
     */
    private static void handOver(Session session, VaultRecord record) {
        try (PendingOwnership pending = new PendingOwnership(record)) {
            session.put(record);
            pending.transferred();
        }
    }

    /** Closes a record on scope exit unless the session took ownership of it first (ADR 0008). */
    private static final class PendingOwnership implements AutoCloseable {
        private final VaultRecord record;
        private boolean owned;

        PendingOwnership(VaultRecord record) {
            this.record = record;
        }

        void transferred() {
            owned = true;
        }

        @Override
        public void close() {
            if (!owned) {
                record.close();
            }
        }
    }

    private static int list(VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        try (Session session = unlock(port, io)) {
            printRecords(io.out(), session.records());
        }
        return ExitCodes.OK;
    }

    private static int search(VaultPort port, ConsoleIo io, String query)
            throws UsageException, VaultException {
        try (Session session = unlock(port, io)) {
            printRecords(io.out(), session.search(query));
        }
        return ExitCodes.OK;
    }

    /**
     * Bare {@code pm}: the whole app in one command. With no vault at {@code vaultPath} it runs the
     * {@code init} flow first, waits for Enter so the recovery key can be written down before the
     * full-screen UI covers it (ADR 0004), then opens the TUI, which unlocks on its own.
     */
    private int openApp(Path vaultPath, ConsoleIo io, VaultOpener opener)
            throws UsageException, VaultException, IOException {
        if (vaultExists.test(vaultPath)) {
            return tui(opener.open(vaultPath, false));
        }
        io.out().println(Messages.FIRST_RUN.text());
        VaultPort port = opener.open(vaultPath, true);
        int status = init(port, io);
        if (status != ExitCodes.OK) {
            return status;
        }
        if (io.readLine(Messages.PROMPT_OPEN_APP.text()) == null) {
            throw new UsageException(Messages.INPUT_CLOSED);
        }
        return tui(port);
    }

    private int tui(VaultPort port) throws IOException {
        tuiLauncher.launch(port);
        return ExitCodes.OK;
    }

    /** Production TUI: a text terminal on stdin/stdout (FIO11-J: explicit UTF-8). */
    private static void launchLanterna(VaultPort port) throws IOException {
        DefaultTerminalFactory factory = new DefaultTerminalFactory(System.out, System.in, StandardCharsets.UTF_8)
                .setForceTextTerminal(true);
        try (Terminal terminal = factory.createTerminal()) {
            new TuiApp(port, TuiApp.DEFAULT_IDLE_LOCK).run(terminal);
        }
    }

    // ---- secrets -----------------------------------------------------------------------------

    /**
     * Writes the recovery key to {@code out} exactly once, straight from its buffer, so it never
     * becomes a {@code String} (ADR 0004, ADR 0008). The caller closes the key afterwards.
     */
    @SecretBoundary(reason = "display recovery key once")
    private static void displayRecoveryKeyOnce(SecretChars recoveryKey, PrintWriter out) {
        out.println(Messages.RECOVERY_KEY_NOTICE.text());
        recoveryKey.withChars(out::write);
        out.println();
        out.flush();
    }

    /**
     * Constant-time comparison of two passphrases over their UTF-8 bytes (SR-016). ArchUnit bans
     * {@code java.security} outside pm-crypto (SR-017), so this uses {@link SecretBytes#equals},
     * which is {@code MessageDigest.isEqual} over both internal buffers.
     */
    private static boolean sameSecret(SecretChars a, SecretChars b) throws UsageException {
        try (SecretBytes left = utf8(a); SecretBytes right = utf8(b)) {
            return left.equals(right);
        }
    }

    private static SecretBytes utf8(SecretChars chars) throws UsageException {
        try {
            return chars.toUtf8();
        } catch (IllegalArgumentException e) {
            throw new UsageException(Messages.MALFORMED_SECRET);
        }
    }

    /** Reads a non-empty secret; the console's array is handed to {@link SecretChars} (and zeroed) at once. */
    private static SecretChars readSecret(ConsoleIo io, Messages prompt, Messages ifEmpty) throws UsageException {
        char[] typed = io.readPassword(prompt.text());
        if (typed == null) {
            throw new UsageException(Messages.INPUT_CLOSED);
        }
        SecretChars secret = SecretChars.takeOwnership(typed);
        if (secret.length() == 0) {
            secret.close();
            throw new UsageException(ifEmpty);
        }
        return secret;
    }

    private static Session unlock(VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        try (SecretChars passphrase = readSecret(io, Messages.PROMPT_PASSPHRASE, Messages.EMPTY_PASSPHRASE)) {
            return port.unlockWithPassphrase(passphrase);
        }
    }

    // ---- non-secret text ---------------------------------------------------------------------

    /**
     * Reads a line, strips surrounding whitespace, then rejects control and invisible formatting
     * characters (IDS01-J, IDS11-J).
     */
    private static String readText(ConsoleIo io, Messages prompt) throws UsageException {
        String line = io.readLine(prompt.text());
        if (line == null) {
            throw new UsageException(Messages.INPUT_CLOSED);
        }
        String normalized = line.strip();
        if (hasUnsafeChars(normalized)) {
            throw new UsageException(Messages.INVALID_TEXT);
        }
        return normalized;
    }

    private static String validQuery(String raw) throws UsageException {
        String normalized = raw.strip();
        if (normalized.isEmpty()) {
            throw new UsageException(Messages.EMPTY_QUERY);
        }
        if (hasUnsafeChars(normalized)) {
            throw new UsageException(Messages.INVALID_TEXT);
        }
        return normalized;
    }

    private static List<String> splitList(String line) {
        return LIST_SEPARATOR.splitAsStream(line).map(String::strip).filter(s -> !s.isEmpty()).toList();
    }

    /**
     * Whether {@code s} contains a code point that must never reach a terminal (IDS01-J): an ISO
     * control (C0/C1, escape sequences), a format character (bidi overrides such as U+202E and
     * U+061C, zero-width U+200B), or a line or paragraph separator (U+2028, U+2029). These can forge
     * or hide text in {@code list} output (SR-501).
     */
    static boolean hasUnsafeChars(String s) {
        return s.codePoints().anyMatch(Cli::isUnsafe);
    }

    private static boolean isUnsafe(int codePoint) {
        if (Character.isISOControl(codePoint)) {
            return true;
        }
        int type = Character.getType(codePoint);
        return type == Character.FORMAT || type == Character.LINE_SEPARATOR
                || type == Character.PARAGRAPH_SEPARATOR;
    }

    /** Prints {@code id  type  title  updated}; never a secret field (SR-500). */
    private static void printRecords(PrintWriter out, List<VaultRecord> records) {
        out.println(Messages.LIST_HEADER.text());
        records.stream().map(Cli::row).forEach(out::println);
    }

    /** One list row; the record stays owned by the session (ADR 0008). */
    private static String row(VaultRecord r) {
        return String.join(COLUMN_GAP, r.id().toString(), typeOf(r), displaySafe(r.title()), r.updated().toString());
    }

    /** {@link VaultRecord} is sealed over exactly these four types (ADR 0006). */
    private static String typeOf(VaultRecord r) {
        if (r instanceof LoginRecord) {
            return "login";
        }
        if (r instanceof WifiRecord) {
            return "wifi";
        }
        if (r instanceof SshKeyRecord) {
            return "ssh-key";
        }
        return "project";
    }

    /**
     * Replaces every unsafe code point ({@link #hasUnsafeChars}) with {@code ?} so stored titles
     * cannot inject terminal escapes or reorder the line (IDS01-J).
     */
    static String displaySafe(String text) {
        StringBuilder sb = new StringBuilder(text.length());
        text.codePoints().forEach(cp -> sb.appendCodePoint(isUnsafe(cp) ? '?' : cp));
        return sb.toString();
    }
}
