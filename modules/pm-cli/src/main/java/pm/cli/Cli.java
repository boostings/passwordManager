package pm.cli;

import com.googlecode.lanterna.terminal.DefaultTerminalFactory;
import com.googlecode.lanterna.terminal.Terminal;
import java.io.Console;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
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
import java.util.function.Function;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
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
 * {@code add-login}, {@code list}, {@code search} and {@code tui} commands, and the mapping from
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

    private final UnaryOperator<String> properties;
    private final Clock clock;
    private final TuiLauncher tuiLauncher;

    /** Production wiring: real system properties, UTC clock, Lanterna terminal. */
    Cli() {
        this(System::getProperty, Clock.systemUTC(), Cli::launchLanterna);
    }

    /** Test wiring: injected property lookup, clock and TUI launcher. */
    Cli(UnaryOperator<String> properties, Clock clock, TuiLauncher tuiLauncher) {
        this.properties = Objects.requireNonNull(properties, "properties");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.tuiLauncher = Objects.requireNonNull(tuiLauncher, "tuiLauncher");
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
                path -> new FileVaultPort(path, clock, Kdf.tune(KDF_TARGET)));
    }

    /**
     * Runs one invocation and returns its exit code.
     *
     * @param opener builds the vault port for the resolved vault path; called only by commands that
     *     touch the vault
     */
    int run(String[] args, ConsoleIo io, Function<Path, VaultPort> opener) {
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
        } finally {
            io.out().flush();
            io.err().flush();
        }
    }

    private int dispatch(String[] args, ConsoleIo io, Function<Path, VaultPort> opener)
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
                    if (remaining.isEmpty()) {
                        throw new UsageException(Messages.MISSING_VAULT_PATH);
                    }
                    vaultArg = remaining.removeFirst();
                }
                case "-h", "--help", "help" -> {
                    io.out().println(Messages.USAGE.text());
                    return ExitCodes.OK;
                }
                default -> {
                    if (arg.startsWith("-")) {
                        throw new UsageException(Messages.UNKNOWN_OPTION);
                    }
                    positional.add(arg);
                }
            }
        }
        if (positional.isEmpty()) {
            io.err().println(Messages.USAGE.text());
            throw new UsageException(Messages.MISSING_COMMAND);
        }
        String command = positional.get(0);
        List<String> operands = positional.subList(1, positional.size());
        int arity = switch (command) {
            case "init", "add-login", "list", "tui" -> 0;
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
        Path vaultPath = vaultArg == null
                ? VaultPaths.defaultPath(properties)
                : VaultPaths.fromArgument(vaultArg);
        VaultPort port = opener.apply(vaultPath);
        return switch (command) {
            case "init" -> init(port, io);
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
                // Ownership of the record, and its password, passes to the session, which closes
                // it on lock (ADR 0008).
                session.put(newLogin(io, id, title, username, utf8(typed)));
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

    /** Reads a line, strips surrounding whitespace, then rejects control characters (IDS01-J). */
    private static String readText(ConsoleIo io, Messages prompt) throws UsageException {
        String line = io.readLine(prompt.text());
        if (line == null) {
            throw new UsageException(Messages.INPUT_CLOSED);
        }
        String normalized = line.strip();
        if (hasControlChars(normalized)) {
            throw new UsageException(Messages.INVALID_TEXT);
        }
        return normalized;
    }

    private static String validQuery(String raw) throws UsageException {
        String normalized = raw.strip();
        if (normalized.isEmpty()) {
            throw new UsageException(Messages.EMPTY_QUERY);
        }
        if (hasControlChars(normalized)) {
            throw new UsageException(Messages.INVALID_TEXT);
        }
        return normalized;
    }

    private static List<String> splitList(String line) {
        return LIST_SEPARATOR.splitAsStream(line).map(String::strip).filter(s -> !s.isEmpty()).toList();
    }

    /** Whether {@code s} contains an ISO control character (terminal-escape injection, IDS01-J). */
    static boolean hasControlChars(String s) {
        return s.chars().anyMatch(Character::isISOControl);
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

    /** Replaces control characters so stored titles cannot inject terminal escapes. */
    private static String displaySafe(String text) {
        StringBuilder sb = new StringBuilder(text.length());
        text.chars().forEach(c -> sb.append(Character.isISOControl(c) ? '?' : (char) c));
        return sb.toString();
    }
}
