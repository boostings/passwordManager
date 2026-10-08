package pm.cli;

import com.googlecode.lanterna.terminal.DefaultTerminalFactory;
import com.googlecode.lanterna.terminal.Terminal;
import java.io.Console;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.Charset;
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
import pm.domain.env.Env;
import pm.domain.health.BreachClient;
import pm.crypto.Argon2Params;
import pm.crypto.Csprng;
import pm.crypto.Kdf;
import pm.crypto.SecretBoundary;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.tui.ApprovalHost;
import pm.tui.CreatedSession;
import pm.tui.Session;
import pm.tui.TuiApp;
import pm.tui.VaultPort;
import pm.vault.VaultException;
import pm.vault.record.DeviceRecord;
import pm.vault.record.LoginRecord;
import pm.vault.record.PasskeyRecord;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/**
 * The CLI behind {@link Main} (plan.md §13 M1): hand-rolled argument parsing, the {@code init},
 * {@code add-login}, {@code list}, {@code search} and {@code tui} commands, the M2
 * {@code project} and {@code env} groups ({@link EnvCommands}), the M4 {@code generate},
 * {@code health} and {@code ssh} groups ({@link GenerateCommand}, {@link HealthCommand},
 * {@link SshCommands}), the M5.4 {@code browser} group and native host ({@link BrowserCommands},
 * {@link BrowserHost}), the M7.7 command table ({@link Command}), the bare {@code pm}
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
    private static final String HELP_SHORT = "-h";
    private static final String HELP_LONG = "--help";
    private static final String VERSION_OPTION = "--version";
    private static final int ONE_WORD = 1;
    private static final int HELP_MAX_WORDS = 2;

    private final UnaryOperator<String> properties;
    private final Clock clock;
    private final TuiLauncher tuiLauncher;
    private final Predicate<Path> vaultExists;
    /** Environment for the approval-broker run directory; replaced only by tests. */
    private Env environment = Env.system();
    /** Builds the opt-in breach client for {@code health --breach}; replaced only by tests. */
    private Supplier<BreachClient> breachClients = BreachClient::pwnedPasswords;
    /** Told {@code ip:port} or a URL when a LAN command starts listening; replaced only by tests. */
    private java.util.function.Consumer<String> lanListening = address -> { };
    /** Where {@code pm browser} installs; replaced only by tests. */
    private BrowserPlatforms browserPlatform = p -> BrowserCommands.Platform.system(p, environment);

    /** Builds the {@code pm browser} platform from the system properties. */
    @FunctionalInterface
    interface BrowserPlatforms {
        BrowserCommands.Platform apply(UnaryOperator<String> properties) throws UsageException;
    }

    /** Production wiring: real system properties, UTC clock, Lanterna terminal, real file system. */
    Cli() {
        this(System::getProperty, Clock.systemUTC(), new TuiLauncher() {
            @Override
            public void launch(VaultPort port) throws IOException {
                throw new IllegalStateException("the production launcher needs the vault path");
            }

            @Override
            public void launch(VaultPort port, Path vaultPath) throws IOException {
                launchLanterna(port, vaultPath);
            }
        }, Files::exists);
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

    /** Test hook: the environment {@code env run} uses to find a running broker. */
    Cli withEnvironment(Env env) {
        this.environment = Objects.requireNonNull(env, "env");
        return this;
    }

    /** Test hook: where {@code health --breach} sends its lookups (a loopback server in tests). */
    Cli withBreachClients(Supplier<BreachClient> clients) {
        this.breachClients = Objects.requireNonNull(clients, "clients");
        return this;
    }

    /** Test hook: told where a {@code pair --listen} or {@code share} window listens. */
    Cli withLanListener(java.util.function.Consumer<String> listener) {
        this.lanListening = Objects.requireNonNull(listener, "listener");
        return this;
    }

    /** Test hook: the platform {@code pm browser} installs for (temporary folders in tests). */
    Cli withBrowserPlatform(BrowserPlatforms platforms) {
        this.browserPlatform = Objects.requireNonNull(platforms, "platforms");
        return this;
    }

    /** Production entry: requires an interactive console (passphrases are never read from a pipe). */
    int run(String[] args) {
        if (BrowserHost.isHostInvocation(args)) {
            // Started by the browser as its native messaging host (ADR 0014 §8): stdin and stdout
            // carry frames, never a console.
            return BrowserHost.serve(args, System.in, System.out, properties);
        }
        // JDK 21 (the pinned toolchain) returns no console when stdin/stdout is not a terminal.
        // JDK 22+ always returns one: moving past 21 must add a Console.isTerminal() check here.
        return run(args, Optional.ofNullable(System.console()), System.out, System.err);
    }

    /**
     * {@link #run(String[])} with the console and standard streams given. Without a console only
     * the commands that read nothing run: {@code generate} (so {@code pm generate | pbcopy} works),
     * {@code browser install/uninstall/status}, {@code help}, {@code --help} and {@code --version}. Every other command is refused, since a
     * passphrase is never read from a pipe.
     */
    int run(String[] args, Optional<Console> console, PrintStream out, PrintStream err) {
        if (console.isPresent()) {
            return run(args, new SystemConsoleIo(console.get()),
                    (path, creating) -> new FileVaultPort(path, clock, kdfFor(creating, () -> Kdf.tune(KDF_TARGET))));
        }
        return run(args, new PipedIo(out, err, Charset.defaultCharset()), (path, creating) -> {
            throw new IllegalStateException("a run without a terminal opens no vault");
        }, false);
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
        return run(args, io, opener, true);
    }

    private int run(String[] args, ConsoleIo io, VaultOpener opener, boolean terminal) {
        Objects.requireNonNull(args, "args");
        Objects.requireNonNull(io, "io");
        Objects.requireNonNull(opener, "opener");
        try {
            return dispatch(args, io, opener, terminal);
        } catch (UsageException e) {
            io.err().println(e.text());
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

    /**
     * Parses the global options, resolves the command against {@link Command} and runs it.
     * {@code -h} or {@code --help} before the command word prints the usage, after it the
     * command's help; {@code --version} counts only before the command word.
     */
    private int dispatch(String[] args, ConsoleIo io, VaultOpener opener, boolean terminal)
            throws UsageException, VaultException, IOException {
        Deque<String> remaining = new ArrayDeque<>(List.of(args));
        String vaultArg = null;
        List<String> positional = new ArrayList<>();
        List<String> sub = null;
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
                case HELP_SHORT, HELP_LONG -> {
                    // Before a command word: the usage. After one of the M1 commands: its help.
                    return help(positional.isEmpty() ? List.of() : List.of(positional.get(0)), io);
                }
                case VERSION_OPTION -> {
                    if (!positional.isEmpty()) {
                        throw new UsageException(Messages.UNKNOWN_OPTION);
                    }
                    io.out().println(Messages.VERSION.text() + Version.current());
                    return ExitCodes.OK;
                }
                default -> {
                    if (arg.startsWith(OPTION_PREFIX)) {
                        throw new UsageException(Messages.UNKNOWN_OPTION);
                    }
                    positional.add(arg);
                    if (positional.size() == ONE_WORD && parsesOwnArgs(arg)) {
                        // The command parses the words after it itself (CommandArgs, EnvCommands.Args).
                        sub = new ArrayList<>(remaining);
                        remaining.clear();
                    }
                }
            }
        }
        if (positional.isEmpty()) {
            requireTerminal(terminal);
            return openApp(vaultPath(vaultArg), io, opener);
        }
        String word = positional.get(0);
        if (!Command.known(word)) {
            io.err().println(Command.usage());
            throw new UsageException(Messages.UNKNOWN_COMMAND);
        }
        List<String> rest = List.copyOf(sub == null ? positional.subList(1, positional.size()) : sub);
        if (parsesOwnArgs(word) && asksForHelp(rest)) {
            return help(helpTarget(word, rest), io);
        }
        Command command = Command.resolve(word, rest);
        if (command.topLevelOperands() && rest.size() != command.arity()) {
            throw new UsageException(Messages.WRONG_ARG_COUNT);
        }
        if (command == Command.HELP) {
            return help(rest, io);
        }
        if (command != Command.GENERATE && command.area() != Command.Area.BROWSER) {
            requireTerminal(terminal);
        }
        return run(command, rest, vaultPath(vaultArg), io, opener);
    }

    /** Runs a resolved command: one case per {@link Command} entry, so every entry is dispatched. */
    private int run(Command command, List<String> rest, Path vaultPath, ConsoleIo io, VaultOpener opener)
            throws UsageException, VaultException, IOException {
        List<String> afterSub = rest.isEmpty() ? rest : rest.subList(1, rest.size());
        return switch (command) {
            case HELP -> help(rest, io);
            case INIT -> {
                // Refuse before asking for a passphrase; create still refuses an existing file itself.
                if (vaultExists.test(vaultPath)) {
                    throw new VaultException(VaultException.Code.ALREADY_EXISTS, null);
                }
                yield init(opener.open(vaultPath, true), io);
            }
            case TUI -> tui(opener.open(vaultPath, false), vaultPath);
            case ADD_LOGIN -> addLogin(opener.open(vaultPath, false), io);
            case LIST -> list(opener.open(vaultPath, false), io);
            case SEARCH -> search(validQuery(rest.get(0)), opener, vaultPath, io);
            case WIFI_ADD -> records().wifiAdd(afterSub, opener.open(vaultPath, false), io);
            case SHOW -> records().show(rest, opener.open(vaultPath, false), io);
            case EDIT -> records().edit(rest, opener.open(vaultPath, false), io);
            case RM -> records().rm(rest, opener.open(vaultPath, false), io);
            case GENERATE -> GenerateCommand.run(rest, io);
            case HEALTH -> new HealthCommand(clock, breachClients).run(rest, opener.open(vaultPath, false), io);
            case SSH_IMPORT, SSH_LIST, SSH_ADD, SSH_REMOVE, SSH_EXPORT ->
                    new SshCommands(properties, clock, environment).run(rest, opener.open(vaultPath, false), io,
                            vaultPath);
            case PROJECT_ADD, PROJECT_LIST ->
                    new EnvCommands(properties, clock, environment).project(rest, opener.open(vaultPath, false), io);
            case ENV_LIST, ENV_IMPORT, ENV_EXPORT, ENV_RUN ->
                    new EnvCommands(properties, clock, environment).env(rest, opener.open(vaultPath, false), io,
                            vaultPath);
            case DEVICES, DEVICES_REMOVE, PAIR, SHARE, RECEIVE, REVOKE ->
                    new LanCommands(properties, clock, environment, lanListening)
                            .run(command.word(), rest, opener, vaultPath, io);
            case PASSPHRASE -> new PassphraseCommands(properties, clock).passphrase(rest, vaultPath, io);
            case RECOVER -> new PassphraseCommands(properties, clock).recover(rest, vaultPath, io);
            case BACKUP_CREATE -> backups().create(afterSub, vaultPath, io);
            case BACKUP_VERIFY -> backups().verify(afterSub, io);
            case RESTORE -> backups().restore(rest, vaultPath, io);
            case BROWSER_INSTALL, BROWSER_UNINSTALL, BROWSER_STATUS -> browser(rest, vaultPath, io);
        };
    }

    /** {@code pm browser}: the default vault only, since that is the one the native host reaches. */
    private int browser(List<String> rest, Path vaultPath, ConsoleIo io) throws UsageException {
        Path defaultVault = VaultPaths.defaultPath(properties);
        if (!defaultVault.equals(vaultPath)) {
            throw new UsageException(Messages.BRIDGE_DEFAULT_VAULT_ONLY);
        }
        Path vaultDir = defaultVault.getParent();
        if (vaultDir == null) {
            throw new UsageException(Messages.NO_HOME_DIR);
        }
        return new BrowserCommands(browserPlatform.apply(properties), vaultDir).run(rest, io);
    }

    private RecordCommands records() {
        return new RecordCommands(clock);
    }

    private BackupCommands backups() {
        return new BackupCommands(clock);
    }

    private Path vaultPath(String vaultArg) throws UsageException {
        return vaultArg == null ? VaultPaths.defaultPath(properties) : VaultPaths.fromArgument(vaultArg);
    }

    private static void requireTerminal(boolean terminal) throws UsageException {
        if (!terminal) {
            throw new UsageException(Messages.NO_TERMINAL);
        }
    }

    /** Whether {@code word} names a command that parses the words after it itself. */
    private static boolean parsesOwnArgs(String word) {
        return Command.named(word).stream().anyMatch(c -> !c.topLevelOperands());
    }

    /** Whether {@code -h} or {@code --help} comes before any {@code --} in {@code words}. */
    private static boolean asksForHelp(List<String> words) {
        for (String w : words) {
            if (END_OF_OPTIONS.equals(w)) {
                return false;
            }
            if (HELP_SHORT.equals(w) || HELP_LONG.equals(w)) {
                return true;
            }
        }
        return false;
    }

    /** {@code ssh add --help} asks about {@code ssh add}; {@code ssh --help} about every ssh command. */
    private static List<String> helpTarget(String word, List<String> rest) {
        boolean namesSub = !rest.isEmpty()
                && Command.named(word).stream().anyMatch(c -> c.sub().filter(rest.get(0)::equals).isPresent());
        return namesSub ? List.of(word, rest.get(0)) : List.of(word);
    }

    /**
     * {@code pm help [<command> [<subcommand>]]}: the usage, the help of every entry of a command,
     * or the help of one subcommand, on stdout.
     */
    private static int help(List<String> words, ConsoleIo io) throws UsageException {
        if (words.isEmpty()) {
            io.out().println(Command.usage());
            return ExitCodes.OK;
        }
        String word = words.get(0);
        if (!Command.known(word)) {
            io.err().println(Command.usage());
            throw new UsageException(Messages.UNKNOWN_COMMAND);
        }
        if (words.size() == ONE_WORD) {
            io.out().println(Command.helpFor(word));
            return ExitCodes.OK;
        }
        if (words.size() > HELP_MAX_WORDS) {
            throw new UsageException(Messages.WRONG_ARG_COUNT);
        }
        String subWord = words.get(1);
        Command entry = Command.named(word).stream().filter(c -> c.sub().filter(subWord::equals).isPresent())
                .findFirst().orElseThrow(() -> new UsageException(Messages.UNKNOWN_COMMAND));
        io.out().println(entry.help());
        return ExitCodes.OK;
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
    static void handOver(Session session, VaultRecord record) {
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

    private static int search(String query, VaultOpener opener, Path vaultPath, ConsoleIo io)
            throws UsageException, VaultException {
        try (Session session = unlock(opener.open(vaultPath, false), io)) {
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
            return tui(opener.open(vaultPath, false), vaultPath);
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
        return tui(port, vaultPath);
    }

    private int tui(VaultPort port, Path vaultPath) throws IOException {
        tuiLauncher.launch(port, vaultPath);
        return ExitCodes.OK;
    }

    /** Production TUI: a text terminal on stdin/stdout (FIO11-J: explicit UTF-8). */
    private static void launchLanterna(VaultPort port, Path vaultPath) throws IOException {
        DefaultTerminalFactory factory = new DefaultTerminalFactory(System.out, System.in, StandardCharsets.UTF_8)
                .setForceTextTerminal(true);
        // While the app is unlocked it hosts the approval broker that `pm env run` asks (M2), and,
        // on the default vault only, the browser relay (ADR 0014 §8).
        try (ApprovalHost host = ApprovalHost.socketFor(vaultPath, Env.system(), Clock.systemUTC(),
                        Objects.requireNonNull(System.getProperty("user.name"), "user.name"),
                        isDefaultVault(vaultPath, System::getProperty));
                Terminal terminal = factory.createTerminal()) {
            SshCommands ssh = new SshCommands(System::getProperty, Clock.systemUTC(), Env.system());
            new TuiApp(port, TuiApp.DEFAULT_IDLE_LOCK, host, new CliSshActions(ssh, vaultPath),
                    CliClipboard.forSystem(System::getProperty), CliClipboard.clearAfter(Env.system())).run(terminal);
        }
    }

    /**
     * Whether {@code vaultPath} is the default vault, the only one the browser's native host
     * reaches (ADR 0014 §8). False when there is no default (no home directory).
     */
    static boolean isDefaultVault(Path vaultPath, UnaryOperator<String> properties) {
        try {
            return VaultPaths.defaultPath(properties).toAbsolutePath().normalize()
                    .equals(vaultPath.toAbsolutePath().normalize());
        } catch (UsageException e) {
            return false;
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
    static boolean sameSecret(SecretChars a, SecretChars b) throws UsageException {
        try (SecretBytes left = utf8(a); SecretBytes right = utf8(b)) {
            return left.equals(right);
        }
    }

    static SecretBytes utf8(SecretChars chars) throws UsageException {
        try {
            return chars.toUtf8();
        } catch (IllegalArgumentException e) {
            throw new UsageException(Messages.MALFORMED_SECRET);
        }
    }

    /** Reads a non-empty secret; the console's array is handed to {@link SecretChars} (and zeroed) at once. */
    static SecretChars readSecret(ConsoleIo io, Messages prompt, Messages ifEmpty) throws UsageException {
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

    static Session unlock(VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        try (SecretChars passphrase = readSecret(io, Messages.PROMPT_PASSPHRASE, Messages.EMPTY_PASSPHRASE)) {
            return port.unlockWithPassphrase(passphrase);
        }
    }

    // ---- non-secret text ---------------------------------------------------------------------

    /**
     * Reads a line, strips surrounding whitespace, then rejects control and invisible formatting
     * characters (IDS01-J, IDS11-J).
     */
    static String readText(ConsoleIo io, Messages prompt) throws UsageException {
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

    static List<String> splitList(String line) {
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

    static boolean isUnsafe(int codePoint) {
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
        records.stream().filter(r -> !DeviceRecord.isInternal(r)).map(Cli::row).forEach(out::println);
    }

    /** One list row; the record stays owned by the session (ADR 0008). */
    static String row(VaultRecord r) {
        return String.join(COLUMN_GAP, r.id().toString(), typeOf(r), displaySafe(r.title()), r.updated().toString());
    }

    /** The item types (ADR 0006, ADR 0016); device records never reach here ({@link #printRecords} drops them). */
    static String typeOf(VaultRecord r) {
        if (r instanceof LoginRecord) {
            return "login";
        }
        if (r instanceof WifiRecord) {
            return "wifi";
        }
        if (r instanceof SshKeyRecord) {
            return "ssh-key";
        }
        if (r instanceof PasskeyRecord) {
            return "passkey";
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
