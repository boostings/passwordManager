package pm.cli;

import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Stream;
import pm.crypto.Csprng;
import pm.crypto.SecretBoundary;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.domain.env.ProjectEnv;
import pm.domain.generate.Generated;
import pm.tui.Session;
import pm.tui.VaultPort;
import pm.vault.VaultException;
import pm.vault.record.DeviceRecord;
import pm.vault.record.LoginRecord;
import pm.vault.record.PasskeyRecord;
import pm.vault.record.ProjectRecord;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/**
 * The item commands of M7.7: {@code show}, {@code edit}, {@code rm} and {@code wifi add}. An
 * {@code <item>} is found as {@code pm ssh} finds a key: by id, else by exact title. A title that
 * several items share is refused and their ids are listed, so the user can pick one.
 *
 * <p>{@code pm show <item> --reveal} is the one CLI path that prints a stored secret, and only the
 * password of a login or a Wi-Fi network (SR-132). New secrets come only from the prompt, typed
 * twice, or from the generator, never from the command line (SR-133). Every record built here owns
 * its own copy of its secret and is handed to the session, which closes it on lock (ADR 0008).
 */
final class RecordCommands {
    static final String REVEAL = "--reveal";
    private static final int BRAILLE_BLANK = 0x2800;
    static final String YES = "--yes";
    static final String TITLE = "--title";
    static final String USERNAME = "--username";
    static final String URLS = "--urls";
    static final String TAGS = "--tags";
    static final String NOTES = "--notes";
    static final String SSID = "--ssid";
    static final String SECURITY = "--security";
    static final String HIDDEN = "--hidden";
    static final String NOT_HIDDEN = "--not-hidden";
    static final String ASK = "--password";
    static final String GENERATE = "--generate";
    static final String OPEN = "OPEN";
    static final String DEFAULT_SECURITY = "WPA2";
    private static final Set<String> SECURITY_TYPES = Set.of("WPA2", "WPA3", "WEP", OPEN);
    private static final Set<String> LOGIN_ONLY = Set.of(USERNAME, URLS, TAGS);
    private static final Set<String> WIFI_ONLY = Set.of(SSID, SECURITY, HIDDEN, NOT_HIDDEN);
    /**
     * Options whose empty value the parser lets through so the command can name it (m77-008):
     * the clearable ones, and the title and SSID, which get {@code EMPTY_TITLE}/{@code EMPTY_SSID}.
     */
    private static final Set<String> EMPTY_PASSED_ON = Set.of(USERNAME, URLS, TAGS, NOTES, TITLE, SSID);
    private static final List<String> CHANGES =
            List.of(TITLE, USERNAME, URLS, TAGS, NOTES, SSID, SECURITY, HIDDEN, NOT_HIDDEN, ASK, GENERATE);
    /** The widest label, {@code display name:}, plus one space. */
    private static final int LABEL_WIDTH = 14;
    private static final int ONE = 1;
    private static final String INDENT = "  ";
    private static final String LIST_JOIN = ", ";
    private static final String PROFILE_SEPARATOR = ": ";

    private final Clock clock;

    RecordCommands(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    // ---- show --------------------------------------------------------------------------------

    /** {@code pm show <item> [--reveal]}. */
    @SuppressWarnings("PMD.CloseResource") // CE-087: records are the session's (ADR 0008)
    int show(List<String> words, VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        CommandArgs args = CommandArgs.parse(words, Set.of(REVEAL), Set.of()).arity(ONE);
        boolean reveal = args.has(REVEAL);
        try (Session session = Cli.unlock(port, io)) {
            VaultRecord item = find(session.records(), args.operand(0), io);
            // Checked before anything is printed: a refused --reveal prints no half view.
            if (reveal && !printable(revealable(item))) {
                throw new UsageException(Messages.REVEAL_UNPRINTABLE);
            }
            print(item, io.out(), reveal);
        }
        return ExitCodes.OK;
    }

    /** The one secret {@code --reveal} prints for {@code item}: a login's or a Wi-Fi network's password. */
    @SuppressWarnings("PMD.CloseResource") // CE-087: the record and its password are the session's
    private static SecretBytes revealable(VaultRecord item) throws UsageException {
        if (item instanceof LoginRecord login) {
            return login.password();
        }
        if (item instanceof WifiRecord wifi) {
            return wifi.password();
        }
        if (item instanceof SshKeyRecord) {
            throw new UsageException(Messages.REVEAL_SSH_KEY);
        }
        if (item instanceof ProjectRecord) {
            throw new UsageException(Messages.REVEAL_PROJECT);
        }
        throw new UsageException(Messages.REVEAL_NOTHING);
    }

    /** Every field of {@code item}; secrets masked unless {@code reveal} (then only the password). */
    @SuppressWarnings("PMD.CloseResource") // CE-087: the record is the session's; the PrintWriter is the ConsoleIo's
    private static void print(VaultRecord item, PrintWriter out, boolean reveal) {
        field(out, Messages.FIELD_ID, item.id().toString());
        field(out, Messages.FIELD_TYPE, Cli.typeOf(item));
        field(out, Messages.FIELD_TITLE, item.title());
        if (item instanceof LoginRecord login) {
            field(out, Messages.FIELD_USERNAME, login.username());
            secretField(out, login.password(), reveal);
            field(out, Messages.FIELD_URLS, String.join(LIST_JOIN, login.urls()));
            field(out, Messages.FIELD_TAGS, String.join(LIST_JOIN, login.tags()));
            notesField(out, login.notes());
            field(out, Messages.FIELD_LAST_USED, login.lastUsed().toString());
        } else if (item instanceof WifiRecord wifi) {
            field(out, Messages.FIELD_SSID, wifi.ssid());
            field(out, Messages.FIELD_SECURITY, wifi.security());
            field(out, Messages.FIELD_HIDDEN, (wifi.hidden() ? Messages.VALUE_YES : Messages.VALUE_NO).text());
            secretField(out, wifi.password(), reveal);
            notesField(out, wifi.notes());
        } else if (item instanceof SshKeyRecord key) {
            field(out, Messages.FIELD_KEY_TYPE, key.keyType());
            field(out, Messages.FIELD_FINGERPRINT, key.fingerprint());
            field(out, Messages.FIELD_PUBLIC_KEY, key.publicKey());
            field(out, Messages.FIELD_COMMENT, key.comment());
            field(out, Messages.FIELD_HOSTS, String.join(LIST_JOIN, key.hosts()));
            field(out, Messages.FIELD_PRIVATE_KEY, Messages.VALUE_MASKED.text());
        } else if (item instanceof PasskeyRecord passkey) {
            field(out, Messages.FIELD_SITE, passkey.rpId());
            field(out, Messages.FIELD_ACCOUNT, passkey.accountName());
            field(out, Messages.FIELD_DISPLAY_NAME, passkey.displayName());
            field(out, Messages.FIELD_SIGN_COUNT, Long.toString(passkey.signCount()));
            field(out, Messages.FIELD_LAST_USED, passkey.lastUsed().toString());
        } else {
            ProjectRecord project = (ProjectRecord) item;
            field(out, Messages.FIELD_DIRECTORY, project.canonicalPath());
            field(out, Messages.FIELD_GIT_REMOTE, project.gitRemote());
            for (String profile : ProjectEnv.profiles(project)) {
                // Variable names only; their values leave the vault only through pm env.
                field(out, Messages.FIELD_VARIABLES, profile + PROFILE_SEPARATOR
                        + String.join(LIST_JOIN, ProjectEnv.variables(project, profile).keySet()));
            }
        }
        field(out, Messages.FIELD_CREATED, item.created().toString());
        field(out, Messages.FIELD_UPDATED, item.updated().toString());
    }

    /** One {@code label: value} line; the value is made terminal-safe (IDS01-J). */
    private static void field(PrintWriter out, Messages label, String value) {
        out.println((label(label) + Cli.displaySafe(value)).stripTrailing());
    }

    private static String label(Messages label) {
        return String.format(Locale.ROOT, "%-" + LABEL_WIDTH + "s", label.text() + ":");
    }

    /** Notes: inline when one line, else one indented line each. */
    private static void notesField(PrintWriter out, String notes) {
        List<String> lines = notes.lines().toList();
        if (lines.size() > ONE) {
            field(out, Messages.FIELD_NOTES, "");
            lines.forEach(line -> out.println(INDENT + Cli.displaySafe(line)));
        } else {
            field(out, Messages.FIELD_NOTES, lines.isEmpty() ? "" : lines.get(0));
        }
    }

    private static void secretField(PrintWriter out, SecretBytes stored, boolean reveal) {
        if (stored.length() == 0) {
            field(out, Messages.FIELD_PASSWORD, Messages.VALUE_NONE.text());
        } else if (reveal) {
            revealLine(out, stored);
        } else {
            field(out, Messages.FIELD_PASSWORD, Messages.VALUE_MASKED.text());
        }
    }

    /**
     * Writes the stored password straight from a decoded {@code char[]} that is zeroed at once, so
     * it never becomes a {@code String} (ADR 0008). {@link #printable} was checked first.
     */
    @SecretBoundary(reason = "pm show --reveal prints the one password the user asked for (SR-132)")
    private static void revealLine(PrintWriter out, SecretBytes stored) {
        out.print(label(Messages.FIELD_PASSWORD));
        stored.withBytes(utf8 -> decode(utf8).ifPresent(chars -> {
            try {
                out.write(chars);
            } finally {
                Arrays.fill(chars, '\0');
            }
        }));
        out.println();
    }

    /** Whether {@code stored} is well-formed UTF-8 with no code point unsafe on a terminal (IDS01-J). */
    private static boolean printable(SecretBytes stored) {
        return stored.apply(utf8 -> decode(utf8).map(RecordCommands::safeThenZeroed).orElse(false));
    }

    private static boolean safeThenZeroed(char[] chars) {
        try {
            return CharBuffer.wrap(chars).codePoints().noneMatch(RecordCommands::unsafeToReveal);
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Unsafe on a terminal ({@link Cli#isUnsafe}), or shown as nothing or as a blank, so a password
     * read off the screen would be wrong (m77-004): any space but U+0020, the braille blank, and
     * the default-ignorable code points of Unicode (DerivedCoreProperties) outside the format
     * category, such as the Hangul fillers, U+034F and the variation selectors.
     */
    static boolean unsafeToReveal(int cp) {
        return Cli.isUnsafe(cp) || (Character.isSpaceChar(cp) && cp != ' ') || cp == BRAILLE_BLANK
                || cp == 0x034F || cp == 0x115F || cp == 0x1160 || cp == 0x17B4 || cp == 0x17B5
                || (cp >= 0x180B && cp <= 0x180F) || cp == 0x3164 || (cp >= 0xFE00 && cp <= 0xFE0F)
                || cp == 0xFFA0 || (cp >= 0xFFF0 && cp <= 0xFFF8) || (cp >= 0x1BCA0 && cp <= 0x1BCA3)
                || (cp >= 0x1D173 && cp <= 0x1D17A) || (cp >= 0xE0000 && cp <= 0xE0FFF);
    }

    /** Strict UTF-8 decoding into a new array the caller zeroes; empty for malformed input. */
    private static Optional<char[]> decode(byte[] utf8) {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        // UTF-8 never decodes to more UTF-16 units than it has bytes.
        CharBuffer decoded = CharBuffer.allocate(utf8.length);
        try {
            CoderResult result = decoder.decode(ByteBuffer.wrap(utf8), decoded, true);
            if (result.isUnderflow()) {
                result = decoder.flush(decoded);
            }
            if (!result.isUnderflow()) {
                return Optional.empty();
            }
            decoded.flip();
            char[] chars = new char[decoded.remaining()];
            decoded.get(chars);
            return Optional.of(chars);
        } finally {
            Arrays.fill(decoded.array(), '\0');
        }
    }

    // ---- edit --------------------------------------------------------------------------------

    /** {@code pm edit <item> <options>}: changes a login or a Wi-Fi network. */
    @SuppressWarnings("PMD.CloseResource") // CE-087: the old record is the session's; the new one is handed over
    int edit(List<String> words, VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        Set<String> flags = new HashSet<>(GenerateCommand.FLAGS);
        flags.addAll(Set.of(HIDDEN, NOT_HIDDEN, ASK, GENERATE));
        Set<String> valued = new HashSet<>(GenerateCommand.VALUED);
        valued.addAll(Set.of(TITLE, USERNAME, URLS, TAGS, NOTES, SSID, SECURITY));
        CommandArgs args = CommandArgs.parse(words, flags, valued, EMPTY_PASSED_ON).arity(ONE);
        checkEdit(args);
        try (Session session = Cli.unlock(port, io)) {
            VaultRecord item = find(session.records(), args.operand(0), io);
            Edited edited;
            if (item instanceof LoginRecord login) {
                refuse(args, WIFI_ONLY, Messages.EDIT_WIFI_ONLY);
                edited = editLogin(login, args, io);
            } else if (item instanceof WifiRecord wifi) {
                refuse(args, LOGIN_ONLY, Messages.EDIT_LOGIN_ONLY);
                edited = editWifi(wifi, args, io);
            } else {
                throw new UsageException(Messages.EDIT_UNSUPPORTED);
            }
            UUID id = edited.record().id();
            Cli.handOver(session, edited.record());
            session.save();
            io.out().println(Messages.EDITED.text() + id);
            if (edited.entropy().isPresent()) {
                io.out().println(Messages.EDIT_GENERATED.text()
                        + String.format(Locale.ROOT, "%.1f", edited.entropy().getAsDouble()));
            }
        }
        return ExitCodes.OK;
    }

    private static void checkEdit(CommandArgs args) throws UsageException {
        boolean generatorOptions = Stream.concat(GenerateCommand.FLAGS.stream(), GenerateCommand.VALUED.stream())
                .anyMatch(args::given);
        if (generatorOptions && !args.has(GENERATE)) {
            throw new UsageException(Messages.EDIT_GENERATE_OPTIONS);
        }
        if (CHANGES.stream().noneMatch(args::given)) {
            throw new UsageException(Messages.EDIT_NOTHING);
        }
        if (args.has(ASK) && args.has(GENERATE)) {
            throw new UsageException(Messages.EDIT_TWO_SOURCES);
        }
        if (args.has(HIDDEN) && args.has(NOT_HIDDEN)) {
            throw new UsageException(Messages.EDIT_HIDDEN_BOTH);
        }
    }

    private static void refuse(CommandArgs args, Set<String> options, Messages reason) throws UsageException {
        if (options.stream().anyMatch(args::given)) {
            throw new UsageException(reason);
        }
    }

    private Edited editLogin(LoginRecord old, CommandArgs args, ConsoleIo io) throws UsageException {
        String title = newTitle(args, old.title());
        String username = text(args, USERNAME).orElse(old.username());
        List<String> urls = text(args, URLS).map(Cli::splitList).orElse(old.urls());
        List<String> tags = text(args, TAGS).map(Cli::splitList).orElse(old.tags());
        String notes = text(args, NOTES).orElse(old.notes());
        Fresh fresh = fresh(args, io, old.password());
        return build(fresh, () -> new LoginRecord(old.id(), title, username, fresh.bytes(), urls, notes, tags,
                old.created(), clock.instant(), old.lastUsed()));
    }

    private Edited editWifi(WifiRecord old, CommandArgs args, ConsoleIo io) throws UsageException {
        String title = newTitle(args, old.title());
        String ssid = text(args, SSID).orElse(old.ssid());
        if (ssid.isEmpty()) {
            throw new UsageException(Messages.EMPTY_SSID);
        }
        Optional<String> securityText = text(args, SECURITY);
        String security = securityText.isPresent() ? securityType(securityText.get()) : old.security();
        boolean hidden = args.has(HIDDEN) || (old.hidden() && !args.has(NOT_HIDDEN));
        String notes = text(args, NOTES).orElse(old.notes());
        Fresh fresh;
        if (OPEN.equals(security)) {
            if (args.has(ASK) || args.has(GENERATE)) {
                throw new UsageException(Messages.OPEN_HAS_NO_PASSWORD);
            }
            fresh = new Fresh(SecretBytes.copyOf(new byte[0]), OptionalDouble.empty());
        } else {
            if (!args.has(ASK) && !args.has(GENERATE) && old.password().length() == 0) {
                throw new UsageException(Messages.WIFI_NEEDS_PASSWORD);
            }
            fresh = fresh(args, io, old.password());
        }
        Fresh secret = fresh;
        return build(secret, () -> new WifiRecord(old.id(), title, ssid, security, secret.bytes(), hidden, notes,
                old.created(), clock.instant()));
    }

    /** The new secret: typed twice ({@code --password}), generated ({@code --generate}) or a copy of {@code current}. */
    private static Fresh fresh(CommandArgs args, ConsoleIo io, SecretBytes current) throws UsageException {
        if (args.has(ASK)) {
            return new Fresh(typedTwice(io, Messages.PROMPT_NEW_PASSWORD), OptionalDouble.empty());
        }
        if (args.has(GENERATE)) {
            try (Generated generated = GenerateCommand.generate(args)) {
                return new Fresh(Cli.utf8(generated.secret()), OptionalDouble.of(generated.entropyBits()));
            }
        }
        return new Fresh(current.apply(SecretBytes::copyOf), OptionalDouble.empty());
    }

    /** Builds a record around {@code fresh}, closing it if the record's bounds reject the fields. */
    private static Edited build(Fresh fresh, Supplier<VaultRecord> make) throws UsageException {
        try {
            return new Edited(make.get(), fresh.entropy());
        } catch (IllegalArgumentException e) {
            fresh.bytes().close();
            throw new UsageException(Messages.INVALID_RECORD);
        }
    }

    private static String newTitle(CommandArgs args, String current) throws UsageException {
        String title = text(args, TITLE).orElse(current);
        if (title.isEmpty()) {
            throw new UsageException(Messages.EMPTY_TITLE);
        }
        return title;
    }

    /** An option's value, stripped; {@link CommandArgs} has already refused unsafe text (IDS01-J). */
    private static Optional<String> text(CommandArgs args, String option) {
        return args.value(option).map(String::strip);
    }

    private static String securityType(String text) throws UsageException {
        String upper = text.strip().toUpperCase(Locale.ROOT);
        if (!SECURITY_TYPES.contains(upper)) {
            throw new UsageException(Messages.BAD_SECURITY);
        }
        return upper;
    }

    /** A new secret read twice from the prompt, never from the command line, as UTF-8 (SR-133). */
    private static SecretBytes typedTwice(ConsoleIo io, Messages prompt) throws UsageException {
        try (SecretChars first = Cli.readSecret(io, prompt, Messages.EMPTY_PASSWORD);
                SecretChars second = Cli.readSecret(io, Messages.PROMPT_REPEAT_PASSWORD, Messages.EMPTY_PASSWORD)) {
            if (!Cli.sameSecret(first, second)) {
                throw new UsageException(Messages.PASSWORD_MISMATCH);
            }
            return Cli.utf8(first);
        }
    }

    /** A new secret and, when generated, its entropy. */
    private record Fresh(SecretBytes bytes, OptionalDouble entropy) {
    }

    /** An edited record, not yet handed to the session, and the entropy of a generated password. */
    private record Edited(VaultRecord record, OptionalDouble entropy) {
    }

    // ---- rm ----------------------------------------------------------------------------------

    /** {@code pm rm <item> [--yes]}: removes any item after a {@code y}, or at once with {@code --yes}. */
    @SuppressWarnings("PMD.CloseResource") // CE-087: the record is the session's; remove retires it
    int rm(List<String> words, VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        CommandArgs args = CommandArgs.parse(words, Set.of(YES), Set.of()).arity(ONE);
        try (Session session = Cli.unlock(port, io)) {
            VaultRecord item = find(session.records(), args.operand(0), io);
            UUID id = item.id();
            io.out().println(Messages.RM_ITEM.text() + Cli.row(item));
            if (item instanceof SshKeyRecord) {
                io.out().println(Messages.RM_SSH_AGENT.text());
            }
            io.out().flush();
            if (!args.has(YES) && !LanCommands.confirmed(io, Messages.RM_CONFIRM)) {
                io.err().println(Messages.RM_CANCELLED.text());
                return ExitCodes.DENIED;
            }
            session.remove(id); // closes the record (ADR 0008); it was just found, so it is there
            session.save();
            io.out().println(Messages.REMOVED.text() + id);
        }
        return ExitCodes.OK;
    }

    // ---- wifi add ----------------------------------------------------------------------------

    /** {@code pm wifi add <ssid> [--title T] [--security S] [--hidden] [--notes N]}. */
    @SuppressWarnings("PMD.CloseResource") // CE-087: the PSK is owned by the record built around it, which is handed over
    int wifiAdd(List<String> words, VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        CommandArgs args = CommandArgs.parse(words, Set.of(HIDDEN), Set.of(TITLE, SECURITY, NOTES), Set.of(TITLE))
                .arity(ONE);
        String ssid = args.operand(0).strip();
        if (ssid.isEmpty()) {
            throw new UsageException(Messages.EMPTY_SSID);
        }
        String title = newTitle(args, ssid);
        String security = securityType(text(args, SECURITY).orElse(DEFAULT_SECURITY));
        String notes = text(args, NOTES).orElse("");
        boolean hidden = args.has(HIDDEN);
        try (Session session = Cli.unlock(port, io)) {
            SecretBytes psk = OPEN.equals(security) ? SecretBytes.copyOf(new byte[0])
                    : typedTwice(io, Messages.PROMPT_WIFI_PASSWORD);
            UUID id = Csprng.uuid();
            Instant now = clock.instant();
            Edited added = build(new Fresh(psk, OptionalDouble.empty()),
                    () -> new WifiRecord(id, title, ssid, security, psk, hidden, notes, now, now));
            Cli.handOver(session, added.record());
            session.save();
            io.out().println(Messages.WIFI_ADDED.text() + id);
        }
        return ExitCodes.OK;
    }

    // ---- lookup ------------------------------------------------------------------------------

    /**
     * The item named by id, else by exact title. Several items with the title are refused and
     * listed on stderr with their ids; internal device records are never found.
     */
    static VaultRecord find(List<VaultRecord> records, String item, ConsoleIo io) throws UsageException {
        List<VaultRecord> visible = records.stream().filter(r -> !DeviceRecord.isInternal(r)).toList();
        List<VaultRecord> byId = visible.stream().filter(r -> r.id().toString().equals(item)).toList();
        List<VaultRecord> matches =
                byId.isEmpty() ? visible.stream().filter(r -> r.title().equals(item)).toList() : byId;
        if (matches.isEmpty()) {
            throw new UsageException(Messages.NO_SUCH_RECORD);
        }
        if (matches.size() > ONE) {
            io.err().println(Messages.LIST_HEADER.text());
            matches.forEach(r -> io.err().println(Cli.row(r)));
            throw new UsageException(Messages.AMBIGUOUS_RECORD);
        }
        return matches.get(0);
    }
}
