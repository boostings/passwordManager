package pm.cli;

import java.io.PrintWriter;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import pm.crypto.SecretBoundary;
import pm.domain.generate.CharClass;
import pm.domain.generate.Generated;
import pm.domain.generate.PassphraseGenerator;
import pm.domain.generate.PassphrasePolicy;
import pm.domain.generate.PasswordGenerator;
import pm.domain.generate.PasswordPolicy;

/**
 * {@code pm generate} (plan.md §13 M4.4, ADR 0012): a random password or passphrase from
 * {@code pm.domain.generate}, drawn from {@code Csprng} by rejection sampling.
 *
 * <pre>
 * pm generate [--length N] [--classes lower,upper,digit,symbol] [--exclude-ambiguous]
 * pm generate --passphrase [--words N] [--separator C]
 * </pre>
 *
 * <p>The secret is written to stdout exactly once, straight from its {@code char[]} buffer, and is
 * never logged, stored or turned into a {@code String} (SR-072, ADR 0008). The entropy line goes to
 * stderr, so {@code pm generate | pbcopy} carries only the secret. pm has no clipboard integration
 * yet, so printing once is the only output.
 */
final class GenerateCommand {
    static final String LENGTH = "--length";
    static final String CLASSES = "--classes";
    static final String EXCLUDE_AMBIGUOUS = "--exclude-ambiguous";
    static final String PASSPHRASE_FLAG = "--passphrase";
    static final String WORDS = "--words";
    static final String SEPARATOR = "--separator";

    private static final int SEPARATOR_CHARS = 1;
    private static final Set<String> FLAGS = Set.of(EXCLUDE_AMBIGUOUS, PASSPHRASE_FLAG);
    private static final Set<String> VALUED = Set.of(LENGTH, CLASSES, WORDS, SEPARATOR);

    private GenerateCommand() {
    }

    /** Runs {@code pm generate} with the arguments after the command word. */
    static int run(List<String> sub, ConsoleIo io) throws UsageException {
        CommandArgs args = CommandArgs.parse(sub, FLAGS, VALUED).arity(0);
        boolean passphrase = args.has(PASSPHRASE_FLAG);
        boolean passwordOptions = args.given(LENGTH) || args.given(CLASSES) || args.given(EXCLUDE_AMBIGUOUS);
        boolean passphraseOptions = args.given(WORDS) || args.given(SEPARATOR);
        if (passphrase ? passwordOptions : passphraseOptions) {
            throw new UsageException(Messages.GENERATE_MIXED_OPTIONS);
        }
        try (Generated generated = passphrase ? newPassphrase(args) : newPassword(args)) {
            printOnce(generated, io.out());
            io.err().println(Messages.GENERATED_ENTROPY.text() + String.format(Locale.ROOT, "%.1f", generated.entropyBits()));
        }
        if (io.out().checkError()) {
            io.err().println(Messages.ERR_TERMINAL.text());
            return ExitCodes.STORAGE;
        }
        return ExitCodes.OK;
    }

    /** The password policy from the options; the defaults are ADR 0012's (20 characters, all classes). */
    static PasswordPolicy passwordPolicy(CommandArgs args) throws UsageException {
        int length = PasswordPolicy.DEFAULT_LENGTH;
        Optional<String> lengthText = args.value(LENGTH);
        if (lengthText.isPresent()) {
            length = CommandArgs.number(lengthText.get(), Messages.BAD_GENERATE_POLICY);
        }
        Set<CharClass> classes = EnumSet.allOf(CharClass.class);
        Optional<String> classText = args.value(CLASSES);
        if (classText.isPresent()) {
            classes = parseClasses(classText.get());
        }
        try {
            return new PasswordPolicy(length, classes, args.has(EXCLUDE_AMBIGUOUS));
        } catch (IllegalArgumentException e) {
            throw new UsageException(Messages.BAD_GENERATE_POLICY);
        }
    }

    /** The passphrase policy from the options; the defaults are six words joined by {@code -}. */
    static PassphrasePolicy passphrasePolicy(CommandArgs args) throws UsageException {
        int words = PassphrasePolicy.DEFAULT_WORDS;
        Optional<String> wordsText = args.value(WORDS);
        if (wordsText.isPresent()) {
            words = CommandArgs.number(wordsText.get(), Messages.BAD_GENERATE_POLICY);
        }
        char separator = PassphrasePolicy.DEFAULT_SEPARATOR;
        Optional<String> separatorText = args.value(SEPARATOR);
        if (separatorText.isPresent()) {
            if (separatorText.get().length() != SEPARATOR_CHARS) {
                throw new UsageException(Messages.BAD_GENERATE_POLICY);
            }
            separator = separatorText.get().charAt(0);
        }
        try {
            return new PassphrasePolicy(words, separator);
        } catch (IllegalArgumentException e) {
            throw new UsageException(Messages.BAD_GENERATE_POLICY);
        }
    }

    private static Generated newPassword(CommandArgs args) throws UsageException {
        return PasswordGenerator.secure().generate(passwordPolicy(args));
    }

    private static Generated newPassphrase(CommandArgs args) throws UsageException {
        return PassphraseGenerator.secure().generate(passphrasePolicy(args));
    }

    private static Set<CharClass> parseClasses(String list) throws UsageException {
        Set<CharClass> out = EnumSet.noneOf(CharClass.class);
        for (String name : list.split(",", -1)) {
            out.add(switch (name.strip()) {
                case "lower" -> CharClass.LOWER;
                case "upper" -> CharClass.UPPER;
                case "digit", "digits" -> CharClass.DIGIT;
                case "symbol", "symbols" -> CharClass.SYMBOL;
                default -> throw new UsageException(Messages.BAD_GENERATE_POLICY);
            });
        }
        return out;
    }

    /** Writes the secret once, from its buffer, followed by a line break (ADR 0008, SR-072). */
    @SecretBoundary(reason = "show a generated secret once on stdout")
    private static void printOnce(Generated generated, PrintWriter out) {
        generated.secret().withChars(out::write);
        out.println();
        out.flush();
    }
}
