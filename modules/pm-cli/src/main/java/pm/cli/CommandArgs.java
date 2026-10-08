package pm.cli;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Options of one M4 subcommand ({@code generate}, {@code health}, {@code ssh ...}): boolean flags,
 * options that take exactly one value, and operands. {@code --} ends the options. Values are kept
 * as typed (a passphrase separator may be a space) but must not hold control or invisible
 * formatting characters (IDS01-J); an unknown or repeated option is a usage error.
 */
final class CommandArgs {
    private static final String END_OF_OPTIONS = "--";
    private static final String OPTION_PREFIX = "-";
    private static final int MAX_NUMBER_DIGITS = 9;

    private final List<String> positional;
    private final Set<String> flagsGiven;
    private final Map<String, String> valuesGiven;

    private CommandArgs(List<String> positional, Set<String> flagsGiven, Map<String, String> valuesGiven) {
        this.positional = List.copyOf(positional);
        this.flagsGiven = Set.copyOf(flagsGiven);
        this.valuesGiven = Map.copyOf(valuesGiven);
    }

    /**
     * Parses {@code raw} against the known {@code flags} and {@code valued} option names.
     *
     * @throws UsageException for an unknown or repeated option, a missing value, or unsafe text
     */
    static CommandArgs parse(List<String> raw, Set<String> flags, Set<String> valued) throws UsageException {
        return parse(raw, flags, valued, Set.of());
    }

    /**
     * As {@link #parse(List, Set, Set)}, except that the options in {@code clearable} may also be
     * given the empty value ({@code --notes ""}), which {@code pm edit} reads as "clear this field".
     *
     * @throws UsageException for an unknown or repeated option, a missing value, or unsafe text
     */
    static CommandArgs parse(List<String> raw, Set<String> flags, Set<String> valued, Set<String> clearable)
            throws UsageException {
        Deque<String> in = new ArrayDeque<>(raw);
        List<String> operands = new ArrayList<>();
        Set<String> seenFlags = new HashSet<>();
        Map<String, String> values = new HashMap<>();
        while (!in.isEmpty()) {
            String a = in.removeFirst();
            if (END_OF_OPTIONS.equals(a)) {
                operands.addAll(in);
                in.clear();
            } else if (flags.contains(a)) {
                if (!seenFlags.add(a)) {
                    throw new UsageException(Messages.DUPLICATE_OPTION);
                }
            } else if (valued.contains(a)) {
                if (values.containsKey(a)) {
                    throw new UsageException(Messages.DUPLICATE_OPTION);
                }
                if (in.isEmpty()) {
                    throw new UsageException(Messages.WRONG_ARG_COUNT);
                }
                values.put(a, in.removeFirst());
            } else if (a.startsWith(OPTION_PREFIX) && a.length() > 1) {
                throw new UsageException(Messages.UNKNOWN_OPTION);
            } else {
                operands.add(a);
            }
        }
        for (String text : operands) {
            checkText(text);
        }
        for (Map.Entry<String, String> option : values.entrySet()) {
            if (!option.getValue().isEmpty() || !clearable.contains(option.getKey())) {
                checkText(option.getValue());
            }
        }
        return new CommandArgs(operands, seenFlags, values);
    }

    private static void checkText(String text) throws UsageException {
        if (text.isEmpty() || Cli.hasUnsafeChars(text)) {
            throw new UsageException(Messages.INVALID_TEXT);
        }
    }

    /** The operands, in order. */
    List<String> operands() {
        return positional;
    }

    /** The operand at {@code index}. */
    String operand(int index) {
        return positional.get(index);
    }

    /** Requires exactly {@code n} operands. */
    CommandArgs arity(int n) throws UsageException {
        if (positional.size() != n) {
            throw new UsageException(Messages.WRONG_ARG_COUNT);
        }
        return this;
    }

    /** Whether the flag {@code name} was given. */
    boolean has(String name) {
        return flagsGiven.contains(name);
    }

    /** The value of option {@code name}, if given. */
    Optional<String> value(String name) {
        return Optional.ofNullable(valuesGiven.get(name));
    }

    /** Whether option {@code name} (flag or valued) was given at all. */
    boolean given(String name) {
        return flagsGiven.contains(name) || valuesGiven.containsKey(name);
    }

    /**
     * A small non-negative decimal number: ASCII digits only, at most nine of them, so it always
     * fits an {@code int} (NUM00-J).
     *
     * @throws UsageException with {@code onError} if the text is not such a number
     */
    static int number(String text, Messages onError) throws UsageException {
        if (text.isEmpty() || text.length() > MAX_NUMBER_DIGITS
                || !text.chars().allMatch(c -> c >= '0' && c <= '9')) {
            throw new UsageException(onError);
        }
        return Integer.parseInt(text);
    }
}
