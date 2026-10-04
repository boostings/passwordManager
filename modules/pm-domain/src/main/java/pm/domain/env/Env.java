package pm.domain.env;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

/**
 * The validating accessor for process environment variables (ENV02-J, trust-boundaries.md). It is
 * the only class allowed to read the environment (Semgrep {@code cert.ENV02-J}). Only the
 * variables in {@link Var} can be read, and a value that fails its check is reported as unset:
 * the environment is attacker-influenced input, so a malformed value is never passed on.
 */
public final class Env {
    /** Longest value accepted for any variable. */
    static final int MAX_VALUE_CHARS = 4_096;

    private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9._+-]{1,64}");

    /**
     * Variables the JVM or the {@code java} launcher read as extra JVM options before {@code main}
     * runs. They can undo the hardening flags baked into the release runtime (SR-711), so pm
     * refuses to start when any is set.
     */
    private static final List<String> JVM_OPTION_VARIABLES =
            List.of("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS");

    /** How a variable's value is checked. */
    private enum Kind {
        /** An absolute filesystem path. */
        PATH,
        /** A short word such as {@code truecolor} or {@code xterm-256color}. */
        TOKEN
    }

    /** The variables pm reads, and the check each must pass. */
    public enum Var {
        /** User home directory (POSIX). */
        HOME(Kind.PATH),
        /** Per-user runtime directory (Linux). */
        XDG_RUNTIME_DIR(Kind.PATH),
        /** Per-user state directory (Linux). */
        XDG_STATE_HOME(Kind.PATH),
        /** Per-user configuration directory (Linux). */
        XDG_CONFIG_HOME(Kind.PATH),
        /** Roaming application data (Windows). */
        APPDATA(Kind.PATH),
        /** Local application data (Windows). */
        LOCALAPPDATA(Kind.PATH),
        /** The ssh-agent socket. */
        SSH_AUTH_SOCK(Kind.PATH),
        /** Terminal color capability, for example {@code truecolor}. */
        COLORTERM(Kind.TOKEN),
        /** Terminal type. */
        TERM(Kind.TOKEN);

        private final Kind kind;

        Var(Kind kind) {
            this.kind = kind;
        }
    }

    private final UnaryOperator<String> source;

    private Env(UnaryOperator<String> source) {
        this.source = source;
    }

    /** The real process environment. */
    public static Env system() {
        return new Env(System::getenv);
    }

    /** A fixed environment, for tests and for callers that captured one. */
    public static Env of(Map<String, String> values) {
        Map<String, String> copy = Map.copyOf(values);
        return new Env(copy::get);
    }

    /** The value of {@code var} if it is set and passes its check; empty otherwise. */
    public Optional<String> get(Var var) {
        Objects.requireNonNull(var, "var");
        String value = source.apply(var.name());
        if (value == null || value.isEmpty() || value.length() > MAX_VALUE_CHARS || hasControl(value)) {
            return Optional.empty();
        }
        boolean valid = switch (var.kind) {
            case TOKEN -> TOKEN.matcher(value).matches();
            case PATH -> isAbsolutePath(value);
        };
        return valid ? Optional.of(value) : Optional.empty();
    }

    /**
     * Whether any of {@code JAVA_TOOL_OPTIONS}, {@code _JAVA_OPTIONS} or {@code JDK_JAVA_OPTIONS}
     * is set to a non-empty value. Only presence is reported; the value is never read out or
     * returned (SR-711).
     */
    public boolean jvmOptionsInjected() {
        return JVM_OPTION_VARIABLES.stream().map(source).anyMatch(v -> v != null && !v.isEmpty());
    }

    /**
     * The value of a {@code PATH} variable as a normalized absolute path.
     *
     * @throws IllegalArgumentException if {@code var} is not a path variable
     */
    public Optional<Path> path(Var var) {
        if (var.kind != Kind.PATH) {
            throw new IllegalArgumentException("NOT_A_PATH_VARIABLE");
        }
        return get(var).map(v -> Path.of(v).normalize());
    }

    private static boolean hasControl(String value) {
        return value.chars().anyMatch(c -> c < 0x20 || c == 0x7f);
    }

    private static boolean isAbsolutePath(String value) {
        try {
            return Path.of(value).isAbsolute();
        } catch (InvalidPathException e) {
            return false;
        }
    }
}
