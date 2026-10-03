package pm.crypto.log;

import java.nio.file.Path;
import java.time.Duration;
import java.time.temporal.TemporalAccessor;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.crypto.Sensitive;

/**
 * Project logger over {@link System.Logger} that accepts only arguments known to be free of
 * secrets (SR-500, FIO13-J).
 *
 * <p><b>Allowlist, not blocklist.</b> An argument is logged only if it is {@code null} or one of:
 * {@link String}, {@link Boolean}, {@link Character}, {@link UUID}, {@link Duration}, an
 * {@link Enum} constant (rendered by {@link Enum#name()}, so an overridden {@code toString} is
 * never called), one of the boxed primitives {@link Integer}, {@link Long}, {@link Short},
 * {@link Byte}, {@link Float} or {@link Double}, or a {@link TemporalAccessor} or {@link Path} whose
 * runtime class is a JDK class in {@code java.base} (so a project subclass cannot smuggle state out
 * through {@code toString}). Everything else throws {@link IllegalArgumentException}.
 *
 * <p>Other {@link Number}s are refused even though they live in {@code java.base}:
 * {@code BigInteger}, {@code BigDecimal} and the {@code Atomic*}/{@code *Adder} types can hold a
 * whole key ({@code new BigInteger(1, keyBytes)}) and print it in full. A boxed primitive carries
 * at most 64 bits.
 *
 * <p>SR-500 requires that no secret reaches any log. A blocklist that inspects the top-level
 * argument type cannot meet that: a secret travels just as well inside a {@code CharBuffer}, a
 * {@code StringBuilder}, a collection, an {@code Optional}, a map value, an array, or a subclass of
 * a sensitive type, and walking those containers recursively would still trust every
 * {@code toString} it ends up calling. An allowlist of value types whose rendering we know closes
 * all of those paths at once, and a new container type is refused by default instead of being a
 * new leak. {@link String} remains allowed; keeping secrets out of {@code String} is the job of
 * MSC03-J and the Semgrep rules that enforce it.
 *
 * <p>{@code SecretBytes}, {@code SecretChars}, {@code byte[]}, {@code char[]} and {@code @Sensitive}
 * types (including subclasses, since {@code Sensitive} is {@code @Inherited}) are also refused
 * explicitly, with the code {@code SECRET_ARG}; the allowlist would refuse them anyway.
 *
 * <p>The event code must match {@code [A-Z][A-Z0-9_]{0,63}}, so free text (and any secret
 * concatenated into it) cannot be passed as the event code. Refusal messages never echo the
 * rejected value.
 *
 * <p><b>One event, one line (IDS03-J).</b> A {@link String}, {@link Character} or {@link Path}
 * argument can hold text the program did not write (a record title, a file name). Every control
 * character in a rendered argument (CR, LF, TAB, ESC, NEL and the rest of C0/C1) and the Unicode
 * line and paragraph separators U+2028/U+2029 is written as six plain characters instead: a
 * backslash, the letter {@code u} and the four lower-case hex digits of the character (a line feed
 * becomes backslash, {@code u000a}). So an argument cannot end the record and start a forged one,
 * or drive the terminal the log is read on. All other text is logged unchanged.
 */
public final class SafeLog {
    private static final Pattern EVENT_CODE = Pattern.compile("[A-Z][A-Z0-9_]{0,63}");
    private static final Module JAVA_BASE = Object.class.getModule();
    private static final String ESCAPE_PREFIX = "\\u";
    private static final HexFormat HEX = HexFormat.of();

    private final System.Logger logger;

    private SafeLog(System.Logger logger) {
        this.logger = logger;
    }

    /** Logger named after {@code owner}. */
    public static SafeLog of(Class<?> owner) {
        Objects.requireNonNull(owner, "owner");
        return new SafeLog(System.getLogger(owner.getName()));
    }

    /** Logger writing to {@code logger}; lets tests capture what is emitted. */
    static SafeLog over(System.Logger logger) {
        return new SafeLog(Objects.requireNonNull(logger, "logger"));
    }

    /** Logs {@code eventCode} at INFO. */
    public void info(String eventCode, Object... args) {
        emit(System.Logger.Level.INFO, eventCode, args);
    }

    /** Logs {@code eventCode} at WARNING. */
    public void warn(String eventCode, Object... args) {
        emit(System.Logger.Level.WARNING, eventCode, args);
    }

    /** Logs {@code eventCode} at ERROR. */
    public void error(String eventCode, Object... args) {
        emit(System.Logger.Level.ERROR, eventCode, args);
    }

    private void emit(System.Logger.Level level, String eventCode, Object... args) {
        Objects.requireNonNull(eventCode, "eventCode");
        if (!EVENT_CODE.matcher(eventCode).matches()) {
            throw new IllegalArgumentException("BAD_EVENT_CODE");
        }
        StringBuilder line = new StringBuilder(eventCode);
        if (args != null) {
            for (Object arg : args) {
                if (secret(arg)) {
                    throw new IllegalArgumentException("SECRET_ARG");
                }
                if (!allowed(arg)) {
                    throw new IllegalArgumentException("UNLOGGABLE_ARG");
                }
            }
            for (Object arg : args) {
                line.append(' ');
                appendNeutralised(line, render(arg));
            }
        }
        logger.log(level, line.toString());
    }

    /** IDS03-J: appends {@code text} with every record-breaking character replaced by its escape. */
    private static void appendNeutralised(StringBuilder line, String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (recordBreaking(c)) {
                line.append(ESCAPE_PREFIX).append(HEX.toHexDigits(c));
            } else {
                line.append(c);
            }
        }
    }

    /** Control characters (Unicode category Cc: C0, DEL and C1) and the U+2028/U+2029 separators. */
    private static boolean recordBreaking(char c) {
        int type = Character.getType(c);
        return type == Character.CONTROL
                || type == Character.LINE_SEPARATOR
                || type == Character.PARAGRAPH_SEPARATOR;
    }

    private static boolean secret(Object arg) {
        return arg instanceof SecretBytes
                || arg instanceof SecretChars
                || arg instanceof byte[]
                || arg instanceof char[]
                || (arg != null && arg.getClass().isAnnotationPresent(Sensitive.class));
    }

    private static boolean allowed(Object arg) {
        if (arg == null
                || arg instanceof String
                || arg instanceof Boolean
                || arg instanceof Character
                || arg instanceof UUID
                || arg instanceof Duration
                || arg instanceof Enum<?>
                || boxedPrimitiveNumber(arg)) {
            return true;
        }
        boolean jdkValue = arg instanceof TemporalAccessor || arg instanceof Path;
        return jdkValue && arg.getClass().getModule() == JAVA_BASE;
    }

    /** Exactly the java.base boxed primitives; all are final, so {@code instanceof} is an exact match. */
    private static boolean boxedPrimitiveNumber(Object arg) {
        return arg instanceof Integer
                || arg instanceof Long
                || arg instanceof Short
                || arg instanceof Byte
                || arg instanceof Float
                || arg instanceof Double;
    }

    private static String render(Object arg) {
        return arg instanceof Enum<?> e ? e.name() : String.valueOf(arg);
    }
}
