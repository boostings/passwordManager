package pm.crypto.log;

import java.util.Objects;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.crypto.Sensitive;

/**
 * Project logger over {@link System.Logger} that refuses secret-bearing arguments (SR-500): any
 * {@code SecretBytes}, {@code SecretChars}, {@code byte[]}, {@code char[]}, or {@code @Sensitive}
 * instance throws {@link IllegalArgumentException}. Allowed arguments are rendered with
 * {@link String#valueOf(Object)} after the event code, space-separated.
 */
public final class SafeLog {
    private final System.Logger logger;

    private SafeLog(System.Logger logger) {
        this.logger = logger;
    }

    /** Logger named after {@code owner}. */
    public static SafeLog of(Class<?> owner) {
        Objects.requireNonNull(owner, "owner");
        return new SafeLog(System.getLogger(owner.getName()));
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
        StringBuilder line = new StringBuilder(eventCode);
        if (args != null) {
            for (Object arg : args) {
                if (refused(arg)) {
                    throw new IllegalArgumentException("SECRET_ARG");
                }
            }
            for (Object arg : args) {
                line.append(' ').append(String.valueOf(arg));
            }
        }
        logger.log(level, line.toString());
    }

    private static boolean refused(Object arg) {
        return arg instanceof SecretBytes
                || arg instanceof SecretChars
                || arg instanceof byte[]
                || arg instanceof char[]
                || (arg != null && arg.getClass().isAnnotationPresent(Sensitive.class));
    }
}
