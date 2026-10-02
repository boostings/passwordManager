package pm.crypto.log;

/**
 * Project logger over {@link System.Logger} that refuses secret-bearing arguments (SR-500): any
 * {@code SecretBytes}, {@code SecretChars}, {@code byte[]}, {@code char[]}, or {@code @Sensitive}
 * instance throws {@link IllegalArgumentException}.
 */
@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)
public final class SafeLog {
    private SafeLog() {
    }

    /** Logger named after {@code owner}. */
    public static SafeLog of(Class<?> owner) {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Logs {@code eventCode} at INFO. */
    public void info(String eventCode, Object... args) {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Logs {@code eventCode} at WARNING. */
    public void warn(String eventCode, Object... args) {
        throw new UnsupportedOperationException("M1 stub");
    }

    /** Logs {@code eventCode} at ERROR. */
    public void error(String eventCode, Object... args) {
        throw new UnsupportedOperationException("M1 stub");
    }
}
