package pm.sharing.wire;

import java.util.Objects;
import java.util.regex.Pattern;

/** Field validation shared by the message records; failures are {@link IllegalArgumentException}. */
final class Checks {
    private static final Pattern TOKEN_PATTERN = Pattern.compile("[a-z0-9_-]{1,32}");

    private Checks() {
    }

    static Octets length(Octets value, int min, int max) {
        int n = Objects.requireNonNull(value, "value").length();
        if (n < min || n > max) {
            throw new IllegalArgumentException("BAD_LENGTH");
        }
        return value;
    }

    /**
     * Text a peer chose that a screen will show: 1..{@code maxChars} UTF-16 units, no control or
     * format characters (so no line breaks, escape sequences or bidi overrides).
     */
    static String label(String value, int maxChars) {
        Objects.requireNonNull(value, "value");
        if (value.isEmpty() || value.length() > maxChars || !value.codePoints().allMatch(Checks::shown)) {
            throw new IllegalArgumentException("BAD_TEXT");
        }
        return value;
    }

    private static boolean shown(int cp) {
        return !Character.isISOControl(cp) && Character.getType(cp) != Character.FORMAT;
    }

    static String token(String value) {
        if (!TOKEN_PATTERN.matcher(Objects.requireNonNull(value, "value")).matches()) {
            throw new IllegalArgumentException("BAD_TOKEN");
        }
        return value;
    }

    static long range(long value, long min, long max) {
        if (value < min || value > max) {
            throw new IllegalArgumentException("BAD_RANGE");
        }
        return value;
    }
}
