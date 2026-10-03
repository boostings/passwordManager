package pm.cli;

import java.nio.charset.StandardCharsets;
import java.util.SortedMap;
import pm.crypto.SecretBytes;

/**
 * Formats variables as a {@code .env} file that {@code pm.domain.env.DotEnv} parses back to the same
 * values: every value double-quoted, with \n \r \t \" \\ and \$ escaped. Two passes (measure, then
 * fill) so the only copy of the output is the array the returned {@link SecretBytes} owns.
 */
final class DotEnvWriter {
    private static final int FIXED_PER_LINE = 4; // = " " \n

    private DotEnvWriter() {
    }

    /**
     * The file bytes, owned by the caller.
     *
     * @throws IllegalArgumentException if a value holds a control byte other than tab, LF or CR,
     *     which the parser would refuse
     */
    static SecretBytes format(SortedMap<String, SecretBytes> vars) {
        int[] size = {0};
        vars.forEach((name, value) -> {
            size[0] += name.length() + FIXED_PER_LINE;
            value.withBytes(bytes -> {
                for (byte b : bytes) {
                    if (!representable(b)) {
                        throw new IllegalArgumentException("UNREPRESENTABLE");
                    }
                    size[0] += needsEscape(b) ? 2 : 1;
                }
            });
        });
        byte[] out = new byte[size[0]];
        int[] at = {0};
        vars.forEach((name, value) -> {
            byte[] n = name.getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(n, 0, out, at[0], n.length);
            at[0] += n.length;
            out[at[0]++] = '=';
            out[at[0]++] = '"';
            value.withBytes(bytes -> {
                for (byte b : bytes) {
                    if (needsEscape(b)) {
                        out[at[0]++] = '\\';
                        out[at[0]++] = escaped(b);
                    } else {
                        out[at[0]++] = b;
                    }
                }
            });
            out[at[0]++] = '"';
            out[at[0]++] = '\n';
        });
        return SecretBytes.takeOwnership(out);
    }

    private static boolean representable(byte b) {
        int u = b & 0xff;
        return (u >= ' ' && u != 0x7f) || needsEscape(b);
    }

    private static boolean needsEscape(byte b) {
        return b == '\n' || b == '\r' || b == '\t' || b == '"' || b == '\\' || b == '$';
    }

    private static byte escaped(byte b) {
        return switch (b) {
            case '\n' -> 'n';
            case '\r' -> 'r';
            case '\t' -> 't';
            default -> b;
        };
    }
}
