package pm.domain.env;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import pm.crypto.SecretBytes;
import pm.domain.env.DotEnvException.Code;

/**
 * A strict {@code .env} parser (plan.md §13 M2, TB-15). The file is untrusted input, so the parser
 * is bounded in every dimension and rejects anything it does not fully understand rather than
 * guessing (IDS00-J spirit, fuzzed by {@code DotEnvFuzzTest}).
 *
 * <p>It works on bytes, never on {@code String}: values are copied straight into
 * {@link SecretBytes} and the one scratch buffer is zero-filled before returning (ADR 0008). Only
 * names, which are not secret, become strings.
 *
 * <p>Accepted syntax, one variable per line:
 * <ul>
 *   <li>blank lines and lines starting with {@code #} (after optional spaces) are skipped;</li>
 *   <li>{@code [export ]NAME=value}, with optional spaces or tabs around {@code =};</li>
 *   <li>a bare value runs to the end of the line, or to a {@code #} preceded by a space or tab,
 *       with trailing spaces and tabs removed;</li>
 *   <li>a {@code '...'} value is taken literally and stays on one line;</li>
 *   <li>a {@code "..."} value may span lines and understands {@code \n \r \t \" \\ \$};</li>
 *   <li>after a closing quote only spaces, tabs and a {@code #} comment may follow.</li>
 * </ul>
 * A leading UTF-8 byte-order mark is skipped and CRLF line ends are read as LF.
 */
public final class DotEnv {
    /** Largest file accepted. */
    public static final int MAX_INPUT_BYTES = 1024 * 1024;
    /** Largest single value, the project-record limit. */
    public static final int MAX_VALUE_BYTES = 64 * 1024;
    /** Most variables per file, the project-record limit. */
    public static final int MAX_ENTRIES = 1_024;
    /** Longest variable name. */
    public static final int MAX_NAME_CHARS = 256;

    private static final byte[] EXPORT = "export".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] BOM = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
    private static final byte TAB = '\t';
    private static final byte LF = '\n';
    private static final byte CR = '\r';
    private static final byte SPACE = ' ';
    private static final byte HASH = '#';
    private static final byte EQUALS = '=';
    private static final byte SINGLE = '\'';
    private static final byte DOUBLE = '"';
    private static final byte BACKSLASH = '\\';
    private static final int DEL = 0x7f;

    private final byte[] in;
    private final byte[] scratch = new byte[MAX_VALUE_BYTES];
    private int pos;
    private int line = 1;
    private int valueLength;

    private DotEnv(byte[] in, int start) {
        this.in = in;
        this.pos = start;
    }

    /**
     * Parses {@code input}. The caller keeps ownership of {@code input} and should zero it after.
     * On success the caller owns the returned entries; on failure nothing is returned and every
     * value read so far has been closed.
     *
     * @throws DotEnvException with a code and line number, never with file content
     */
    public static List<EnvEntry> parse(byte[] input) throws DotEnvException {
        Objects.requireNonNull(input, "input");
        if (input.length > MAX_INPUT_BYTES) {
            throw new DotEnvException(Code.TOO_LARGE, 0);
        }
        Utf8.check(input);
        DotEnv parser = new DotEnv(input, 0);
        if (parser.startsWithWord(BOM)) {
            parser.pos = BOM.length;
        }
        List<EnvEntry> entries = new ArrayList<>();
        try {
            parser.parseInto(entries);
            return List.copyOf(entries);
        } catch (DotEnvException | RuntimeException e) {
            entries.forEach(EnvEntry::close);
            throw e;
        } finally {
            Arrays.fill(parser.scratch, (byte) 0);
        }
    }

    /** True if {@code name} is a valid variable name: {@code [A-Za-z_][A-Za-z0-9_]*}, 1–256 chars. */
    public static boolean isValidName(String name) {
        if (name.isEmpty() || name.length() > MAX_NAME_CHARS || isDigit(name.charAt(0))) {
            return false;
        }
        return name.chars().allMatch(DotEnv::isNameChar);
    }

    private void parseInto(List<EnvEntry> entries) throws DotEnvException {
        Set<String> seen = new HashSet<>();
        while (pos < in.length) {
            skipBlanks();
            if (atLineEnd()) {
                endLine();
                continue;
            }
            if (in[pos] == HASH) {
                skipComment();
                endLine();
                continue;
            }
            int startLine = line;
            String name = readName();
            if (entries.size() >= MAX_ENTRIES) {
                throw new DotEnvException(Code.TOO_MANY_ENTRIES, startLine);
            }
            if (!seen.add(name)) {
                throw new DotEnvException(Code.DUPLICATE_NAME, startLine);
            }
            readValue();
            entries.add(new EnvEntry(name, SecretBytes.takeOwnership(Arrays.copyOf(scratch, valueLength))));
            Arrays.fill(scratch, 0, valueLength, (byte) 0);
            endLine();
        }
    }

    private String readName() throws DotEnvException {
        if (startsWithWord(EXPORT) && pos + EXPORT.length < in.length && isBlank(in[pos + EXPORT.length])) {
            pos += EXPORT.length;
            skipBlanks();
        }
        int start = pos;
        while (pos < in.length && isNameChar(in[pos])) {
            pos++;
        }
        int length = pos - start;
        if (length == 0 || length > MAX_NAME_CHARS || isDigit(in[start])) {
            throw new DotEnvException(Code.BAD_NAME, line);
        }
        String name = new String(in, start, length, StandardCharsets.US_ASCII);
        skipBlanks();
        if (pos >= in.length || in[pos] != EQUALS) {
            throw new DotEnvException(atLineEnd() ? Code.MISSING_EQUALS : Code.BAD_NAME, line);
        }
        pos++;
        skipBlanks();
        return name;
    }

    private void readValue() throws DotEnvException {
        valueLength = 0;
        if (pos < in.length && in[pos] == SINGLE) {
            readSingleQuoted();
            afterQuote();
        } else if (pos < in.length && in[pos] == DOUBLE) {
            readDoubleQuoted();
            afterQuote();
        } else {
            readBare();
        }
    }

    private void readBare() throws DotEnvException {
        int start = pos;
        while (!atLineEnd() && !(in[pos] == HASH && pos > start && isBlank(in[pos - 1]))) {
            checkControl(in[pos]);
            pos++;
        }
        int end = pos;
        while (end > start && isBlank(in[end - 1])) {
            end--;
        }
        for (int i = start; i < end; i++) {
            append(in[i]);
        }
        if (!atLineEnd()) {
            skipComment();
        }
    }

    private void readSingleQuoted() throws DotEnvException {
        int startLine = line;
        pos++;
        while (pos < in.length && in[pos] != SINGLE) {
            if (in[pos] == LF || in[pos] == CR) {
                throw new DotEnvException(Code.UNTERMINATED_QUOTE, startLine);
            }
            checkControl(in[pos]);
            append(in[pos++]);
        }
        if (pos >= in.length) {
            throw new DotEnvException(Code.UNTERMINATED_QUOTE, startLine);
        }
        pos++;
    }

    private void readDoubleQuoted() throws DotEnvException {
        int startLine = line;
        pos++;
        while (pos < in.length && in[pos] != DOUBLE) {
            byte b = in[pos];
            if (b == BACKSLASH) {
                pos++;
                if (pos >= in.length) {
                    throw new DotEnvException(Code.UNTERMINATED_QUOTE, startLine);
                }
                append(unescape(in[pos]));
                pos++;
            } else if (b == CR && pos + 1 < in.length && in[pos + 1] == LF) {
                pos++; // CRLF inside a value is stored as LF
            } else {
                if (b == LF) {
                    line++;
                } else {
                    checkControl(b);
                }
                append(b);
                pos++;
            }
        }
        if (pos >= in.length) {
            throw new DotEnvException(Code.UNTERMINATED_QUOTE, startLine);
        }
        pos++;
    }

    private byte unescape(byte b) throws DotEnvException {
        return switch (b) {
            case 'n' -> LF;
            case 'r' -> CR;
            case 't' -> TAB;
            case '"', '\\', '$' -> b;
            default -> throw new DotEnvException(Code.BAD_ESCAPE, line);
        };
    }

    private void afterQuote() throws DotEnvException {
        skipBlanks();
        if (atLineEnd()) {
            return;
        }
        if (in[pos] != HASH) {
            throw new DotEnvException(Code.TRAILING_TEXT, line);
        }
        skipComment();
    }

    private void append(byte b) throws DotEnvException {
        if (valueLength >= MAX_VALUE_BYTES) {
            throw new DotEnvException(Code.VALUE_TOO_LARGE, line);
        }
        scratch[valueLength++] = b;
    }

    private void skipComment() throws DotEnvException {
        while (!atLineEnd()) {
            checkControl(in[pos]);
            pos++;
        }
    }

    private void skipBlanks() {
        while (pos < in.length && isBlank(in[pos])) {
            pos++;
        }
    }

    /** True at end of input, LF, or CRLF. A lone CR is a control character, not a line end. */
    private boolean atLineEnd() {
        return pos >= in.length || in[pos] == LF || (in[pos] == CR && pos + 1 < in.length && in[pos + 1] == LF);
    }

    private void endLine() {
        if (pos < in.length && in[pos] == CR) {
            pos++;
        }
        if (pos < in.length && in[pos] == LF) {
            pos++;
            line++;
        }
    }

    private void checkControl(byte b) throws DotEnvException {
        int u = b & 0xff;
        if ((u < SPACE && b != TAB) || u == DEL) {
            throw new DotEnvException(Code.CONTROL_CHARACTER, line);
        }
    }

    private boolean startsWithWord(byte[] word) {
        if (pos + word.length > in.length) {
            return false;
        }
        for (int i = 0; i < word.length; i++) {
            if (in[pos + i] != word[i]) {
                return false;
            }
        }
        return true; // syntax match on public words (export, BOM), not a secret comparison
    }

    private static boolean isBlank(byte b) {
        return b == SPACE || b == TAB;
    }

    private static boolean isDigit(int c) {
        return c >= '0' && c <= '9';
    }

    private static boolean isNameChar(int c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || isDigit(c) || c == '_';
    }

    /** Strict UTF-8 validation without decoding into a {@code String} (no secret copies). */
    static final class Utf8 {
        private Utf8() {
        }

        private static final int CONTINUATION = 0x80;

        static void check(byte[] in) throws DotEnvException {
            int i = 0;
            while (i < in.length) {
                int b = in[i] & 0xff;
                int extra;
                int min;
                if (b < CONTINUATION) {
                    i++;
                    continue;
                } else if (b >= 0xC2 && b <= 0xDF) {
                    extra = 1;
                    min = CONTINUATION;
                } else if (b >= 0xE0 && b <= 0xEF) {
                    extra = 2;
                    min = 0x800;
                } else if (b >= 0xF0 && b <= 0xF4) {
                    extra = 3;
                    min = 0x10000;
                } else {
                    throw new DotEnvException(Code.BAD_ENCODING, 0);
                }
                if (i + extra >= in.length) {
                    throw new DotEnvException(Code.BAD_ENCODING, 0);
                }
                int cp = b & (0x3F >> extra);
                for (int k = 1; k <= extra; k++) {
                    int c = in[i + k] & 0xff;
                    if ((c & 0xC0) != CONTINUATION) {
                        throw new DotEnvException(Code.BAD_ENCODING, 0);
                    }
                    cp = (cp << 6) | (c & 0x3F);
                }
                if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
                    throw new DotEnvException(Code.BAD_ENCODING, 0);
                }
                i += extra + 1;
            }
        }
    }
}
