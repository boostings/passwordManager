package pm.browser.host;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;

/**
 * A strict, bounded JSON reader and writer for the native messaging protocol (RFC 8259 subset,
 * ADR 0014 §3). Hand-written so the host takes no dependency, and every limit is enforced while
 * reading, before anything grows (MSC05-J):
 *
 * <ul>
 *   <li>exactly one value with only RFC 8259 whitespace around it; no BOM, comments or trailing
 *       commas;</li>
 *   <li>nesting at most {@link #MAX_DEPTH}, at most {@link #MAX_MEMBERS} members per object or
 *       array, duplicate member names refused;</li>
 *   <li>strings at most {@link #MAX_STRING} UTF-16 units, no raw control characters, only RFC 8259
 *       escapes, and an escaped surrogate must be half of a valid escaped pair;</li>
 *   <li>numbers are integers of at most {@link #MAX_DIGITS} digits with no leading zero; a
 *       fraction or exponent is refused.</li>
 * </ul>
 */
public final class JsonText {
    /** Deepest nesting of objects and arrays. */
    public static final int MAX_DEPTH = 8;
    /** Most members in one object or items in one array. */
    public static final int MAX_MEMBERS = 256;
    /** Longest string, in UTF-16 units. */
    public static final int MAX_STRING = 65_536;
    /** Most digits in an integer; 15 digits stay exact in a JavaScript number. */
    public static final int MAX_DIGITS = 15;

    private static final char OBJECT_OPEN = '{';
    private static final char OBJECT_CLOSE = '}';
    private static final char ARRAY_OPEN = '[';
    private static final char ARRAY_CLOSE = ']';
    private static final char DOUBLE_QUOTE = '"';
    private static final char BACKSLASH = '\\';
    private static final char MINUS = '-';
    private static final char UNICODE_ESCAPE = 'u';
    private static final char FIRST_PRINTABLE = 0x20;
    private static final String TRUE = "true";
    private static final String FALSE = "false";
    private static final String NULL = "null";
    private static final String ESCAPED = "\"\\/bfnrt";
    private static final String UNESCAPED = "\"\\/\b\f\n\r\t";
    /** ASCII hex digits only: {@code Character.digit} would also accept non-ASCII digits. */
    private static final String HEX = "0123456789abcdefABCDEF";

    private final char[] in;
    private int pos;

    private JsonText(char[] in) {
        this.in = in;
    }

    /**
     * Parses exactly one JSON value. The caller keeps ownership of {@code text}.
     *
     * @throws HostException {@code MALFORMED} for any syntax error or exceeded limit
     */
    public static Json parse(char[] text) throws HostException {
        JsonText reader = new JsonText(text);
        reader.skipSpace();
        Json value = reader.value(0);
        reader.skipSpace();
        if (reader.pos != text.length) {
            value.wipe();
            throw malformed();
        }
        return value;
    }

    /**
     * Serialises {@code value} as UTF-8 JSON. The caller owns the result.
     *
     * @throws IllegalArgumentException if a string holds an unpaired surrogate
     */
    public static SecretBytes toUtf8(Json value) {
        Sink out = new Sink();
        try {
            write(value, out);
            try (SecretChars text = out.take()) {
                return text.toUtf8();
            }
        } finally {
            out.wipe();
        }
    }

    // ---- reading ------------------------------------------------------------------------

    private Json value(int depth) throws HostException {
        char c = peek();
        if (c == OBJECT_OPEN) {
            return object(depth + 1);
        }
        if (c == ARRAY_OPEN) {
            return array(depth + 1);
        }
        if (c == DOUBLE_QUOTE) {
            return string();
        }
        if (c == TRUE.charAt(0)) {
            literal(TRUE);
            return new Json.Bool(true);
        }
        if (c == FALSE.charAt(0)) {
            literal(FALSE);
            return new Json.Bool(false);
        }
        if (c == NULL.charAt(0)) {
            literal(NULL);
            return Json.Null.NULL;
        }
        return number();
    }

    private Json object(int depth) throws HostException {
        enter(depth);
        Map<String, Json> members = new LinkedHashMap<>();
        try {
            skipSpace();
            if (peek() == OBJECT_CLOSE) {
                pos++;
                return new Json.Obj(members);
            }
            while (true) {
                if (peek() != DOUBLE_QUOTE || members.size() == MAX_MEMBERS) {
                    throw malformed();
                }
                String name = string().text();
                skipSpace();
                expect(':');
                skipSpace();
                Json member = value(depth);
                if (members.putIfAbsent(name, member) != null) {
                    member.wipe();
                    throw malformed();
                }
                skipSpace();
                if (next() == OBJECT_CLOSE) {
                    return new Json.Obj(members);
                }
                pos--;
                expect(',');
                skipSpace();
            }
        } catch (HostException e) {
            members.values().forEach(Json::wipe);
            throw e;
        }
    }

    private Json array(int depth) throws HostException {
        enter(depth);
        List<Json> items = new ArrayList<>();
        try {
            skipSpace();
            if (peek() == ARRAY_CLOSE) {
                pos++;
                return new Json.Arr(items);
            }
            while (true) {
                if (items.size() == MAX_MEMBERS) {
                    throw malformed();
                }
                items.add(value(depth));
                skipSpace();
                if (next() == ARRAY_CLOSE) {
                    return new Json.Arr(items);
                }
                pos--;
                expect(',');
                skipSpace();
            }
        } catch (HostException e) {
            items.forEach(Json::wipe);
            throw e;
        }
    }

    /** Steps over the opening bracket of a container at nesting level {@code depth}. */
    private void enter(int depth) throws HostException {
        if (depth > MAX_DEPTH) {
            throw malformed();
        }
        pos++;
    }

    private Json.Str string() throws HostException {
        pos++; // opening quote
        Sink out = new Sink();
        try {
            while (true) {
                char c = next();
                if (c == DOUBLE_QUOTE) {
                    return Json.Str.take(out.copy());
                }
                if (c < FIRST_PRINTABLE) {
                    throw malformed();
                }
                if (c == BACKSLASH) {
                    escape(out);
                } else {
                    out.append(c);
                }
                if (out.length() > MAX_STRING) {
                    throw malformed();
                }
            }
        } finally {
            out.wipe();
        }
    }

    /** One escape after the backslash; an escaped high surrogate needs an escaped low one next. */
    private void escape(Sink out) throws HostException {
        char c = next();
        int at = ESCAPED.indexOf(c);
        if (at >= 0) {
            out.append(UNESCAPED.charAt(at));
            return;
        }
        if (c != UNICODE_ESCAPE) {
            throw malformed();
        }
        char unit = hex4();
        if (Character.isHighSurrogate(unit)) {
            expect(BACKSLASH);
            expect(UNICODE_ESCAPE);
            char low = hex4();
            if (!Character.isLowSurrogate(low)) {
                throw malformed();
            }
            out.append(unit);
            out.append(low);
            return;
        }
        if (Character.isLowSurrogate(unit)) {
            throw malformed();
        }
        out.append(unit);
    }

    private char hex4() throws HostException {
        int v = 0;
        for (int i = 0; i < 4; i++) {
            int at = HEX.indexOf(next());
            if (at < 0) {
                throw malformed();
            }
            v = v << 4 | (at < 16 ? at : at - 6);
        }
        return (char) v;
    }

    private Json number() throws HostException {
        int start = pos;
        if (in[pos] == MINUS) {
            pos++;
        }
        int digitsStart = pos;
        while (pos < in.length && in[pos] >= '0' && in[pos] <= '9') {
            pos++;
        }
        int digits = pos - digitsStart;
        if (digits == 0 || digits > MAX_DIGITS || (digits > 1 && in[digitsStart] == '0')) {
            throw malformed();
        }
        return new Json.Num(Long.parseLong(String.valueOf(in, start, pos - start)));
    }

    private void literal(String word) throws HostException {
        for (int i = 0; i < word.length(); i++) {
            if (next() != word.charAt(i)) {
                throw malformed();
            }
        }
    }

    private void skipSpace() {
        while (pos < in.length && isSpace(in[pos])) {
            pos++;
        }
    }

    private static boolean isSpace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    private char peek() throws HostException {
        if (pos >= in.length) {
            throw malformed();
        }
        return in[pos];
    }

    private char next() throws HostException {
        char c = peek();
        pos++;
        return c;
    }

    private void expect(char c) throws HostException {
        if (next() != c) {
            throw malformed();
        }
    }

    private static HostException malformed() {
        return new HostException(HostException.Code.MALFORMED);
    }

    // ---- writing ------------------------------------------------------------------------

    private static void write(Json value, Sink out) {
        if (value instanceof Json.Obj o) {
            out.append('{');
            String sep = "";
            for (Map.Entry<String, Json> m : o.members().entrySet()) {
                out.append(sep);
                quote(Json.Str.of(m.getKey()), out);
                out.append(':');
                write(m.getValue(), out);
                sep = ",";
            }
            out.append('}');
        } else if (value instanceof Json.Arr a) {
            out.append('[');
            String sep = "";
            for (Json item : a.items()) {
                out.append(sep);
                write(item, out);
                sep = ",";
            }
            out.append(']');
        } else if (value instanceof Json.Str s) {
            quote(s, out);
        } else if (value instanceof Json.Num n) {
            out.append(Long.toString(n.value()));
        } else if (value instanceof Json.Bool b) {
            out.append(Boolean.toString(b.value()));
        } else {
            out.append(NULL);
        }
    }

    private static void quote(Json.Str s, Sink out) {
        out.append(DOUBLE_QUOTE);
        for (int i = 0; i < s.length(); i++) {
            char c = s.unitAt(i);
            if (c == DOUBLE_QUOTE || c == BACKSLASH) {
                out.append('\\');
                out.append(c);
            } else if (c < FIRST_PRINTABLE) {
                out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        out.append(DOUBLE_QUOTE);
    }

    /** A growable char buffer that zeroes every array it lets go of. */
    private static final class Sink {
        private char[] buf = new char[64];
        private int len;

        void append(char c) {
            if (len == buf.length) {
                char[] bigger = Arrays.copyOf(buf, len * 2);
                Arrays.fill(buf, '\0');
                buf = bigger;
            }
            buf[len++] = c;
        }

        void append(String s) {
            for (int i = 0; i < s.length(); i++) {
                append(s.charAt(i));
            }
        }

        int length() {
            return len;
        }

        char[] copy() {
            return Arrays.copyOf(buf, len);
        }

        SecretChars take() {
            return SecretChars.takeOwnership(copy());
        }

        void wipe() {
            Arrays.fill(buf, '\0');
        }
    }
}
