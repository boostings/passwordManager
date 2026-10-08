package pm.fuzz;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The native messaging harness's own reading of ADR 0014 §2 and §3: strict UTF-8 by the byte table
 * of RFC 3629 §4, and RFC 8259 JSON with the ADR's limits. It is written from those texts, not
 * from {@code pm.browser.host}: it shares no code, constant, table or regular expression with
 * {@code NativeFrames}, {@code JsonText} or {@code Messages}, so a limit or rule that the host
 * drops shows up as a disagreement.
 *
 * <p>A parsed value is a {@code Map<String, Object>} (object, member order kept), a
 * {@code List<Object>} (array), a {@code String}, a {@code Long}, a {@code Boolean} or
 * {@link Null#NULL}.
 */
final class JsonOracle {
    /** ADR 0014 §3: depth ≤ 8 (the outermost object or array is depth 1). */
    static final int MAX_DEPTH = 8;
    /** ADR 0014 §3: ≤ 256 members per object or array. */
    static final int MAX_MEMBERS = 256;
    /** ADR 0014 §3: strings ≤ 65,536 UTF-16 units, counted after unescaping. */
    static final int MAX_STRING = 65_536;
    /** ADR 0014 §3: integers of at most 15 digits. */
    static final int MAX_DIGITS = 15;

    /**
     * RFC 3629 §4, one row per lead-byte range: lowest lead, highest lead, continuation bytes,
     * lowest and highest second byte. Every later continuation byte is 80..BF.
     */
    private static final int[][] UTF8_ROWS = {
        {0x00, 0x7F, 0, 0, 0},
        {0xC2, 0xDF, 1, 0x80, 0xBF},
        {0xE0, 0xE0, 2, 0xA0, 0xBF},
        {0xE1, 0xEC, 2, 0x80, 0xBF},
        {0xED, 0xED, 2, 0x80, 0x9F},
        {0xEE, 0xEF, 2, 0x80, 0xBF},
        {0xF0, 0xF0, 3, 0x90, 0xBF},
        {0xF1, 0xF3, 3, 0x80, 0xBF},
        {0xF4, 0xF4, 3, 0x80, 0x8F},
    };
    /** Payload bits of the lead byte, by continuation count. */
    /** No row: the byte cannot start a sequence. */
    private static final int[] NO_ROW = {};
    private static final int[] LEAD_BITS = {0x7F, 0x1F, 0x0F, 0x07};
    private static final int TAIL_LOW = 0x80;
    private static final int TAIL_HIGH = 0xBF;
    private static final int TAIL_BITS = 0x3F;
    private static final int TAIL_SHIFT = 6;
    private static final int BYTE = 0xFF;
    /** RFC 8259 §7: {@code unescaped = %x20-21 / %x23-5B / %x5D-10FFFF}. */
    private static final char FIRST_UNESCAPED = 0x20;
    private static final char QUOTE = '"';
    private static final char BACKSLASH = '\\';
    private static final char MINUS = '-';
    private static final char CLOSE_OBJECT = '}';
    private static final char CLOSE_ARRAY = ']';
    private static final int HEX_DIGITS = 4;
    private static final int HEX_RADIX = 16;
    private static final int DECIMAL_LETTER = 10;

    /** JSON {@code null} in a parsed tree. */
    enum Null {
        /** The only value. */
        NULL
    }

    /** The oracle refuses the input; no stack trace is filled in, so fuzzing stays fast. */
    static final class Refused extends Exception {
        private static final long serialVersionUID = 1L;

        Refused() {
            super(null, null, false, false);
        }
    }

    private JsonOracle() {
    }

    /** The text of {@code in} if it is well-formed UTF-8 by RFC 3629 §4, else null. */
    static String utf8(byte[] in) {
        StringBuilder out = new StringBuilder(in.length);
        int i = 0;
        while (i < in.length) {
            int lead = in[i] & BYTE;
            int[] row = rowFor(lead);
            if (row.length == 0) {
                return null;
            }
            int tails = row[2];
            if (i + tails >= in.length) {
                return null;
            }
            int cp = lead & LEAD_BITS[tails];
            for (int t = 1; t <= tails; t++) {
                int b = in[i + t] & BYTE;
                boolean second = t == 1;
                int low = second ? row[3] : TAIL_LOW;
                int high = second ? row[4] : TAIL_HIGH;
                if (b < low || b > high) {
                    return null;
                }
                cp = (cp << TAIL_SHIFT) | (b & TAIL_BITS);
            }
            out.appendCodePoint(cp);
            i += tails + 1;
        }
        return out.toString();
    }

    private static int[] rowFor(int lead) {
        for (int[] row : UTF8_ROWS) {
            if (lead >= row[0] && lead <= row[1]) {
                return row;
            }
        }
        return NO_ROW;
    }

    /**
     * Parses exactly one RFC 8259 value with only RFC whitespace around it. With {@code limits},
     * the ADR 0014 §3 subset applies (depth, members, string length, integers only of at most 15
     * digits); without, only the integer-only rule does, for reading the host's replies.
     */
    static Object parse(String text, boolean limits) throws Refused {
        Reader r = new Reader(text, limits);
        r.space();
        Object value = r.value(0);
        r.space();
        if (!r.atEnd()) {
            throw new Refused();
        }
        return value;
    }

    /** A recursive-descent reader over UTF-16 text. */
    private static final class Reader {
        private final String s;
        private final boolean limits;
        private int pos;

        Reader(String s, boolean limits) {
            this.s = s;
            this.limits = limits;
        }

        boolean atEnd() {
            return pos == s.length();
        }

        /** RFC 8259 §2: {@code ws = *( %x20 / %x09 / %x0A / %x0D )}. */
        void space() {
            while (!atEnd() && isSpace(s.charAt(pos))) {
                pos++;
            }
        }

        private static boolean isSpace(char c) {
            return c == ' ' || c == '\t' || c == '\n' || c == '\r';
        }

        char peek() throws Refused {
            if (atEnd()) {
                throw new Refused();
            }
            return s.charAt(pos);
        }

        char next() throws Refused {
            char c = peek();
            pos++;
            return c;
        }

        void expect(char wanted) throws Refused {
            if (next() != wanted) {
                throw new Refused();
            }
        }

        Object value(int depth) throws Refused {
            return switch (peek()) {
                case '{' -> object(depth + 1);
                case '[' -> array(depth + 1);
                case '"' -> string();
                case 't' -> word("true", true);
                case 'f' -> word("false", false);
                case 'n' -> word("null", Null.NULL);
                default -> number();
            };
        }

        private Object word(String w, Object result) throws Refused {
            for (int i = 0; i < w.length(); i++) {
                expect(w.charAt(i));
            }
            return result;
        }

        private void enter(int depth) throws Refused {
            if (limits && depth > MAX_DEPTH) {
                throw new Refused();
            }
            pos++;
            space();
        }

        private void count(int size) throws Refused {
            if (limits && size >= MAX_MEMBERS) {
                throw new Refused();
            }
        }

        private Map<String, Object> object(int depth) throws Refused {
            enter(depth);
            Map<String, Object> members = new LinkedHashMap<>();
            if (peek() == CLOSE_OBJECT) {
                pos++;
                return members;
            }
            while (true) {
                count(members.size());
                if (peek() != QUOTE) {
                    throw new Refused();
                }
                String name = string();
                space();
                expect(':');
                space();
                Object value = value(depth);
                if (members.containsKey(name)) {
                    throw new Refused();
                }
                members.put(name, value);
                space();
                if (next() == CLOSE_OBJECT) {
                    return members;
                }
                pos--;
                expect(',');
                space();
            }
        }

        private List<Object> array(int depth) throws Refused {
            enter(depth);
            List<Object> items = new ArrayList<>();
            if (peek() == CLOSE_ARRAY) {
                pos++;
                return items;
            }
            while (true) {
                count(items.size());
                items.add(value(depth));
                space();
                if (next() == CLOSE_ARRAY) {
                    return items;
                }
                pos--;
                expect(',');
                space();
            }
        }

        private String string() throws Refused {
            pos++;
            StringBuilder out = new StringBuilder();
            while (true) {
                char c = next();
                if (c == QUOTE) {
                    break;
                }
                if (c < FIRST_UNESCAPED) {
                    throw new Refused();
                }
                if (c == BACKSLASH) {
                    escape(out);
                } else {
                    out.append(c);
                }
            }
            if (limits && out.length() > MAX_STRING) {
                throw new Refused();
            }
            return out.toString();
        }

        /** RFC 8259 §7 escapes; ADR 0014 §3: an escaped surrogate only as half of a valid pair. */
        private void escape(StringBuilder out) throws Refused {
            char c = next();
            switch (c) {
                case '"' -> out.append('"');
                case '\\' -> out.append('\\');
                case '/' -> out.append('/');
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> unicode(out);
                default -> throw new Refused();
            }
        }

        private void unicode(StringBuilder out) throws Refused {
            char unit = hex4();
            if (Character.isLowSurrogate(unit)) {
                throw new Refused();
            }
            out.append(unit);
            if (Character.isHighSurrogate(unit)) {
                expect('\\');
                expect('u');
                char low = hex4();
                if (!Character.isLowSurrogate(low)) {
                    throw new Refused();
                }
                out.append(low);
            }
        }

        private char hex4() throws Refused {
            int v = 0;
            for (int i = 0; i < HEX_DIGITS; i++) {
                int d = hexValue(next());
                if (d < 0) {
                    throw new Refused();
                }
                v = v * HEX_RADIX + d;
            }
            return (char) v;
        }

        /** RFC 8259 §7 / RFC 5234 {@code HEXDIG}: ASCII 0-9, A-F, a-f only. */
        private static int hexValue(char c) {
            return c >= '0' && c <= '9' ? c - '0'
                    : c >= 'a' && c <= 'f' ? c - 'a' + DECIMAL_LETTER
                    : c >= 'A' && c <= 'F' ? c - 'A' + DECIMAL_LETTER
                    : -1;
        }

        /**
         * RFC 8259 §6 {@code [ minus ] int} with {@code int = zero / ( digit1-9 *DIGIT )}; a
         * fraction or exponent is left unread, so it fails as trailing text (ADR: integers only).
         */
        private Long number() throws Refused {
            int start = pos;
            if (peek() == MINUS) {
                pos++;
            }
            int first = pos;
            while (!atEnd() && isDigit(s.charAt(pos))) {
                pos++;
            }
            int digits = pos - first;
            if (digits == 0 || leadingZero(first, digits) || (limits && digits > MAX_DIGITS)) {
                throw new Refused();
            }
            return Long.valueOf(s.substring(start, pos));
        }

        private boolean leadingZero(int first, int digits) {
            return digits > 1 && s.charAt(first) == '0';
        }

        private static boolean isDigit(char c) {
            return c >= '0' && c <= '9';
        }
    }
}
