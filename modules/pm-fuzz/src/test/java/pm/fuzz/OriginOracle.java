package pm.fuzz;

/**
 * The origin harness's own reading of ADR 0014 §5. It is written from the ADR text, not from
 * {@code pm.browser.bridge.Origin}: it shares no code, constant or regular expression with it, and
 * it uses no regular expressions, no {@code toLowerCase} and no {@code java.net} parser at all.
 */
final class OriginOracle {
    /** ADR 0014 §3: an origin is at most 256 characters. */
    static final int MAX_TEXT = 256;
    /** ADR 0014 §5, RFC 1035: at most 253 characters in all. */
    static final int MAX_HOST = 253;
    /** RFC 1035 / RFC 5890 LDH: labels of 1–63 characters. */
    static final int MAX_LABEL = 63;
    private static final String SEPARATOR = "://";
    private static final String HTTP = "http";
    private static final String HTTPS = "https";
    private static final int HTTP_DEFAULT = 80;
    private static final int HTTPS_DEFAULT = 443;
    private static final int MAX_PORT = 65_535;
    private static final int MAX_PORT_DIGITS = 5;
    private static final int MAX_OCTET = 255;
    private static final int QUAD = 4;
    private static final String HEX_START = "0x";
    /** ADR 0014 §5: no userinfo, IPv6 brackets, backslash, percent or whitespace in the authority. */
    private static final String FORBIDDEN = "@[]\\% \t\n\u000b\f\r";
    private static final String URL_ENDS = "/?#";
    private static final char COLON = ':';
    private static final char DOT = '.';
    private static final char HYPHEN = '-';
    private static final char ZERO = '0';
    private static final int CASE_STEP = 'a' - 'A';

    /** A canonical origin: the triple ADR 0014 §5 compares, and its text form. */
    record Canonical(String scheme, String host, int port) {
        /** The text form: the default port is left out. */
        String text() {
            int standard = HTTPS.equals(scheme) ? HTTPS_DEFAULT : HTTP_DEFAULT;
            return scheme + SEPARATOR + host + (port == standard ? "" : COLON + Integer.toString(port));
        }
    }

    private OriginOracle() {
    }

    /** {@code location.origin} text by ADR 0014 §5, or null if it is not an exact origin. */
    static Canonical parse(String text) {
        int sep = text.indexOf(SEPARATOR);
        if (sep < 1 || text.length() > MAX_TEXT) {
            return null;
        }
        String scheme = foldAscii(text.substring(0, sep));
        if (!HTTP.equals(scheme) && !HTTPS.equals(scheme)) {
            return null;
        }
        String authority = text.substring(sep + SEPARATOR.length());
        if (authority.isEmpty() || containsAny(authority, URL_ENDS) || containsAny(authority, FORBIDDEN)) {
            return null;
        }
        int colon = authority.indexOf(COLON);
        int port = HTTPS.equals(scheme) ? HTTPS_DEFAULT : HTTP_DEFAULT;
        String host = authority;
        if (colon >= 0) {
            port = port(authority.substring(colon + 1));
            if (port < 0) {
                return null;
            }
            host = authority.substring(0, colon);
        }
        host = foldAscii(host);
        return isHost(host) ? new Canonical(scheme, host, port) : null;
    }

    /** A stored login URL: its origin after cutting path, query and fragment, or null. */
    static Canonical ofUrl(String url) {
        int sep = url.indexOf(SEPARATOR);
        if (sep < 0) {
            return null;
        }
        int end = sep + SEPARATOR.length();
        while (end < url.length() && URL_ENDS.indexOf(url.charAt(end)) < 0) {
            end++;
        }
        return parse(url.substring(0, end));
    }

    /** 1–65535, digits only, no sign and no leading zero; -1 otherwise. */
    private static int port(String digits) {
        if (digits.isEmpty() || digits.length() > MAX_PORT_DIGITS || digits.charAt(0) == ZERO || !allDigits(digits)) {
            return -1;
        }
        int value = Integer.parseInt(digits);
        return value > MAX_PORT ? -1 : value;
    }

    private static boolean isHost(String host) {
        if (host.isEmpty() || host.length() > MAX_HOST) {
            return false;
        }
        int start = 0;
        String last = "";
        while (start <= host.length()) {
            int dot = host.indexOf(DOT, start);
            int end = dot < 0 ? host.length() : dot;
            last = host.substring(start, end);
            if (!isLdhLabel(last)) {
                return false;
            }
            start = end + 1;
            if (dot < 0) {
                break;
            }
        }
        if (allDigits(last) || last.startsWith(HEX_START)) {
            return isDottedQuad(host);
        }
        return true;
    }

    /** RFC 5890 LDH label: 1–63 of a–z, 0–9 and hyphen, not starting or ending with a hyphen. */
    private static boolean isLdhLabel(String label) {
        if (label.isEmpty() || label.length() > MAX_LABEL || label.charAt(0) == HYPHEN
                || label.charAt(label.length() - 1) == HYPHEN) {
            return false;
        }
        for (int i = 0; i < label.length(); i++) {
            char c = label.charAt(i);
            if (!isLowerLetter(c) && !isDigit(c) && c != HYPHEN) {
                return false;
            }
        }
        return true;
    }

    /** Four decimal octets 0–255, each in its shortest form: exactly what {@code 127.0.0.1} looks like. */
    private static boolean isDottedQuad(String host) {
        String rest = host;
        for (int i = 0; i < QUAD; i++) {
            int dot = rest.indexOf(DOT);
            boolean lastOctet = i == QUAD - 1;
            if (lastOctet != (dot < 0)) {
                return false;
            }
            String octet = lastOctet ? rest : rest.substring(0, dot);
            if (octet.isEmpty() || octet.length() > String.valueOf(MAX_OCTET).length() || !allDigits(octet)) {
                return false;
            }
            int value = Integer.parseInt(octet);
            if (value > MAX_OCTET || !Integer.toString(value).equals(octet)) {
                return false;
            }
            rest = lastOctet ? "" : rest.substring(dot + 1);
        }
        return true;
    }

    /** ADR 0014 §5: A–Z only are folded; every other character is left as it is. */
    static String foldAscii(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            out.append(c >= 'A' && c <= 'Z' ? (char) (c + CASE_STEP) : c);
        }
        return out.toString();
    }

    private static boolean containsAny(String s, String chars) {
        for (int i = 0; i < s.length(); i++) {
            if (chars.indexOf(s.charAt(i)) >= 0) {
                return true;
            }
        }
        return false;
    }

    private static boolean allDigits(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (!isDigit(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static boolean isLowerLetter(char c) {
        return c >= 'a' && c <= 'z';
    }
}
