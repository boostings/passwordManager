package pm.browser.bridge;

import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import pm.browser.host.HostException;

/**
 * A canonical web origin (ADR 0014 §5, SR-306): lowercase {@code http} or {@code https}, a
 * lowercase ASCII host name (internationalised names only in their {@code xn--} A-label form) or
 * canonical dotted-quad IPv4 address, and an explicit port.
 * Two origins are the same site for autofill only if they are {@linkplain #equals equal}: no
 * subdomain, scheme, port or lookalike leniency.
 *
 * <p>Refused outright: userinfo ({@code user@host}), IPv6 literals, backslashes, empty labels,
 * a trailing dot, percent-encoding, non-canonical IPv4 forms ({@code 0x7f.1}, {@code 010.0.0.1},
 * {@code 1.2.3}), any non-ASCII character and anything longer than {@link #MAX_TEXT}.
 *
 * <p>No IDNA mapping is done here. {@code java.net.IDN} implements IDNA2003, which maps
 * {@code faß.de} to {@code fass.de} and drops joiners, while browsers use UTS #46
 * non-transitional processing ({@code xn--fa-hia.de}); mapping here would make two different
 * registrable names compare equal. Browsers already serialise {@code location.origin} in A-label
 * form, so the only Unicode hosts that reach this class are stored URLs, and those never match.
 *
 * @param scheme {@code http} or {@code https}
 * @param host canonical host
 * @param port 1–65535; the scheme's default when the text named none
 */
public record Origin(String scheme, String host, int port) {
    /** Longest origin text considered. */
    public static final int MAX_TEXT = 256;
    /** Longest host name (RFC 1035). */
    public static final int MAX_HOST = 253;

    private static final String HTTP = "http";
    private static final String HTTPS = "https";
    private static final int HTTP_PORT = 80;
    private static final int HTTPS_PORT = 443;
    private static final int MIN_PORT = 1;
    private static final char FIRST_UPPER = 'A';
    private static final char LAST_UPPER = 'Z';
    private static final int CASE_OFFSET = 'a' - 'A';
    private static final int MAX_PORT = 65_535;
    private static final String SCHEME_END = "://";
    private static final String HEX_PREFIX = "0x";
    private static final char PORT_SEPARATOR = ':';
    private static final Pattern LABEL = Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");
    private static final Pattern NUMERIC = Pattern.compile("[0-9]+");
    private static final Pattern OCTET = Pattern.compile("0|[1-9][0-9]{0,2}");
    private static final Pattern PORT = Pattern.compile("[1-9][0-9]{0,4}");
    private static final Pattern IPV4_LABELS = Pattern.compile("[^.]+\\.[^.]+\\.[^.]+\\.[^.]+");
    private static final int MAX_OCTET = 255;
    private static final Pattern FORBIDDEN = Pattern.compile("[@\\[\\]\\\\%\\s]");

    /**
     * Checks the components are already canonical.
     *
     * @throws IllegalArgumentException {@code BAD_ORIGIN} otherwise
     */
    public Origin {
        Objects.requireNonNull(scheme, "scheme");
        Objects.requireNonNull(host, "host");
        if (!(HTTP.equals(scheme) || HTTPS.equals(scheme)) || port < MIN_PORT || port > MAX_PORT || !isCanonicalHost(host)) {
            throw new IllegalArgumentException("BAD_ORIGIN");
        }
    }

    /**
     * Parses an origin exactly as a browser serialises {@code location.origin}: a scheme,
     * {@code ://} and an authority, with no path, query or fragment. ASCII case is normalised and
     * the default port is made explicit; a non-ASCII host is refused, not mapped.
     *
     * @throws HostException {@code BAD_ORIGIN} if {@code text} is not such an origin
     */
    public static Origin parse(String text) throws HostException {
        Objects.requireNonNull(text, "text");
        int sep = text.indexOf(SCHEME_END);
        if (sep <= 0 || text.length() > MAX_TEXT) {
            throw bad();
        }
        String authority = text.substring(sep + SCHEME_END.length());
        if (authority.indexOf('/') >= 0 || authority.indexOf('?') >= 0 || authority.indexOf('#') >= 0) {
            throw bad();
        }
        return build(text.substring(0, sep), authority);
    }

    /**
     * The origin of a URL registered on a login (for example {@code https://example.com/login}).
     * The path, query and fragment are dropped. Empty if the URL has no {@code http(s)} origin
     * that {@link #parse} would accept; such a URL never matches any page.
     */
    public static Optional<Origin> ofUrl(String url) {
        Objects.requireNonNull(url, "url");
        int sep = url.indexOf(SCHEME_END);
        int start = sep + SCHEME_END.length();
        int end = start;
        while (end < url.length() && "/?#".indexOf(url.charAt(end)) < 0) {
            end++;
        }
        try {
            return Optional.of(parse(sep < 0 ? url : url.substring(0, end)));
        } catch (HostException e) {
            return Optional.empty();
        }
    }

    /** The serialised origin; the port is omitted when it is the scheme's default. */
    public String text() {
        String base = scheme + SCHEME_END + host;
        return port == defaultPort(scheme) ? base : base + PORT_SEPARATOR + port;
    }

    @Override
    public String toString() {
        return text();
    }

    private static Origin build(String rawScheme, String authority) throws HostException {
        String scheme = asciiLower(rawScheme);
        if (!(HTTP.equals(scheme) || HTTPS.equals(scheme)) || authority.isEmpty()
                || FORBIDDEN.matcher(authority).find()) {
            throw bad();
        }
        int colon = authority.lastIndexOf(PORT_SEPARATOR);
        int port = defaultPort(scheme);
        String rawHost = authority;
        if (colon >= 0) {
            String digits = authority.substring(colon + 1);
            if (!PORT.matcher(digits).matches() || Integer.parseInt(digits) > MAX_PORT) {
                throw bad();
            }
            port = Integer.parseInt(digits);
            rawHost = authority.substring(0, colon);
        }
        // LABEL admits ASCII letters, digits and hyphens only, so any Unicode host fails here.
        String host = asciiLower(rawHost);
        if (!isCanonicalHost(host)) {
            throw bad();
        }
        return new Origin(scheme, host, port);
    }

    /** LDH labels, no trailing dot, and a numeric-looking host only as a canonical dotted quad. */
    private static boolean isCanonicalHost(String host) {
        if (host.length() > MAX_HOST) {
            return false;
        }
        // An empty host, an empty label and a trailing dot all leave an empty label here.
        String[] labels = host.split("\\.", -1);
        for (String label : labels) {
            if (!LABEL.matcher(label).matches()) {
                return false;
            }
        }
        String last = labels[labels.length - 1];
        if (NUMERIC.matcher(last).matches() || last.startsWith(HEX_PREFIX)) {
            return isDottedQuad(host);
        }
        return true;
    }

    private static boolean isDottedQuad(String host) {
        if (!IPV4_LABELS.matcher(host).matches()) {
            return false;
        }
        for (String octet : host.split("\\.", -1)) {
            if (!OCTET.matcher(octet).matches() || Integer.parseInt(octet) > MAX_OCTET) {
                return false;
            }
        }
        return true;
    }

    /**
     * Lowercases A–Z only. Every other character is left for the checks that follow to refuse;
     * locale-aware case mapping (dotless i, Kelvin sign) never runs on browser input.
     */
    private static String asciiLower(String text) {
        char[] chars = text.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] >= FIRST_UPPER && chars[i] <= LAST_UPPER) {
                chars[i] = (char) (chars[i] + CASE_OFFSET);
            }
        }
        return String.valueOf(chars);
    }

    private static int defaultPort(String scheme) {
        return HTTPS.equals(scheme) ? HTTPS_PORT : HTTP_PORT;
    }

    private static HostException bad() {
        return new HostException(HostException.Code.BAD_ORIGIN);
    }
}
