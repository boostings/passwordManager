package pm.browser.webauthn;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import pm.crypto.ConstantTime;
import pm.crypto.Hash;

/**
 * The public suffix of a host name (https://publicsuffix.org/list/ algorithm), from a vendored,
 * pinned snapshot of the Public Suffix List (ADR 0016 M6.3 addendum, SR-116). Both the ICANN and
 * the private sections apply, as in the HTML Standard's "public suffix". The snapshot is the
 * resource {@code public_suffix_list.dat} next to this class: an unmodified MPL-2.0 file whose
 * SHA-256 is checked on load; a different file is refused, so the list cannot change without a
 * reviewed code change. Rules are held as lower-case A-labels.
 *
 * <p>Nothing is loaded when the class initialises: {@link #pinned(Source)} reads and checks a
 * snapshot when asked and answers empty for a missing or different file, so a damaged snapshot
 * disables RP ID checks (and so WebAuthn) and nothing else ({@link RpId}).
 */
public final class PublicSuffixList {
    /** Where the snapshot came from. */
    public static final String SOURCE = "https://publicsuffix.org/list/public_suffix_list.dat";
    /** The snapshot's VERSION line. */
    public static final String VERSION = "2026-10-01_23-02-52_UTC";
    /** SHA-256 of the vendored file, lower-case hex. */
    public static final String SHA256 = "e0fe072d26b0536525badea237953ff451c9f8e64c9d02c6daa81a4491d2fc66";

    private static final String RESOURCE = "public_suffix_list.dat";
    private static final String COMMENT = "//";
    private static final String WILDCARD = "*.";
    private static final String EXCEPTION = "!";
    private static final String ACE_PREFIX = "xn--";
    private static final Pattern RULE_END = Pattern.compile("\\s");
    private static final char DOT = '.';
    private static final int ASCII_END = 0x80;

    /** The vendored snapshot, the resource {@code public_suffix_list.dat} next to this class. */
    public static final Source VENDORED = fromResource(RESOURCE);

    private final Set<String> rules = new HashSet<>();
    private final Set<String> wildcards = new HashSet<>();
    private final Set<String> exceptions = new HashSet<>();

    private PublicSuffixList(String text) {
        for (String raw : text.split("\n", -1)) {
            String line = raw.strip();
            if (line.isEmpty() || line.startsWith(COMMENT)) {
                continue;
            }
            String rule = RULE_END.split(line, 2)[0];
            if (rule.startsWith(EXCEPTION)) {
                exceptions.add(aLabels(rule.substring(EXCEPTION.length())));
            } else if (rule.startsWith(WILDCARD)) {
                wildcards.add(aLabels(rule.substring(WILDCARD.length())));
            } else {
                rules.add(aLabels(rule));
            }
        }
    }

    /** Supplies the bytes of a snapshot. */
    @FunctionalInterface
    public interface Source {
        /**
         * The snapshot's bytes.
         *
         * @throws IOException if they cannot be read
         */
        byte[] read() throws IOException;
    }

    /**
     * The snapshot from {@code source} if it is exactly the pinned file ({@link #SHA256}); empty if
     * it cannot be read or is any other file.
     */
    public static Optional<PublicSuffixList> pinned(Source source) {
        Objects.requireNonNull(source, "source");
        byte[] data;
        try {
            data = source.read();
        } catch (IOException e) {
            return Optional.empty();
        }
        return verified(data, SHA256);
    }

    /** Parses {@code data} if its SHA-256 is {@code sha256Hex}; else empty. */
    static Optional<PublicSuffixList> verified(byte[] data, String sha256Hex) {
        if (!ConstantTime.equals(Hash.sha256(data), HexFormat.of().parseHex(sha256Hex))) {
            return Optional.empty();
        }
        return Optional.of(new PublicSuffixList(new String(data, StandardCharsets.UTF_8)));
    }

    /** A source reading resource {@code name} next to this class; a missing one fails to read. */
    static Source fromResource(String name) {
        Objects.requireNonNull(name, "name");
        return () -> {
            try (InputStream in = PublicSuffixList.class.getResourceAsStream(name)) {
                if (in == null) {
                    throw new FileNotFoundException(name);
                }
                return in.readAllBytes();
            }
        };
    }

    /**
     * The public suffix of {@code host}, a canonical lower-case A-label host name: the labels
     * matched by the prevailing rule (an exception rule minus its first label; else the longest
     * matching rule, {@code *} matching one label; else the last label).
     */
    public String publicSuffixOf(String host) {
        Objects.requireNonNull(host, "host");
        String[] labels = host.split("\\.", -1);
        int n = labels.length;
        int longest = 1;
        for (int i = 0; i < n; i++) {
            String suffix = String.join(".", Arrays.copyOfRange(labels, i, n));
            if (exceptions.contains(suffix)) {
                return String.join(".", Arrays.copyOfRange(labels, i + 1, n));
            }
            if (rules.contains(suffix)) {
                longest = Math.max(longest, n - i);
            }
            if (i > 0 && wildcards.contains(suffix)) {
                longest = Math.max(longest, n - i + 1);
            }
        }
        return String.join(".", Arrays.copyOfRange(labels, n - longest, n));
    }

    /** True if {@code host} is itself a public suffix. */
    public boolean isPublicSuffix(String host) {
        return publicSuffixOf(host).equals(host);
    }

    /** A rule with every non-ASCII label in {@code xn--} form. */
    private static String aLabels(String rule) {
        StringBuilder out = new StringBuilder(rule.length());
        for (String label : rule.split("\\.", -1)) {
            if (!out.isEmpty()) {
                out.append(DOT);
            }
            out.append(label.chars().allMatch(c -> c < ASCII_END)
                    ? label : ACE_PREFIX + Punycode.encode(label));
        }
        return out.toString();
    }
}
