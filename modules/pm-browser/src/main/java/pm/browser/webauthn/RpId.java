package pm.browser.webauthn;

import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;
import pm.browser.bridge.Origin;
import pm.browser.host.HostException;

/**
 * RP ID validation (ADR 0016 M6.3 addendum, SR-116): WebAuthn Level 3 §4 "RP ID", §5.1.3 step 8
 * and §5.1.4.1 step 7, which defer to the HTML Standard's "is a registrable domain suffix of or is
 * equal to" (§7.1.1.2 of the browsers chapter). The origin is first made canonical by
 * {@link Origin} (M5.2 rules: ASCII A-labels only, no IPv6, canonical IPv4 only).
 *
 * <p>Refused: an origin that is not {@code https} unless it is {@code http://localhost}
 * (§4: an RP ID needs a secure origin); an effective domain that is an IP address (§5.1.3: not a
 * valid domain, a SecurityError); an RP ID that is not a canonical host name or is an IP address;
 * and any RP ID other than the effective domain itself or a registrable suffix of it, using the
 * vendored {@link PublicSuffixList}. Related origins (§5.11) are not supported.
 *
 * <p>The list is read on first use, not at class initialisation, and the result is kept. If it
 * cannot be read or is not the pinned file, every check answers {@code PSL_UNAVAILABLE}: WebAuthn
 * is refused and every other request is unaffected.
 */
public final class RpId {
    private static final String HTTPS = "https";
    private static final String LOCALHOST = "localhost";
    private static final Pattern NUMERIC_LABEL = Pattern.compile("(.*\\.)?[0-9]+");
    private static final char DOT = '.';
    private static final String SCHEME_END = "://";
    private static final RpId SHARED = new RpId(PublicSuffixList.VENDORED);

    private final PublicSuffixList.Source source;
    private final ReentrantLock guard = new ReentrantLock();
    /** Guarded by {@link #guard}. */
    private boolean attempted;
    /** Guarded by {@link #guard}. Null until loaded, and after a failed load. */
    private PublicSuffixList loaded;

    private RpId(PublicSuffixList.Source source) {
        this.source = Objects.requireNonNull(source, "source");
    }

    /** RP ID checks against the vendored snapshot; one shared instance, so the list loads once. */
    public static RpId vendored() {
        return SHARED;
    }

    /** RP ID checks against the pinned snapshot read from {@code source} (tests supply a damaged one). */
    public static RpId from(PublicSuffixList.Source source) {
        return new RpId(source);
    }

    /**
     * Checks that {@code rpId} may be used by {@code origin}.
     *
     * @return {@code rpId}
     * @throws HostException {@code PSL_UNAVAILABLE} if the list is missing or is not the pinned
     *     file; else {@code BAD_RP_ID} if {@code rpId} may not be used
     */
    public String validate(Origin origin, String rpId) throws HostException {
        return validate(origin, rpId, suffixList());
    }

    /** The list, read and checked on first use; a failed load stays failed. */
    private PublicSuffixList suffixList() throws HostException {
        guard.lock();
        try {
            if (!attempted) {
                attempted = true;
                loaded = PublicSuffixList.pinned(source).orElse(null);
            }
            if (loaded == null) {
                throw new HostException(HostException.Code.PSL_UNAVAILABLE);
            }
            return loaded;
        } finally {
            guard.unlock();
        }
    }

    /** {@link #validate(Origin, String)} against {@code list}. */
    static String validate(Origin origin, String rpId, PublicSuffixList list) throws HostException {
        Objects.requireNonNull(origin, "origin");
        Objects.requireNonNull(rpId, "rpId");
        boolean secure = HTTPS.equals(origin.scheme()) || LOCALHOST.equals(origin.host());
        if (!secure || isIpAddress(origin.host()) || !isCanonicalDomain(rpId)
                || !isRegistrableSuffixOrEqual(rpId, origin.host(), list)) {
            throw new HostException(HostException.Code.BAD_RP_ID);
        }
        return rpId;
    }

    /**
     * The HTML Standard's "is a registrable domain suffix of or is equal to" for two canonical
     * hosts (§7.1.1.2, steps 3 to 4; parsing is done by {@link Origin}).
     */
    static boolean isRegistrableSuffixOrEqual(String suffix, String host, PublicSuffixList list) {
        if (suffix.equals(host)) {
            return true;
        }
        if (isIpAddress(suffix) || isIpAddress(host)) {
            return false;
        }
        String dotted = DOT + suffix;
        return host.endsWith(dotted) && !list.isPublicSuffix(suffix)
                && !list.publicSuffixOf(host).endsWith(dotted);
    }

    /**
     * A canonical host whose last label is all digits: {@link Origin} admits such a host only as a
     * canonical dotted-quad IPv4 address.
     */
    static boolean isIpAddress(String host) {
        return NUMERIC_LABEL.matcher(host).matches();
    }

    /** A host {@link Origin} accepts as canonical, and not an IP address. */
    private static boolean isCanonicalDomain(String rpId) {
        try {
            return Origin.parse(HTTPS + SCHEME_END + rpId).host().equals(rpId) && !isIpAddress(rpId);
        } catch (HostException e) {
            return false;
        }
    }
}
