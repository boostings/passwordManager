package pm.browser.bridge;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import pm.browser.host.HostException;

/** Origin canonicalisation and the confusion cases of SR-300/SR-306. */
@Tag("T-EXT-01")
class OriginTest {
    private static final String SITE = "https://example.com";

    @Test
    void caseAndDefaultPortsAreCanonicalised() throws HostException {
        Origin site = Origin.parse(SITE);
        assertEquals(new Origin("https", "example.com", 443), site);
        assertEquals(site, Origin.parse("HTTPS://Example.COM"));
        assertEquals(site, Origin.parse("https://example.com:443"));
        assertEquals(SITE, Origin.parse("https://EXAMPLE.com:443").text());
        assertEquals("http://example.com", Origin.parse("http://example.com:80").text());
        assertEquals("http://example.com:443", Origin.parse("http://example.com:443").text());
        assertEquals(SITE, site.toString());
    }

    @Test
    void subdomainsAndParentsAreDifferentOrigins() throws HostException {
        Origin site = Origin.parse(SITE);
        assertNotEquals(site, Origin.parse("https://a.example.com"));
        assertNotEquals(site, Origin.parse("https://www.example.com"));
        assertNotEquals(Origin.parse("https://a.example.com"), site);
        assertNotEquals(site, Origin.parse("https://example.com.evil.net"));
        assertNotEquals(site, Origin.parse("https://evil-example.com"));
        assertNotEquals(site, Origin.parse("https://com"));
    }

    @Test
    void schemeAndPortMustMatch() throws HostException {
        Origin site = Origin.parse(SITE);
        assertNotEquals(site, Origin.parse("http://example.com"));
        assertNotEquals(site, Origin.parse("https://example.com:8443"));
        assertEquals("https://example.com:8443", Origin.parse("https://example.com:8443").text());
        assertNotEquals(site, Origin.parse("http://example.com:443"));
        assertEquals(65_535, Origin.parse("https://example.com:65535").port());
    }

    @Test
    void ipLiteralsMustBeCanonicalDottedQuads() throws HostException {
        assertEquals("https://127.0.0.1:8443", Origin.parse("https://127.0.0.1:8443").text());
        assertEquals("http://0.0.0.0", Origin.parse("http://0.0.0.0").text());
        assertNotEquals(Origin.parse("https://127.0.0.1"), Origin.parse("https://localhost"));
    }

    @Test
    void punycodeLookalikesAreDistinctFromTheirTargets() throws HostException {
        // Browsers serialise location.origin with A-labels; those compare exactly, case-insensitively.
        Origin apple = Origin.parse("https://apple.com");
        Origin cyrillic = Origin.parse("https://xn--pple-43d.com"); // CYRILLIC SMALL LETTER A + "pple"
        assertNotEquals(apple, cyrillic);
        assertEquals(cyrillic, Origin.parse("https://XN--PPLE-43D.com"));
        assertEquals("https://xn--fa-hia.de", Origin.parse("https://xn--fa-hia.de").text());
        assertNotEquals(Origin.parse("https://fass.de"), Origin.parse("https://xn--fa-hia.de"));
        assertNotEquals(Origin.parse("https://xn--4xa.com"), Origin.parse("https://xn--3xa.com"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "https://faß.de", // IDNA2003 maps this to fass.de; browsers to xn--fa-hia.de
        "https://ς.com", // IDNA2003 maps final sigma to σ; browsers keep it
        "https://a\u200Db.com", // ZERO WIDTH JOINER: IDNA2003 drops it, browsers refuse it
        "https://a\u200Cb.com", // ZERO WIDTH NON-JOINER
        "https://аpple.com", // CYRILLIC SMALL LETTER A
        "https://ｅxample.com", // FULLWIDTH LATIN SMALL LETTER E
        "https://Bücher.example",
        "https://example\u3002com", // IDEOGRAPHIC FULL STOP
        "https://exam\u00ADple.com", // SOFT HYPHEN
    })
    void unicodeHostsAreRefusedNotMapped(String text) {
        assertEquals(HostException.Code.BAD_ORIGIN,
                assertThrows(HostException.class, () -> Origin.parse(text)).code());
        assertEquals(Optional.empty(), Origin.ofUrl(text + "/login"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "example.com", "://example.com", "https:/example.com", "https://",
        "ftp://example.com", "javascript://example.com", "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
        "file://example.com", "data://example.com",
        "https://example.com/", "https://example.com/login", "https://example.com?x=1", "https://example.com#top",
        "https://user@example.com", "https://user:pw@example.com", "https://example.com@evil.net",
        "https://example.com\\@evil.net", "https://ex%61mple.com", "https://exa mple.com",
        "https://example.com.", "https://example..com", "https://.example.com", "https://-example.com",
        "https://example-.com", "https://ex_ample.com", "https://example.com:", "https://example.com:0",
        "https://example.com:65536", "https://example.com:99999", "https://example.com:08443",
        "https://example.com:+443", "https://a:b:443", "https://[::1]", "https://[::1]:443",
        "https://0x7f.0.0.1", "https://2130706433", "https://127.1", "https://010.0.0.1",
        "https://256.0.0.1", "https://1.2.3.0x10", "https://1.2.3.4.5", "https://1.2.3.",
    })
    void confusingOrUnsupportedOriginsAreRefused(String text) {
        assertEquals(HostException.Code.BAD_ORIGIN,
                assertThrows(HostException.class, () -> Origin.parse(text)).code());
    }

    @Test
    void overlongTextAndLabelsAreRefused() {
        String label = "a".repeat(63);
        String longest = "https://" + label + "." + label + "." + label + "." + "a".repeat(56);
        assertEquals(Origin.MAX_TEXT, longest.length());
        assertEquals(longest, assertDoesNotThrow(() -> Origin.parse(longest)).text());
        assertThrows(HostException.class, () -> Origin.parse(longest + "a"));
        assertThrows(HostException.class, () -> Origin.parse("https://" + "a".repeat(64) + ".com"));
        String host254 = label + "." + label + "." + label + "." + "a".repeat(62);
        assertEquals(Origin.MAX_HOST + 1, host254.length());
        assertThrows(IllegalArgumentException.class, () -> new Origin("https", host254, 443));
    }

    @Test
    void theCanonicalConstructorChecksItsParts() {
        assertThrows(IllegalArgumentException.class, () -> new Origin("ftp", "example.com", 21));
        assertThrows(IllegalArgumentException.class, () -> new Origin("HTTPS", "example.com", 443));
        assertThrows(IllegalArgumentException.class, () -> new Origin("https", "Example.com", 443));
        assertThrows(IllegalArgumentException.class, () -> new Origin("https", "example.com.", 443));
        assertThrows(IllegalArgumentException.class, () -> new Origin("https", "example.com", 0));
        assertThrows(IllegalArgumentException.class, () -> new Origin("https", "example.com", 65_536));
        assertEquals("http://example.com:8080", new Origin("http", "example.com", 8080).text());
    }

    @Test
    void registeredUrlsLoseTheirPathQueryAndFragment() throws HostException {
        Origin site = Origin.parse(SITE);
        assertEquals(Optional.of(site), Origin.ofUrl("https://example.com/login?next=/#form"));
        assertEquals(Optional.of(site), Origin.ofUrl("https://Example.com"));
        assertEquals(Optional.of(site), Origin.ofUrl("https://example.com#x"));
        assertEquals(Optional.of(site), Origin.ofUrl("https://example.com?x"));
        assertEquals(Optional.of(Origin.parse("https://example.com:8443")), Origin.ofUrl("https://example.com:8443/a"));
        assertEquals(Optional.empty(), Origin.ofUrl("example.com/login"));
        assertEquals(Optional.empty(), Origin.ofUrl("https://user@example.com/login"));
        assertEquals(Optional.empty(), Origin.ofUrl("https://example.com./login"));
        assertEquals(Optional.empty(), Origin.ofUrl("android://com.example.app"));
        assertEquals(Optional.empty(), Origin.ofUrl(""));
    }
}
