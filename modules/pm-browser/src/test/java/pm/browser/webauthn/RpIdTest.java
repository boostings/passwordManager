package pm.browser.webauthn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.browser.bridge.Origin;
import pm.browser.host.HostException;

/**
 * RP ID validation against the specifications' own examples (SR-116, SR-400). Each vector names
 * the section it comes from: WebAuthn Level 3 §4 (Terminology, "RP ID"), and the HTML Standard
 * §7.1.1.2 ("Relaxing the same-origin restriction", the table of "is a registrable domain suffix
 * of or is equal to" examples).
 */
@Tag("T-PK-01")
final class RpIdTest {
    private static final PublicSuffixList PSL = PublicSuffixListTest.vendored();

    /** A dotted-quad IPv4 address (built, so the test holds no address literals). */
    private static String ip(int a, int b, int c, int d) {
        return a + "." + b + "." + c + "." + d;
    }

    private static boolean valid(String origin, String rpId) throws HostException {
        try {
            assertEquals(rpId, RpId.vendored().validate(Origin.parse(origin), rpId));
            return true;
        } catch (HostException e) {
            assertEquals(HostException.Code.BAD_RP_ID, e.code());
            return false;
        }
    }

    /** WebAuthn L3 §4 "RP ID": the origin https://login.example.com:1337 example. */
    @Test
    void webauthnSection4Example() throws HostException {
        String origin = "https://login.example.com:1337";
        assertTrue(valid(origin, "login.example.com"));
        assertTrue(valid(origin, "example.com"));
        assertFalse(valid(origin, "m.login.example.com"));
        assertFalse(valid(origin, "com"));
    }

    /** WebAuthn L3 §4 "RP ID": https, or http only on localhost (http://localhost:8000 is valid). */
    @Test
    void webauthnSection4SchemeRule() throws HostException {
        assertTrue(valid("http://localhost:8000", "localhost"));
        assertFalse(valid("http://example.com", "example.com"));
        assertFalse(valid("http://login.example.com:8080", "example.com"));
        assertTrue(valid("https://localhost", "localhost"));
    }

    /** WebAuthn L3 §5.1.3 step 7 / §5.1.4.1 step 6: an effective domain that is not a valid domain. */
    @Test
    void ipAddressOriginsHaveNoRpId() throws HostException {
        assertFalse(valid("https://" + ip(192, 0, 2, 10), ip(192, 0, 2, 10)));
        assertFalse(valid("https://" + ip(127, 0, 0, 1) + ":8443", ip(127, 0, 0, 1)));
        assertFalse(valid("https://" + ip(127, 0, 0, 1), "localhost"));
    }

    /**
     * HTML §7.1.1.2 example table, row by row (hostSuffixString, originalHost, outcome). Rows the
     * canonical-origin rules refuse before this algorithm runs are marked; pm is stricter there.
     */
    @Test
    void htmlSection7_1_1_2ExampleTable() {
        // "0.0.0.0" / 0.0.0.0: equal, so true.
        assertTrue(RpId.isRegistrableSuffixOrEqual(ip(0, 0, 0, 0), ip(0, 0, 0, 0), PSL));
        // "0x10203" / 0.1.2.3 and "[0::1]" / ::1: true in HTML; pm refuses non-canonical IPv4 and
        // IPv6 as RP IDs and origins (M5.2 rules), and WebAuthn refuses IP effective domains anyway.
        assertThrows(HostException.class, () -> Origin.parse("https://0x10203"));
        assertThrows(HostException.class, () -> Origin.parse("https://[::1]"));
        // "example.com" / example.com: true.
        assertTrue(RpId.isRegistrableSuffixOrEqual("example.com", "example.com", PSL));
        // "example.com" / example.com. and "example.com." / example.com: false (a trailing dot
        // is never canonical, so neither string reaches the comparison).
        assertFalse(RpId.isRegistrableSuffixOrEqual("example.com", "example.com.", PSL));
        assertFalse(RpId.isRegistrableSuffixOrEqual("example.com.", "example.com", PSL));
        assertThrows(HostException.class,
                () -> RpId.vendored().validate(Origin.parse("https://example.com"), "example.com."));
        // "example.com" / www.example.com: true.
        assertTrue(RpId.isRegistrableSuffixOrEqual("example.com", "www.example.com", PSL));
        // "com" / example.com: false (a public suffix).
        assertFalse(RpId.isRegistrableSuffixOrEqual("com", "example.com", PSL));
        // "example" / example: true.
        assertTrue(RpId.isRegistrableSuffixOrEqual("example", "example", PSL));
        // "compute.amazonaws.com" / example.compute.amazonaws.com: false (*.compute.amazonaws.com).
        assertFalse(RpId.isRegistrableSuffixOrEqual("compute.amazonaws.com", "example.compute.amazonaws.com", PSL));
        // "example.compute.amazonaws.com" / www.example.compute.amazonaws.com: false.
        assertFalse(RpId.isRegistrableSuffixOrEqual("example.compute.amazonaws.com",
                "www.example.compute.amazonaws.com", PSL));
        // "amazonaws.com" / www.example.compute.amazonaws.com: false.
        assertFalse(RpId.isRegistrableSuffixOrEqual("amazonaws.com", "www.example.compute.amazonaws.com", PSL));
        // "amazonaws.com" / test.amazonaws.com: true.
        assertTrue(RpId.isRegistrableSuffixOrEqual("amazonaws.com", "test.amazonaws.com", PSL));
    }

    /** The same table through the full WebAuthn check, for the rows that are domains. */
    @Test
    void htmlTableThroughTheWebauthnCheck() throws HostException {
        assertTrue(valid("https://www.example.com", "example.com"));
        assertFalse(valid("https://example.com", "com"));
        assertTrue(valid("https://example", "example"));
        assertFalse(valid("https://example.compute.amazonaws.com", "compute.amazonaws.com"));
        assertFalse(valid("https://www.example.compute.amazonaws.com", "example.compute.amazonaws.com"));
        assertFalse(valid("https://www.example.compute.amazonaws.com", "amazonaws.com"));
        assertTrue(valid("https://test.amazonaws.com", "amazonaws.com"));
    }

    /** Public suffixes from the private section and exception rules (PSL algorithm). */
    @Test
    void privateSuffixesAndExceptions() throws HostException {
        assertFalse(valid("https://alice.github.io", "github.io"));
        assertTrue(valid("https://alice.github.io", "alice.github.io"));
        assertFalse(valid("https://www.example.co.uk", "co.uk"));
        assertTrue(valid("https://www.example.co.uk", "example.co.uk"));
        // *.ck with the exception !www.ck: www.ck is registrable, anything.ck is a suffix.
        assertTrue(valid("https://a.www.ck", "www.ck"));
        assertFalse(valid("https://a.b.ck", "b.ck"));
        // IDN suffixes match in A-label form: xn--55qx5d.cn is 公司.cn.
        assertFalse(valid("https://shop.xn--55qx5d.cn", "xn--55qx5d.cn"));
        assertTrue(valid("https://www.shop.xn--55qx5d.cn", "shop.xn--55qx5d.cn"));
    }

    /** RP IDs must be canonical host names: case, ports, paths, dots, IPs and non-ASCII refused. */
    @Test
    void nonCanonicalRpIdsAreRefused() throws HostException {
        for (String bad : List.of("Example.com", "example.com:443", "example.com/", ".example.com", "example..com",
                "", "*.example.com", "exa mple.com", "bücher.example", ip(10, 0, 0, 1), "example.com.",
                "user@example.com", "-example.com", "a".repeat(64) + ".com")) {
            assertFalse(valid("https://www.example.com", bad), bad);
        }
        // Not a suffix at a label boundary.
        assertFalse(valid("https://myexample.com", "example.com"));
        // Wider than the origin: a sibling and a different site.
        assertFalse(valid("https://login.example.com", "www.example.com"));
        assertFalse(valid("https://example.com", "example.org"));
    }

    @Test
    void ipComparisonsAreNeverSuffixes() {
        assertFalse(RpId.isRegistrableSuffixOrEqual("0.0.1", ip(10, 0, 0, 1), PSL));
        assertFalse(RpId.isRegistrableSuffixOrEqual("example.com", ip(10, 0, 0, 1), PSL));
        assertTrue(RpId.isIpAddress(ip(10, 0, 0, 1)));
        assertTrue(RpId.isIpAddress("1"));
        assertFalse(RpId.isIpAddress("10.0.0.a1"));
    }

    /**
     * A missing or tampered list is read once, on first use, and every check then answers
     * PSL_UNAVAILABLE (fix round, item 3); a good source behaves like the vendored one.
     */
    @Test
    void aDamagedListRefusesEveryCheckWithPslUnavailableAndIsReadOnce() throws IOException, HostException {
        byte[] good = PublicSuffixList.VENDORED.read();
        byte[] tampered = good.clone();
        tampered[0] ^= 1;
        AtomicInteger reads = new AtomicInteger();
        RpId damaged = RpId.from(() -> {
            reads.incrementAndGet();
            return tampered.clone();
        });
        RpId missing = RpId.from(() -> {
            reads.incrementAndGet();
            throw new FileNotFoundException("public_suffix_list.dat");
        });
        assertEquals(0, reads.get());
        Origin origin = Origin.parse("https://www.example.com");
        for (RpId broken : List.of(damaged, missing)) {
            for (int i = 0; i < 2; i++) {
                assertEquals(HostException.Code.PSL_UNAVAILABLE,
                        assertThrows(HostException.class, () -> broken.validate(origin, "example.com")).code());
            }
        }
        assertEquals(2, reads.get());
        RpId fine = RpId.from(() -> good);
        assertEquals("example.com", fine.validate(origin, "example.com"));
        assertEquals(HostException.Code.BAD_RP_ID,
                assertThrows(HostException.class, () -> fine.validate(origin, "com")).code());
        assertSame(RpId.vendored(), RpId.vendored());
        assertThrows(NullPointerException.class, () -> RpId.from(null));
    }
}
