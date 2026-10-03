package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;

/** The throwaway ECDSA P-256 HTTPS identity for browser-only receiving. */
class WebIdentityTest {
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final InetAddress HOST = InetAddress.getLoopbackAddress();

    @Test
    void certificateIsSelfSignedForTheHostAndTheWindow() throws CryptoException, java.security.cert.CertificateException {
        WebIdentity web = WebIdentity.generate(NOW, Duration.ofMinutes(10), HOST);
        X509Certificate cert = web.x509();
        assertDoesNotThrow(() -> cert.verify(cert.getPublicKey()));
        assertEquals("EC", cert.getPublicKey().getAlgorithm());
        assertEquals("SHA256withECDSA", cert.getSigAlgName());
        assertEquals(NOW.minus(Duration.ofHours(1)), cert.getNotBefore().toInstant());
        assertEquals(NOW.plus(Duration.ofMinutes(10)), cert.getNotAfter().toInstant());
        assertEquals(List.of(List.of(7, HOST.getHostAddress())), cert.getSubjectAlternativeNames().stream()
                .map(List::copyOf).toList());
        assertEquals(List.of("1.3.6.1.5.5.7.3.1"), cert.getExtendedKeyUsage());
        assertEquals(-1, cert.getBasicConstraints());
        assertArrayEquals(cert.getEncoded(), web.certificate());
        assertTrue(web.key().getAlgorithm().startsWith("EC"));
    }

    @Test
    void fingerprintIsTheSha256OfTheCertificateAsBrowsersShowIt() throws CryptoException {
        WebIdentity web = WebIdentity.generate(NOW, Duration.ofMinutes(10), HOST);
        String hex = HexFormat.of().formatHex(Hash.sha256(web.certificate())).toUpperCase(Locale.ROOT);
        assertEquals(hex, web.fingerprint().replace(":", ""));
        assertEquals(32 * 3 - 1, web.fingerprint().length());
    }

    @Test
    void eachIdentityIsNew() throws CryptoException {
        WebIdentity a = WebIdentity.generate(NOW, Duration.ofMinutes(10), HOST);
        WebIdentity b = WebIdentity.generate(NOW, Duration.ofMinutes(10), HOST);
        assertTrue(!a.fingerprint().equals(b.fingerprint()));
    }

    @Test
    void validityMustBePositiveAndAtMostTheLongestWindow() {
        DeviceIdentityTest.assertBadInput(() -> WebIdentity.generate(NOW, Duration.ZERO, HOST));
        DeviceIdentityTest.assertBadInput(() -> WebIdentity.generate(NOW, Duration.ofSeconds(-1), HOST));
        DeviceIdentityTest.assertBadInput(() -> WebIdentity.generate(NOW,
                WebIdentity.MAX_VALIDITY.plusSeconds(1), HOST));
        assertDoesNotThrow(() -> WebIdentity.generate(NOW, WebIdentity.MAX_VALIDITY, HOST));
    }
}
