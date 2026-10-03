package pm.sharing.web;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import pm.crypto.Aead;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;
import pm.sharing.share.Shares;

class WebShareTest {
    static final Instant T0 = Instant.parse("2026-10-03T12:00:00Z");
    static final byte[] TEXT = "DB_PASSWORD=correct horse".getBytes(StandardCharsets.UTF_8);

    static WebShare seal(Duration ttl) throws CryptoException {
        try (SecretBytes p = SecretBytes.copyOf(TEXT)) {
            return seal(p, ttl);
        }
    }

    static WebShare seal(SecretBytes payload, Duration ttl) throws CryptoException {
        return WebShare.seal(payload, ttl, T0);
    }

    /** The key in the URL fragment opens the ciphertext under the share id as associated data. */
    @Test
    void theFragmentKeyOpensTheCiphertextBoundToTheId() throws CryptoException, UnknownHostException {
        try (WebShare s = seal(Duration.ofMinutes(10))) {
            String url = s.url(InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 168, 1, 20}), 8443);
            assertTrue(url.startsWith("https://192.168.1.20:8443/s/" + s.id() + "#"), url);
            byte[] key = Base64.getUrlDecoder().decode(url.substring(url.indexOf('#') + 1));
            assertEquals(WebShare.KEY_BYTES, key.length);
            byte[] id = HexFormat.of().parseHex(s.id());
            assertEquals(WebShare.ID_BYTES, id.length);
            try (SecretBytes k = SecretBytes.takeOwnership(key); SecretBytes plain = Aead.openWithFreshKey(k,
                    s.ciphertext(), id)) {
                assertArrayEquals(TEXT, plain.apply(byte[]::clone));
                byte[] otherId = id.clone();
                otherId[0] ^= 1;
                assertThrows(CryptoException.class, () -> Aead.openWithFreshKey(k, s.ciphertext(), otherId));
            }
            assertEquals(T0.plus(Duration.ofMinutes(10)), s.expires());
        }
    }

    @Test
    void ipv6HostsAreBracketedWithoutTheScope() throws CryptoException, UnknownHostException {
        try (WebShare s = seal(Duration.ofMinutes(1))) {
            byte[] linkLocal = new byte[16];
            linkLocal[0] = (byte) 0xfe;
            linkLocal[1] = (byte) 0x80;
            linkLocal[15] = 1;
            assertTrue(s.url(Inet6Address.getByAddress(null, linkLocal, 1), 9)
                    .startsWith("https://[fe80:0:0:0:0:0:0:1]:9/s/"));
            byte[] loopback = new byte[16];
            loopback[15] = 1;
            assertTrue(s.url(InetAddress.getByAddress(loopback), 9).startsWith("https://[0:0:0:0:0:0:0:1]:9/s/"));
        }
    }

    @Test
    void everyShareHasItsOwnIdAndKey() throws CryptoException {
        try (WebShare a = seal(Duration.ofMinutes(1)); WebShare b = seal(Duration.ofMinutes(1))) {
            assertNotEquals(a.id(), b.id());
            InetAddress h = InetAddress.getLoopbackAddress();
            assertNotEquals(a.url(h, 1).split("#", -1)[1], b.url(h, 1).split("#", -1)[1]);
        }
    }

    @Test
    void closeWipesTheKey() throws CryptoException {
        assertThrows(IllegalStateException.class, () -> closedShare().url(InetAddress.getLoopbackAddress(), 1));
    }

    private static WebShare closedShare() throws CryptoException {
        try (WebShare s = seal(Duration.ofMinutes(1))) {
            return s;
        }
    }

    @Test
    void payloadAndWindowAreBounded() throws CryptoException {
        assertBad(() -> seal(Duration.ofMillis(999)));
        assertBad(() -> seal(Shares.MAX_TTL.plusSeconds(1)));
        try (WebShare longest = seal(Shares.MAX_TTL)) {
            assertEquals(T0.plus(Shares.MAX_TTL), longest.expires());
        }
        try (SecretBytes empty = SecretBytes.copyOf(new byte[0]);
                SecretBytes big = SecretBytes.copyOf(new byte[WebShare.MAX_PAYLOAD + 1]);
                SecretBytes max = SecretBytes.copyOf(new byte[WebShare.MAX_PAYLOAD])) {
            assertBad(() -> seal(empty, Duration.ofMinutes(1)));
            assertBad(() -> seal(big, Duration.ofMinutes(1)));
            try (WebShare largest = seal(max, Duration.ofMinutes(1))) {
                assertEquals(WebShare.MAX_PAYLOAD + 16, largest.ciphertext().length);
            }
        }
    }

    private static void assertBad(org.junit.jupiter.api.function.Executable call) {
        assertEquals(CryptoException.Code.BAD_INPUT, assertThrows(CryptoException.class, call).code());
    }
}
