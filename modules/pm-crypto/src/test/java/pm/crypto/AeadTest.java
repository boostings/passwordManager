package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/** AES-256-GCM with the ADR 0005 zero nonce: known answers, round trip, and tamper detection. */
class AeadTest {
    private static final HexFormat HEX = HexFormat.of();
    private static final int TAG_LEN = Aead.TAG_BITS / Byte.SIZE;

    // McGrew & Viega GCM spec (NIST submission), test cases 13 and 14: 256-bit zero key, 96-bit zero IV.
    private static final String GCM_TC13_TAG_HEX = "530f8afbc74536b9a963b4f1c4cb738b";
    private static final String GCM_TC14_PT_HEX = "00".repeat(16);
    private static final String GCM_TC14_CT_TAG_HEX = "cea7403d4d606b6e074ec5d3baf39d18" + "d0d1c8a799996bf0265b98b5d48ab919";

    private static SecretBytes sb(byte[] b) {
        return SecretBytes.copyOf(b);
    }

    private static byte[] raw(SecretBytes s) {
        return TestBytes.copyOut(s);
    }

    private static void assertCode(CryptoException.Code code, Executable call) {
        CryptoException e = assertThrows(CryptoException.class, call);
        assertEquals(code, e.code());
        assertEquals(code.name(), e.getMessage());
        assertNull(e.getCause());
    }

    private static void flipBit(byte[] a, int bit) {
        int pos = Math.floorMod(bit, a.length * Byte.SIZE);
        a[pos / Byte.SIZE] ^= (byte) (1 << (pos % Byte.SIZE));
    }

    @Test
    void gcmTestCase13EmptyPlaintext() throws CryptoException {
        byte[] sealed = Aead.sealWithFreshKey(sb(new byte[Aead.KEY_LEN]), sb(new byte[0]), new byte[0]);
        assertArrayEquals(HEX.parseHex(GCM_TC13_TAG_HEX), sealed);
        try (SecretBytes back = Aead.openWithFreshKey(sb(new byte[Aead.KEY_LEN]), sealed, new byte[0])) {
            assertEquals(0, back.length());
        }
    }

    @Test
    void gcmTestCase14OneZeroBlock() throws CryptoException {
        byte[] sealed = Aead.sealWithFreshKey(sb(new byte[Aead.KEY_LEN]), sb(HEX.parseHex(GCM_TC14_PT_HEX)), new byte[0]);
        assertArrayEquals(HEX.parseHex(GCM_TC14_CT_TAG_HEX), sealed);
    }

    @Test
    void roundTripAndTamper() throws CryptoException {
        byte[] k = new byte[Aead.KEY_LEN];
        k[0] = 7;
        byte[] aad = "header".getBytes(StandardCharsets.UTF_8);
        byte[] pt = "vault payload".getBytes(StandardCharsets.UTF_8);
        byte[] sealed = Aead.sealWithFreshKey(sb(k), sb(pt), aad);
        assertEquals(pt.length + TAG_LEN, sealed.length);
        try (SecretBytes back = Aead.openWithFreshKey(sb(k), sealed, aad)) {
            assertArrayEquals(pt, raw(back));
        }
        sealed[0] ^= 1;
        assertCode(CryptoException.Code.AUTH_FAILED, () -> Aead.openWithFreshKey(sb(k), sealed, aad));
    }

    /** ADR 0005: seal consumes its key, so a second seal under the same key (nonce reuse) is impossible. */
    @Test
    void sealConsumesKeySoSecondSealThrows() throws CryptoException {
        try (SecretBytes key = sb(new byte[Aead.KEY_LEN])) {
            byte[] first = Aead.sealWithFreshKey(key, sb(new byte[1]), new byte[0]);
            assertEquals(1 + TAG_LEN, first.length);
            assertTrue(key.isClosed());
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> Aead.sealWithFreshKey(key, sb(new byte[1]), new byte[0]));
            assertEquals("SECRET_CLOSED", e.getMessage());
        }
    }

    @Test
    void sealConsumesKeyEvenWhenItFails() {
        try (SecretBytes shortKey = sb(new byte[Aead.KEY_LEN - 1])) {
            assertCode(CryptoException.Code.BAD_INPUT, () -> Aead.sealWithFreshKey(shortKey, sb(new byte[1]), new byte[0]));
            assertTrue(shortKey.isClosed());
        }
    }

    @Test
    void openDoesNotConsumeKey() throws CryptoException {
        byte[] sealed = Aead.sealWithFreshKey(sb(new byte[Aead.KEY_LEN]), sb(new byte[1]), new byte[0]);
        try (SecretBytes key = sb(new byte[Aead.KEY_LEN]);
                SecretBytes a = Aead.openWithFreshKey(key, sealed, new byte[0]);
                SecretBytes b = Aead.openWithFreshKey(key, sealed, new byte[0])) {
            assertFalse(key.isClosed());
            assertEquals(a, b);
        }
    }

    @Test
    void keyMustBe32Bytes() {
        for (int len : new int[] {0, 16, 24, 31, 33}) {
            assertCode(CryptoException.Code.BAD_INPUT,
                    () -> Aead.sealWithFreshKey(sb(new byte[len]), sb(new byte[1]), new byte[0]));
            assertCode(CryptoException.Code.BAD_INPUT,
                    () -> Aead.openWithFreshKey(sb(new byte[len]), new byte[TAG_LEN], new byte[0]));
        }
    }

    @Test
    void inputShorterThanTagFailsAuth() {
        for (int len : new int[] {0, 1, TAG_LEN - 1}) {
            assertCode(CryptoException.Code.AUTH_FAILED,
                    () -> Aead.openWithFreshKey(sb(new byte[Aead.KEY_LEN]), new byte[len], new byte[0]));
        }
    }

    @Property(tries = 200)
    void openInvertsSeal(@ForAll @Size(32) byte[] k, @ForAll @Size(max = 256) byte[] pt,
                         @ForAll @Size(max = 64) byte[] aad) throws CryptoException {
        byte[] sealed = Aead.sealWithFreshKey(sb(k), sb(pt), aad);
        try (SecretBytes back = Aead.openWithFreshKey(sb(k), sealed, aad)) {
            assertArrayEquals(pt, raw(back));
        }
    }

    @Property(tries = 200)
    void flippingAnyCiphertextBitFailsAuth(@ForAll @Size(32) byte[] k, @ForAll @Size(max = 64) byte[] pt,
                                           @ForAll @Size(max = 32) byte[] aad, @ForAll int bit)
            throws CryptoException {
        byte[] sealed = Aead.sealWithFreshKey(sb(k), sb(pt), aad);
        flipBit(sealed, bit);
        assertCode(CryptoException.Code.AUTH_FAILED, () -> Aead.openWithFreshKey(sb(k), sealed, aad));
    }

    @Property(tries = 200)
    void flippingAnyAadBitFailsAuth(@ForAll @Size(32) byte[] k, @ForAll @Size(max = 64) byte[] pt,
                                    @ForAll @Size(min = 1, max = 32) byte[] aad, @ForAll int bit)
            throws CryptoException {
        byte[] sealed = Aead.sealWithFreshKey(sb(k), sb(pt), aad);
        byte[] tampered = aad.clone();
        flipBit(tampered, bit);
        assertCode(CryptoException.Code.AUTH_FAILED, () -> Aead.openWithFreshKey(sb(k), sealed, tampered));
    }
}
