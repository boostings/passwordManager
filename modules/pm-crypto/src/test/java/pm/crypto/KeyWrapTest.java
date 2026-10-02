package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/** RFC 5649 AES-KWP known answers (cipher wiring) and the public 32-byte-KEK contract. */
class KeyWrapTest {
    private static final HexFormat HEX = HexFormat.of();

    // RFC 5649 §6: both vectors use a 192-bit KEK.
    private static final String RFC5649_KEK_HEX = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8";
    private static final String RFC5649_K20_HEX = "c37b7e6492584340bed12207808941155068f738";
    private static final String RFC5649_W20_HEX = "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a";
    private static final String RFC5649_K7_HEX = "466f7250617369";
    private static final String RFC5649_W7_HEX = "afbeb0f07dfbf5419200f2ccb50bb24f";

    private static SecretBytes sb(byte[] b) {
        return SecretBytes.copyOf(b);
    }

    private static byte[] raw(SecretBytes s) {
        return s.apply(byte[]::clone);
    }

    private static void assertCode(CryptoException.Code code, Executable call) {
        CryptoException e = assertThrows(CryptoException.class, call);
        assertEquals(code, e.code());
        assertEquals(code.name(), e.getMessage());
        assertNull(e.getCause());
    }

    private static void assertRfc5649(String wrappedHex, String keyHex)
            throws CryptoException, GeneralSecurityException {
        try (SecretBytes kek192 = sb(HEX.parseHex(RFC5649_KEK_HEX))) {
            byte[] w = KeyWrap.initCipher(Cipher.ENCRYPT_MODE, kek192).doFinal(HEX.parseHex(keyHex));
            assertArrayEquals(HEX.parseHex(wrappedHex), w);
            byte[] k = KeyWrap.initCipher(Cipher.DECRYPT_MODE, kek192).doFinal(w);
            assertArrayEquals(HEX.parseHex(keyHex), k);
        }
    }

    @Test
    void rfc5649Vector20ByteKey() throws CryptoException, GeneralSecurityException {
        assertRfc5649(RFC5649_W20_HEX, RFC5649_K20_HEX);
    }

    @Test
    void rfc5649Vector7ByteKey() throws CryptoException, GeneralSecurityException {
        assertRfc5649(RFC5649_W7_HEX, RFC5649_K7_HEX);
    }

    @Test
    void publicApiRequires32ByteKek() {
        for (int len : new int[] {16, 24, 31, 33}) {
            assertCode(CryptoException.Code.BAD_INPUT, () -> KeyWrap.wrap(sb(new byte[len]), sb(new byte[Kdf.SALT_LEN])));
            assertCode(CryptoException.Code.BAD_INPUT, () -> KeyWrap.unwrap(sb(new byte[len]), new byte[40]));
        }
    }

    @Test
    void emptyKeyIsRejected() {
        assertCode(CryptoException.Code.BAD_INPUT, () -> KeyWrap.wrap(sb(new byte[KeyWrap.KEK_LEN]), sb(new byte[0])));
    }

    @Test
    void malformedWrappedInputFailsAuth() {
        for (int len : new int[] {0, 8, 15, 16, 17, 23, 24}) {
            assertCode(CryptoException.Code.AUTH_FAILED, () -> KeyWrap.unwrap(sb(new byte[KeyWrap.KEK_LEN]), new byte[len]));
        }
    }

    /** Any garbage input fails with AUTH_FAILED only, never an unchecked provider exception. */
    @Property(tries = 300)
    void arbitraryWrappedInputOnlyFailsAuth(@ForAll @Size(32) byte[] kek, @ForAll @Size(max = 80) byte[] garbage) {
        assertCode(CryptoException.Code.AUTH_FAILED, () -> KeyWrap.unwrap(sb(kek), garbage));
    }

    @Property(tries = 200)
    void wrapUnwrapRoundTrip(@ForAll @Size(32) byte[] kek, @ForAll @Size(min = 1, max = 64) byte[] k)
            throws CryptoException {
        byte[] w = KeyWrap.wrap(sb(kek), sb(k));
        try (SecretBytes back = KeyWrap.unwrap(sb(kek), w)) {
            assertArrayEquals(k, raw(back));
        }
    }

    @Property(tries = 200)
    void unwrapWithDifferentKekFailsAuth(@ForAll @Size(32) byte[] kek, @ForAll @Size(min = 1, max = 64) byte[] k,
                                         @ForAll int bit) throws CryptoException {
        byte[] w = KeyWrap.wrap(sb(kek), sb(k));
        byte[] other = Arrays.copyOf(kek, kek.length);
        int pos = Math.floorMod(bit, other.length * Byte.SIZE);
        other[pos / Byte.SIZE] ^= (byte) (1 << (pos % Byte.SIZE));
        assertCode(CryptoException.Code.AUTH_FAILED, () -> KeyWrap.unwrap(sb(other), w));
    }

    @Property(tries = 200)
    void flippingAnyWrappedBitFailsAuth(@ForAll @Size(32) byte[] kek, @ForAll @Size(min = 1, max = 64) byte[] k,
                                        @ForAll int bit) throws CryptoException {
        byte[] w = KeyWrap.wrap(sb(kek), sb(k));
        int pos = Math.floorMod(bit, w.length * Byte.SIZE);
        w[pos / Byte.SIZE] ^= (byte) (1 << (pos % Byte.SIZE));
        assertCode(CryptoException.Code.AUTH_FAILED, () -> KeyWrap.unwrap(sb(kek), w));
    }
}
