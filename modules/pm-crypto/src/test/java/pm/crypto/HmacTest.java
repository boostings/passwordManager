package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** HMAC-SHA256 against RFC 4231 and the verify contract. */
class HmacTest {
    private static final HexFormat HEX = HexFormat.of();

    @Test
    void rfc4231Vectors() throws CryptoException {
        try (SecretBytes k1 = SecretBytes.copyOf(HEX.parseHex("0b".repeat(20)));
                SecretBytes k2 = SecretBytes.copyOf("Jefe".getBytes(StandardCharsets.US_ASCII))) {
            assertEquals("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                    HEX.formatHex(Hmac.anyKey(k1, "Hi There".getBytes(StandardCharsets.US_ASCII))));
            assertEquals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                    HEX.formatHex(Hmac.anyKey(k2, "what do ya want for nothing?".getBytes(StandardCharsets.US_ASCII))));
        }
    }

    @Test
    void verifyAcceptsTheTagAndNothingElse() throws CryptoException {
        byte[] data = {1, 2, 3};
        try (SecretBytes key = Csprng.secretBytes(32); SecretBytes other = Csprng.secretBytes(32)) {
            byte[] tag = Hmac.sha256(key, data);
            assertEquals(Hmac.TAG_BYTES, tag.length);
            assertArrayEquals(tag, Hmac.anyKey(key, data));
            assertTrue(Hmac.verify(key, data, tag));
            assertFalse(Hmac.verify(other, data, tag));
            assertFalse(Hmac.verify(key, new byte[] {1, 2, 4}, tag));
            tag[0] ^= 1;
            assertFalse(Hmac.verify(key, data, tag));
            assertFalse(Hmac.verify(key, data, new byte[0]));
        }
    }

    @Test
    void shortKeysAreRefused() {
        try (SecretBytes key = Csprng.secretBytes(Hmac.MIN_KEY_BYTES - 1)) {
            CryptoException e = assertThrows(CryptoException.class, () -> Hmac.sha256(key, new byte[1]));
            assertEquals(CryptoException.Code.BAD_INPUT, e.code());
        }
    }
}
