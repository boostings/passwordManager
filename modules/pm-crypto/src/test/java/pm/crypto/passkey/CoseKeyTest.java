package pm.crypto.passkey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static pm.crypto.passkey.Vectors.assertBadInput;
import static pm.crypto.passkey.Vectors.hex;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;

/** The CTAP2 canonical COSE_Key of an ES256 P-256 public key (ADR 0016, SR-083). */
class CoseKeyTest {
    /**
     * The expected bytes, built by hand from RFC 9052/9053 and CTAP 2.1 §8: map(5) with keys in
     * canonical order 1, 3, -1, -2, -3.
     */
    private static final String EXPECTED = "a5"
            + "01" + "02" // 1 (kty): 2 (EC2)
            + "03" + "26" // 3 (alg): -7 (ES256)
            + "20" + "01" // -1 (crv): 1 (P-256)
            + "21" + "5820" + Vectors.RFC_UX // -2 (x): bstr(32)
            + "22" + "5820" + Vectors.RFC_UY; // -3 (y): bstr(32)

    @Test
    void encodingIsExactForAFixedKey() throws CryptoException {
        byte[] cose = CoseKey.encodeEc2(Vectors.rfcPoint());
        assertEquals(CoseKey.EC2_BYTES, cose.length);
        assertArrayEquals(hex(EXPECTED), cose);
        try (SecretBytes stored = Vectors.rfcStorage(); PasskeyKey key = PasskeyKey.fromStorage(stored)) {
            assertArrayEquals(hex(EXPECTED), key.cosePublicKey());
        }
    }

    @Test
    void decodingReturnsThePoint() throws CryptoException {
        assertArrayEquals(Vectors.rfcPoint(), CoseKey.decodeEc2(hex(EXPECTED)));
    }

    @Test
    void anythingButTheCanonicalLayoutIsRefused() {
        byte[] good = hex(EXPECTED);
        assertBadInput(() -> CoseKey.decodeEc2(new byte[0]));
        assertBadInput(() -> CoseKey.decodeEc2(Arrays.copyOf(good, 78)));
        assertBadInput(() -> CoseKey.decodeEc2(Arrays.copyOf(good, 76)));
        // Every prefix and y-label byte matters: kty, alg (e.g. -8 EdDSA = 0x27), crv, lengths, order.
        int[] fixed = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 42, 43, 44};
        for (int i : fixed) {
            byte[] mutated = good.clone();
            mutated[i] ^= 0x01;
            assertBadInput(() -> CoseKey.decodeEc2(mutated));
        }
        // Keys in a non-canonical order (-1 before 3) are refused even though the content matches.
        byte[] reordered = hex("a501022001032621" + "5820" + Vectors.RFC_UX + "225820" + Vectors.RFC_UY);
        assertBadInput(() -> CoseKey.decodeEc2(reordered));
        // A point not on the curve.
        byte[] offCurve = good.clone();
        offCurve[76] ^= 0x01;
        assertBadInput(() -> CoseKey.decodeEc2(offCurve));
    }

    @Test
    void encodingRefusesInvalidPoints() {
        byte[] point = Vectors.rfcPoint();
        assertBadInput(() -> CoseKey.encodeEc2(Arrays.copyOf(point, 64)));
        byte[] compressed = point.clone();
        compressed[0] = 0x02;
        assertBadInput(() -> CoseKey.encodeEc2(compressed));
        byte[] offCurve = point.clone();
        offCurve[64] ^= 0x01;
        assertBadInput(() -> CoseKey.encodeEc2(offCurve));
    }
}
