package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HexFormat;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.Size;
import org.junit.jupiter.api.Test;

/**
 * The pairing construction (ADR 0010 Amendment 1). Known answers come from an independent Python
 * implementation (hashlib/hmac, HKDF per RFC 5869), not from this code.
 */
class PairingTest {
    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] KEY_A = range(0, 32);
    private static final byte[] KEY_B = range(32, 64);
    private static final byte[] NONCE_I = filled(0x11);
    private static final byte[] NONCE_R = filled(0x22);

    private static byte[] range(int from, int to) {
        byte[] b = new byte[to - from];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) (from + i);
        }
        return b;
    }

    private static byte[] filled(int v) {
        byte[] b = new byte[Pairing.NONCE_BYTES];
        Arrays.fill(b, (byte) v);
        return b;
    }

    @Test
    void knownAnswers() throws CryptoException {
        assertEquals("f95949a3f91568af1e7e10c70c092d2bda91f900b7acf5b7f342c5ed008542b6",
                HEX.formatHex(Pairing.commitment(KEY_A, NONCE_I)));
        try (SecretBytes key = Pairing.sasKey(KEY_A, KEY_B, NONCE_I, NONCE_R)) {
            assertEquals("8277bc85e0821ae5020b5d63c526631b0c10bd49124cf5c2ccb219f8453c4ee8",
                    HEX.formatHex(TestBytes.copyOut(key)));
            assertEquals("494949", Pairing.sas(key));
            assertEquals("7c2491511314496a932797480d24e9965c86b6f9f284cf8560736222adcf47cb",
                    HEX.formatHex(Pairing.confirmation(key, KEY_A)));
        }
    }

    @Test
    void bothSidesDeriveTheSameKeyWhicheverKeyTheyCallTheirOwn() throws CryptoException {
        try (SecretBytes initiator = Pairing.sasKey(KEY_A, KEY_B, NONCE_I, NONCE_R);
                SecretBytes responder = Pairing.sasKey(KEY_B, KEY_A, NONCE_I, NONCE_R)) {
            assertArrayEquals(TestBytes.copyOut(initiator), TestBytes.copyOut(responder));
            assertEquals(Pairing.sas(initiator), Pairing.sas(responder));
        }
    }

    @Property(tries = 50)
    void sasIsDeterministicAndOrderIndependent(@ForAll @Size(32) byte[] a, @ForAll @Size(32) byte[] b,
            @ForAll @Size(32) byte[] nI, @ForAll @Size(32) byte[] nR) throws CryptoException {
        try (SecretBytes one = Pairing.sasKey(a, b, nI, nR); SecretBytes two = Pairing.sasKey(b, a, nI, nR)) {
            String sas = Pairing.sas(one);
            assertEquals(sas, Pairing.sas(two));
            assertEquals(Pairing.SAS_DIGITS, sas.length());
            assertTrue(sas.chars().allMatch(Character::isDigit));
        }
    }

    @Test
    void theKeyBindsBothPublicKeysAndTheNonceRoles() throws CryptoException {
        byte[] mallory = range(64, 96);
        try (SecretBytes honest = Pairing.sasKey(KEY_A, KEY_B, NONCE_I, NONCE_R);
                SecretBytes substituted = Pairing.sasKey(KEY_A, mallory, NONCE_I, NONCE_R);
                SecretBytes swappedNonces = Pairing.sasKey(KEY_A, KEY_B, NONCE_R, NONCE_I)) {
            assertNotEquals(HEX.formatHex(TestBytes.copyOut(honest)), HEX.formatHex(TestBytes.copyOut(substituted)));
            assertNotEquals(HEX.formatHex(TestBytes.copyOut(honest)), HEX.formatHex(TestBytes.copyOut(swappedNonces)));
        }
    }

    @Test
    void sasReadsEightBytesUnsignedAndZeroPads() {
        byte[] high = new byte[32];
        Arrays.fill(high, (byte) 0xff);
        try (SecretBytes ones = SecretBytes.copyOf(high); SecretBytes zeros = SecretBytes.copyOf(new byte[32])) {
            assertEquals("551615", Pairing.sas(ones)); // 2^64 - 1 mod 10^6, not a negative remainder
            assertEquals("000000", Pairing.sas(zeros));
        }
    }

    @Test
    void aCommitmentOpensOnlyWithItsKeyAndNonce() {
        byte[] nonce = Pairing.nonce();
        assertEquals(Pairing.NONCE_BYTES, nonce.length);
        byte[] c = Pairing.commitment(KEY_A, nonce);
        assertTrue(Pairing.opens(c, KEY_A, nonce));
        assertFalse(Pairing.opens(c, KEY_B, nonce)); // reflected to the other side
        assertFalse(Pairing.opens(c, KEY_A, Pairing.nonce()));
    }

    @Test
    void aConfirmationVerifiesOnlyAsTheSenderAndOnlyUnderTheSameKey() throws CryptoException {
        try (SecretBytes key = Pairing.sasKey(KEY_A, KEY_B, NONCE_I, NONCE_R);
                SecretBytes other = Pairing.sasKey(KEY_A, KEY_B, NONCE_R, NONCE_I)) {
            byte[] fromA = Pairing.confirmation(key, KEY_A);
            assertTrue(Pairing.confirms(key, KEY_A, fromA));
            assertFalse(Pairing.confirms(key, KEY_B, fromA)); // A's MAC reflected back to A as B's
            assertFalse(Pairing.confirms(other, KEY_A, fromA));
        }
    }

    @Test
    void wrongLengthsAreRefused() {
        byte[] shortKey = new byte[31];
        byte[] shortNonce = new byte[31];
        assertThrows(IllegalArgumentException.class, () -> Pairing.commitment(shortKey, NONCE_I));
        assertThrows(IllegalArgumentException.class, () -> Pairing.commitment(KEY_A, shortNonce));
        assertThrows(IllegalArgumentException.class, () -> Pairing.sasKey(KEY_A, shortKey, NONCE_I, NONCE_R));
        assertThrows(IllegalArgumentException.class, () -> Pairing.sasKey(shortKey, KEY_B, NONCE_I, NONCE_R));
        assertThrows(IllegalArgumentException.class, () -> Pairing.sasKey(KEY_A, KEY_B, shortNonce, NONCE_R));
        assertThrows(IllegalArgumentException.class, () -> Pairing.sasKey(KEY_A, KEY_B, NONCE_I, shortNonce));
    }
}
