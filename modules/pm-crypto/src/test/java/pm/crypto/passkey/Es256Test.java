package pm.crypto.passkey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pm.crypto.passkey.Vectors.assertBadInput;
import static pm.crypto.passkey.Vectors.hex;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;

/** ES256 DER signatures and the verify helper (ADR 0016, SR-082). */
class Es256Test {
    private static final byte[] AUTH_DATA = new byte[40];
    private static final byte[] CLIENT_DATA_HASH = new byte[32];

    static {
        Arrays.fill(AUTH_DATA, (byte) 0x11);
        Arrays.fill(CLIENT_DATA_HASH, (byte) 0x22);
    }

    private static byte[] cose() throws CryptoException {
        return CoseKey.encodeEc2(Vectors.rfcPoint());
    }

    private static byte[] rfcSignature() throws CryptoException {
        try (SecretBytes stored = Vectors.rfcStorage(); PasskeyKey key = PasskeyKey.fromStorage(stored)) {
            return key.sign(AUTH_DATA, CLIENT_DATA_HASH);
        }
    }

    private static boolean verifies(byte[] sig) throws CryptoException {
        return Es256.verify(cose(), AUTH_DATA, CLIENT_DATA_HASH, sig);
    }

    @Test
    void verifiesItsOwnAndJdkSignatures() throws CryptoException, GeneralSecurityException {
        assertTrue(verifies(rfcSignature()));
        // A signature from the JDK's own ECDSA (randomized nonce) verifies too.
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "SunEC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = g.generateKeyPair();
        Signature s = Signature.getInstance("SHA256withECDSA", "SunEC");
        s.initSign(pair.getPrivate());
        s.update(Es256.signedData(AUTH_DATA, CLIENT_DATA_HASH));
        byte[] jdkSig = s.sign();
        ECPublicKey pub = (ECPublicKey) pair.getPublic();
        byte[] point = new byte[65];
        point[0] = 4;
        put(point, 1, pub.getW().getAffineX());
        put(point, 33, pub.getW().getAffineY());
        assertTrue(Es256.verify(CoseKey.encodeEc2(point), AUTH_DATA, CLIENT_DATA_HASH, jdkSig));
        assertFalse(Es256.verify(cose(), AUTH_DATA, CLIENT_DATA_HASH, jdkSig), "other key");
    }

    private static void put(byte[] out, int at, BigInteger v) {
        byte[] b = v.toByteArray();
        int n = Math.min(b.length, 32);
        System.arraycopy(b, b.length - n, out, at + 32 - n, n);
    }

    @Test
    void wrongMessageDoesNotVerify() throws CryptoException {
        byte[] sig = rfcSignature();
        byte[] hash = CLIENT_DATA_HASH.clone();
        hash[0] ^= 1;
        assertFalse(Es256.verify(cose(), AUTH_DATA, hash, sig));
        byte[] auth = AUTH_DATA.clone();
        auth[39] ^= 1;
        assertFalse(Es256.verify(cose(), auth, CLIENT_DATA_HASH, sig));
    }

    @Test
    void derEncodingIsCanonical() {
        assertArrayEquals(hex("3006020101020102"), Es256.encodeDer(BigInteger.ONE, BigInteger.TWO));
        // A high bit gets a leading zero; a 256-bit value is 33 bytes then.
        BigInteger big = BigInteger.ONE.shiftLeft(255);
        byte[] der = Es256.encodeDer(big, big);
        assertEquals(Es256.MAX_SIGNATURE_BYTES, der.length);
        assertArrayEquals(hex("30460221" + "0080" + "00".repeat(31)), Arrays.copyOf(der, 37));
        BigInteger[] rs = Es256.decodeDer(der);
        assertEquals(big, rs[0]);
        assertEquals(big, rs[1]);
    }

    @Test
    void malformedSignaturesAreInvalidNotErrors() throws CryptoException {
        byte[] good = rfcSignature();
        assertTrue(verifies(good));
        String[] bad = {
            "",
            "30050201010201", // shorter than 8 bytes
            "30" + "4a" + "0223" + "01".repeat(35) + "0223" + "01".repeat(35), // longer than 72
            "3106020101020101", // not a SEQUENCE
            "3007020101020101", // SEQUENCE length does not match
            "3006030101020101", // r is not an INTEGER
            "3006020101030101", // s is not an INTEGER
            "3006020401010101", // r consumes the whole SEQUENCE, no s header
            "3006020001020101", // zero-length r
            "3006027f01020101", // r runs past the end
            "30080201010201010000", // wrong overall length vs content: trailing bytes after s
            "3009020101020101020101", // three INTEGERs
            "300702020001020101", // non-minimal r (leading 00 before a byte < 0x80)
            "3006020181020101", // negative r
            "3006020100020101", // r = 0
            "3006020101020100", // s = 0
        };
        for (String h : bad) {
            assertFalse(verifies(hex(h)), h);
        }
        byte[] trailing = Arrays.copyOf(good, good.length + 1);
        assertFalse(verifies(trailing));
        // r = n is out of range even though it is canonical DER.
        BigInteger n = new BigInteger(Vectors.ORDER, 16);
        assertFalse(verifies(Es256.encodeDer(n, BigInteger.ONE)));
        assertFalse(verifies(Es256.encodeDer(BigInteger.ONE, n)));
        // s and n - s are both valid ECDSA signatures; ES256 does not require low S.
        BigInteger[] rs = Es256.decodeDer(good);
        assertTrue(verifies(Es256.encodeDer(rs[0], n.subtract(rs[1]))));
    }

    @Test
    void verifyRefusesMalformedKeysAndInputs() throws CryptoException {
        byte[] sig = rfcSignature();
        assertBadInput(() -> Es256.verify(new byte[77], AUTH_DATA, CLIENT_DATA_HASH, sig));
        assertBadInput(() -> Es256.verify(cose(), new byte[36], CLIENT_DATA_HASH, sig));
        assertBadInput(() -> Es256.verify(cose(), AUTH_DATA, new byte[32 + 1], sig));
    }

    @Test
    void signedDataIsTheConcatenation() throws CryptoException {
        byte[] d = Es256.signedData(AUTH_DATA, CLIENT_DATA_HASH);
        assertEquals(72, d.length);
        assertArrayEquals(AUTH_DATA, Arrays.copyOf(d, 40));
        assertArrayEquals(CLIENT_DATA_HASH, Arrays.copyOfRange(d, 40, 72));
        assertEquals(-7, Es256.COSE_ALG);
    }
}
