package pm.crypto.passkey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pm.crypto.passkey.Vectors.assertBadInput;
import static pm.crypto.passkey.Vectors.hex;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import org.junit.jupiter.api.Test;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;

/** P-256 passkey keys: generation, strict storage form, ES256 signing (ADR 0016, SR-080 to SR-082). */
class PasskeyKeyTest {
    private static final byte[] AUTH_DATA = new byte[37];
    private static final byte[] CLIENT_DATA_HASH = new byte[32];

    static {
        Arrays.fill(AUTH_DATA, (byte) 0x49);
        AUTH_DATA[32] = 0x05; // UP | UV
        Arrays.fill(CLIENT_DATA_HASH, (byte) 0x7a);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    @Test
    void rfc6979VectorsAreReproducedExactly() throws CryptoException {
        // RFC 6979 Appendix A.2.5, P-256 with SHA-256: deterministic nonces give exact signatures.
        try (SecretBytes stored = Vectors.rfcStorage(); PasskeyKey key = PasskeyKey.fromStorage(stored)) {
            assertArrayEquals(Vectors.rfcPoint(), key.publicPoint());
            BigIntegerPair sample = BigIntegerPair.of(key.signMessage("sample".getBytes(StandardCharsets.US_ASCII)));
            assertEquals("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716", sample.r());
            assertEquals("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8", sample.s());
            BigIntegerPair test = BigIntegerPair.of(key.signMessage("test".getBytes(StandardCharsets.US_ASCII)));
            assertEquals("f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367", test.r());
            assertEquals("019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083", test.s());
        }
    }

    /** The r and s of a DER signature as 64-digit lowercase hex. */
    private record BigIntegerPair(String r, String s) {
        static BigIntegerPair of(byte[] der) {
            java.math.BigInteger[] rs = Es256.decodeDer(der);
            assertEquals(2, rs.length, "canonical DER");
            return new BigIntegerPair(String.format("%064x", rs[0]), String.format("%064x", rs[1]));
        }
    }

    @Test
    void assertionSignatureIsDerOverAuthenticatorDataAndClientDataHash() throws CryptoException,
            GeneralSecurityException {
        try (PasskeyKey key = PasskeyKey.generate()) {
            byte[] sig = key.sign(AUTH_DATA, CLIENT_DATA_HASH);
            assertEquals(0x30, sig[0] & 0xff);
            assertTrue(sig.length <= Es256.MAX_SIGNATURE_BYTES);
            byte[] signed = concat(AUTH_DATA, CLIENT_DATA_HASH);
            // Independent check 1: the JDK's SunEC verifier over the raw concatenation.
            assertTrue(Vectors.jcaVerify(key.publicPoint(), signed, sig));
            // Independent check 2: decode the COSE key and verify through it.
            assertTrue(Es256.verify(key.cosePublicKey(), AUTH_DATA, CLIENT_DATA_HASH, sig));
            assertArrayEquals(key.publicPoint(), CoseKey.decodeEc2(key.cosePublicKey()));
            // Deterministic: the same input signs to the same bytes.
            assertArrayEquals(sig, key.sign(AUTH_DATA, CLIENT_DATA_HASH));
            byte[] other = AUTH_DATA.clone();
            other[33] ^= 1;
            assertFalse(Vectors.jcaVerify(key.publicPoint(), concat(other, CLIENT_DATA_HASH), sig));
        }
    }

    @Test
    void signingInputsAreLengthChecked() throws CryptoException {
        try (PasskeyKey key = PasskeyKey.generate()) {
            assertBadInput(() -> key.sign(new byte[36], CLIENT_DATA_HASH));
            assertBadInput(() -> key.sign(new byte[Es256.MAX_AUTHENTICATOR_DATA_BYTES + 1], CLIENT_DATA_HASH));
            assertBadInput(() -> key.sign(AUTH_DATA, new byte[31]));
            assertBadInput(() -> key.sign(AUTH_DATA, new byte[33]));
            assertTrue(Es256.verify(key.cosePublicKey(), new byte[Es256.MAX_AUTHENTICATOR_DATA_BYTES],
                    CLIENT_DATA_HASH, key.sign(new byte[Es256.MAX_AUTHENTICATOR_DATA_BYTES], CLIENT_DATA_HASH)));
        }
    }

    @Test
    void generationRejectsOutOfRangeCandidates() throws CryptoException {
        byte[] zero = new byte[32];
        byte[] order = hex(Vectors.ORDER);
        byte[] ones = new byte[32];
        Arrays.fill(ones, (byte) 0xff);
        byte[] good = hex(Vectors.RFC_X);
        Deque<byte[]> draws = new ArrayDeque<>(List.of(zero.clone(), order.clone(), ones.clone(), good.clone()));
        List<byte[]> handedOut = new java.util.ArrayList<>();
        try (PasskeyKey key = PasskeyKey.generate(n -> {
            assertEquals(32, n);
            byte[] d = draws.removeFirst();
            handedOut.add(d);
            return d;
        })) {
            assertTrue(draws.isEmpty());
            assertArrayEquals(Vectors.rfcPoint(), key.publicPoint());
        }
        for (byte[] d : handedOut) {
            assertArrayEquals(new byte[32], d, "every candidate is zero-filled");
        }
    }

    @Test
    void generatedKeysAreDistinctAndRoundTripThroughStorage() throws CryptoException {
        try (PasskeyKey a = PasskeyKey.generate(); PasskeyKey b = PasskeyKey.generate();
                SecretBytes stored = a.toStorage(); PasskeyKey back = PasskeyKey.fromStorage(stored)) {
            assertFalse(ConstantTime.equals(a.publicPoint(), b.publicPoint()));
            assertEquals(PasskeyKey.STORAGE_BYTES, stored.length());
            assertArrayEquals(a.publicPoint(), back.publicPoint());
            assertArrayEquals(a.cosePublicKey(), back.cosePublicKey());
            assertArrayEquals(a.sign(AUTH_DATA, CLIENT_DATA_HASH), back.sign(AUTH_DATA, CLIENT_DATA_HASH));
            assertFalse(stored.isClosed(), "the caller keeps ownership of the stored form");
        }
    }

    @Test
    void storageFormIsVersionScalarAndPoint() throws CryptoException {
        try (SecretBytes stored = Vectors.rfcStorage(); PasskeyKey key = PasskeyKey.fromStorage(stored);
                SecretBytes again = key.toStorage()) {
            assertEquals(98, PasskeyKey.STORAGE_BYTES);
            assertEquals(PasskeyKey.STORAGE_BYTES, pm.crypto.passkey.storage.PasskeyStorage.STORAGE_BYTES);
            assertEquals(stored, again);
        }
    }

    @Test
    void invalidStorageFormsAreRefused() {
        String point = "04" + Vectors.RFC_UX + Vectors.RFC_UY;
        // Wrong lengths and version.
        assertBadStorage(new byte[0]);
        assertBadStorage(hex("01" + Vectors.RFC_X + point + "00"));
        assertBadStorage(hex("01" + Vectors.RFC_X + point.substring(2)));
        assertBadStorage(hex("02" + Vectors.RFC_X + point));
        assertBadStorage(hex("00" + Vectors.RFC_X + point));
        // Scalar 0, n, n + 1 and 2^256 - 1.
        assertBadStorage(hex("01" + "00".repeat(32) + point));
        assertBadStorage(hex("01" + Vectors.ORDER + point));
        assertBadStorage(hex("01" + new java.math.BigInteger(Vectors.ORDER, 16).add(java.math.BigInteger.ONE)
                .toString(16) + point));
        assertBadStorage(hex("01" + "ff".repeat(32) + point));
        // Compressed prefix, off-curve point, coordinate not below p.
        assertBadStorage(hex("01" + Vectors.RFC_X + "02" + Vectors.RFC_UX + Vectors.RFC_UY));
        String offCurveY = Vectors.RFC_UY.substring(0, 63) + "8";
        assertBadStorage(hex("01" + Vectors.RFC_X + "04" + Vectors.RFC_UX + offCurveY));
        assertBadStorage(hex("01" + Vectors.RFC_X + "04" + Vectors.PRIME + Vectors.RFC_UY));
        // A valid point that is not d·G (the generator G itself).
        String g = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        assertBadStorage(hex("01" + Vectors.RFC_X + g));
    }

    private static void assertBadStorage(byte[] form) {
        try (SecretBytes stored = SecretBytes.takeOwnership(form)) {
            assertBadInput(() -> PasskeyKey.fromStorage(stored));
            assertFalse(stored.isClosed());
        }
    }

    @Test
    void secretsAreZeroedOnClose() throws CryptoException {
        byte[][] internal = new byte[1][];
        PasskeyKey[] held = new PasskeyKey[1];
        try (PasskeyKey key = PasskeyKey.generate()) {
            held[0] = key;
            try (SecretBytes stored = key.toStorage()) {
                stored.withBytes(b -> internal[0] = b);
                assertEquals(PasskeyKey.STORAGE_VERSION, internal[0][0]);
            }
            assertArrayEquals(new byte[PasskeyKey.STORAGE_BYTES], internal[0], "storage form zeroed on close");
            assertFalse(key.isClosed());
        }
        assertTrue(held[0].isClosed());
        held[0].close();
        assertTrue(held[0].isClosed(), "close is idempotent");
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> held[0].sign(AUTH_DATA, CLIENT_DATA_HASH));
        assertEquals("SECRET_CLOSED", e.getMessage());
        assertThrows(IllegalStateException.class, held[0]::toStorage);
        assertEquals(65, held[0].publicPoint().length, "the public half stays usable");
    }

    @Test
    void toStringNeverShowsKeyMaterial() throws CryptoException {
        try (SecretBytes stored = Vectors.rfcStorage(); PasskeyKey key = PasskeyKey.fromStorage(stored)) {
            String s = key.toString();
            assertEquals("PasskeyKey[ES256 P-256]", s);
            assertFalse(s.contains(Vectors.RFC_X.substring(0, 8)));
            assertFalse(s.contains(Vectors.HEX_FORMAT.formatHex(key.publicPoint()).substring(2, 10)));
        }
    }

    @Test
    void credentialIdsAreRandom32Bytes() {
        byte[] a = PasskeyKey.newCredentialId();
        byte[] b = PasskeyKey.newCredentialId();
        assertEquals(PasskeyKey.CREDENTIAL_ID_BYTES, a.length);
        assertEquals(32, b.length);
        assertFalse(ConstantTime.equals(a, b));
    }
}
