package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** Device identity, certificate shape and restore (docs/protocols/lan-share.md §1). */
class DeviceIdentityTest {
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");

    @Test
    void identityMatchesTheProtocolDocument() throws CryptoException {
        try (DeviceIdentity id = DeviceIdentity.generate(NOW)) {
            byte[] pk = id.publicKey();
            assertEquals(DeviceIdentity.PUBLIC_KEY_BYTES, pk.length);
            assertArrayEquals(Arrays.copyOf(Hash.sha256(pk), 16), id.deviceId());
            X509Certificate cert = id.x509();
            assertEquals("CN=" + DeviceIdentity.base32(id.deviceId()), cert.getSubjectX500Principal().getName());
            assertEquals(cert.getSubjectX500Principal(), cert.getIssuerX500Principal());
            assertEquals(NOW.minus(DeviceIdentity.CLOCK_SKEW), cert.getNotBefore().toInstant());
            assertEquals(NOW.plus(DeviceIdentity.VALIDITY), cert.getNotAfter().toInstant());
            assertEquals(DeviceIdentity.ED25519_OID.getId(), cert.getSigAlgOID());
            assertEquals("Ed25519", cert.getSigAlgName());
            assertEquals(-1, cert.getBasicConstraints());
            assertTrue(cert.getKeyUsage()[0]);
            assertEquals(3, cert.getVersion());
            assertArrayEquals(pk, DeviceIdentity.rawPublicKey(cert.getPublicKey()));
            assertTrue(id.toString().contains(DeviceIdentity.fingerprint(pk)));
        }
    }

    @Test
    void fingerprintIsEightGroupsOfFourHex() {
        byte[] pk = new byte[32];
        String hex = HexFormat.of().formatHex(Hash.sha256(pk));
        String fp = DeviceIdentity.fingerprint(pk);
        assertTrue(fp.matches("([0-9a-f]{4} ){7}[0-9a-f]{4}"), fp);
        assertEquals(hex.substring(0, 32), fp.replace(" ", ""));
    }

    @Test
    void base32MatchesRfc4648LowercaseUnpadded() {
        String[][] vectors = {{"", ""}, {"f", "my"}, {"fo", "mzxq"}, {"foo", "mzxw6"}, {"foob", "mzxw6yq"},
            {"fooba", "mzxw6ytb"}, {"foobar", "mzxw6ytboi"}};
        for (String[] v : vectors) {
            assertEquals(v[1], DeviceIdentity.base32(v[0].getBytes(StandardCharsets.US_ASCII)));
        }
    }

    @Test
    void signaturesVerifyOnlyForTheSignedMessageAndKey() throws CryptoException {
        byte[] msg = {1, 2, 3};
        try (DeviceIdentity id = DeviceIdentity.generate(NOW); DeviceIdentity other = DeviceIdentity.generate(NOW)) {
            byte[] sig = id.sign(msg);
            assertEquals(DeviceIdentity.SIGNATURE_BYTES, sig.length);
            assertTrue(DeviceIdentity.verify(id.publicKey(), msg, sig));
            assertFalse(DeviceIdentity.verify(other.publicKey(), msg, sig));
            assertFalse(DeviceIdentity.verify(id.publicKey(), new byte[] {1, 2, 4}, sig));
            assertFalse(DeviceIdentity.verify(id.publicKey(), msg, Arrays.copyOf(sig, 10)));
            assertFalse(DeviceIdentity.verify(new byte[31], msg, sig));
        }
    }

    @Test
    void restoreRoundTripsAndKeepsTheCallersBuffer() throws CryptoException {
        try (DeviceIdentity id = DeviceIdentity.generate(NOW); SecretBytes stored = id.privateKeyPkcs8()) {
            try (DeviceIdentity back = DeviceIdentity.restore(stored, id.certificate())) {
                assertArrayEquals(id.publicKey(), back.publicKey());
                assertArrayEquals(id.certificate(), back.certificate());
                assertTrue(DeviceIdentity.verify(id.publicKey(), new byte[1], back.sign(new byte[1])));
            }
            assertFalse(stored.isClosed());
        }
    }

    @Test
    void restoreRefusesMismatchedOrMalformedParts() throws CryptoException {
        try (DeviceIdentity a = DeviceIdentity.generate(NOW); DeviceIdentity b = DeviceIdentity.generate(NOW);
                SecretBytes keyA = a.privateKeyPkcs8(); SecretBytes junk = SecretBytes.copyOf(new byte[48])) {
            byte[] tampered = a.certificate();
            tampered[tampered.length - 1] ^= 1; // inside the signature
            assertBadInput(() -> DeviceIdentity.restore(keyA, b.certificate()));
            assertBadInput(() -> DeviceIdentity.restore(junk, a.certificate()));
            assertBadInput(() -> DeviceIdentity.restore(keyA, new byte[] {0x30, 0}));
            assertBadInput(() -> DeviceIdentity.restore(keyA, tampered));
        }
    }

    @Test
    void rawPublicKeyAcceptsOnlyEd25519() throws GeneralSecurityException {
        PublicKey ec = KeyPairGenerator.getInstance("EC").generateKeyPair().getPublic();
        assertBadInput(() -> DeviceIdentity.rawPublicKey(ec));
        assertBadInput(() -> DeviceIdentity.rawPublicKey(fixedKey(null)));
        assertBadInput(() -> DeviceIdentity.rawPublicKey(fixedKey(new byte[44]))); // right length, wrong prefix
    }

    @Test
    void closedIdentityRefusesToSignOrExport() throws CryptoException {
        try (DeviceIdentity id = closedIdentity()) { // closing again on exit must be a no-op
            assertThrows(IllegalStateException.class, () -> id.sign(new byte[1]));
            assertThrows(IllegalStateException.class, id::privateKeyPkcs8);
            assertEquals(32, id.publicKey().length);
        }
    }

    private static DeviceIdentity closedIdentity() throws CryptoException {
        try (DeviceIdentity id = DeviceIdentity.generate(NOW)) {
            return id;
        }
    }

    private static PublicKey fixedKey(byte[] encoded) {
        return new PublicKey() {
            private static final long serialVersionUID = 1L;

            @Override
            public String getAlgorithm() {
                return "Ed25519";
            }

            @Override
            public String getFormat() {
                return "X.509";
            }

            @Override
            public byte[] getEncoded() {
                return encoded == null ? null : encoded.clone();
            }
        };
    }

    interface Call {
        void run() throws CryptoException;
    }

    static void assertBadInput(Call call) {
        CryptoException e = assertThrows(CryptoException.class, call::run);
        assertEquals(CryptoException.Code.BAD_INPUT, e.code());
    }
}
