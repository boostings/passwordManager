package pm.browser.webauthn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.browser.bridge.Origin;
import pm.browser.host.HostException;
import pm.crypto.CryptoException;
import pm.crypto.Hash;
import pm.crypto.passkey.CoseKey;
import pm.crypto.passkey.Es256;

/**
 * Authenticator data, the {@code none} attestation object and client data against the WebAuthn
 * Level 3 §16 test vectors (SR-117, SR-118). §16.2 (ES256, no attestation) uses exactly the flags
 * pm sets (0x59 on create, 0x19 on get), so pm's builders must reproduce its bytes exactly. Our
 * outputs are also read back with an independent CBOR decoder ({@link TestCbor}).
 */
@Tag("T-PK-04")
final class WebAuthnVectorsTest {
    private static final int RP_ID_HASH_BYTES = 32;

    private static Origin origin() throws HostException {
        return Origin.parse(Vectors.ORIGIN);
    }

    /** The authData of a vector's attestation object, read with the independent decoder. */
    private static byte[] registrationAuthData(String section) {
        Map<?, ?> attestation = assertInstanceOf(Map.class,
                TestCbor.decode(Vectors.get(section + ".create.attestationObject")));
        return assertInstanceOf(byte[].class, attestation.get("authData"));
    }

    /** §16.2: the registration authenticator data and attestation object, byte for byte. */
    @Test
    void section16_2RegistrationIsReproducedExactly() {
        byte[] expected = Vectors.get("16.2.create.attestationObject");
        byte[] vectorAuthData = registrationAuthData("16.2");
        AuthenticatorData parsed = AuthenticatorData.parse(vectorAuthData);
        assertEquals(AuthenticatorData.REGISTRATION_FLAGS, parsed.flags());
        assertEquals(0, parsed.signCount());
        assertTrue(parsed.isFor(Vectors.RP_ID));
        assertArrayEquals(Vectors.get("16.2.create.aaguid"), parsed.aaguid());
        assertArrayEquals(Vectors.get("16.2.create.credential_id"), parsed.credentialId());

        byte[] built = AuthenticatorData.registration(Vectors.RP_ID, 0, Vectors.get("16.2.create.aaguid"),
                Vectors.get("16.2.create.credential_id"), parsed.cosePublicKey());
        assertArrayEquals(vectorAuthData, built);
        assertArrayEquals(expected, AttestationObject.none(built));
    }

    /** §16.2: the assertion authenticator data byte for byte, and its signature verifies. */
    @Test
    void section16_2AssertionIsReproducedAndVerifies() throws CryptoException {
        byte[] authData = Vectors.get("16.2.get.authenticatorData");
        assertArrayEquals(authData, AuthenticatorData.assertion(Vectors.RP_ID, 0));
        AuthenticatorData parsed = AuthenticatorData.parse(authData);
        assertEquals(AuthenticatorData.ASSERTION_FLAGS, parsed.flags());
        assertFalse(parsed.hasAttestedCredential());
        byte[] cose = AuthenticatorData.parse(registrationAuthData("16.2")).cosePublicKey();
        assertTrue(Es256.verify(cose, authData, Hash.sha256(Vectors.get("16.2.get.clientDataJSON")),
                Vectors.get("16.2.get.signature")));
    }

    /** §16.2, §16.4, §16.5, §16.6: every get signature verifies against its registered key. */
    @Test
    void everyVectorAssertionVerifiesWithItsParsedKey() throws CryptoException {
        for (String section : List.of("16.2", "16.4", "16.5", "16.6")) {
            AuthenticatorData registration = AuthenticatorData.parse(registrationAuthData(section));
            assertTrue(registration.isFor(Vectors.RP_ID), section);
            assertArrayEquals(Vectors.get(section + ".create.credential_id"), registration.credentialId(), section);
            byte[] authData = Vectors.get(section + ".get.authenticatorData");
            AuthenticatorData assertion = AuthenticatorData.parse(authData);
            assertTrue((assertion.flags() & AuthenticatorData.FLAG_UP) != 0, section);
            assertTrue(Es256.verify(registration.cosePublicKey(), authData,
                    Hash.sha256(Vectors.get(section + ".get.clientDataJSON")),
                    Vectors.get(section + ".get.signature")), section);
        }
    }

    /** §16.6: the parser takes the longest credential ID (1023 bytes). */
    @Test
    void section16_6LongestCredentialIdParses() {
        AuthenticatorData parsed = AuthenticatorData.parse(registrationAuthData("16.6"));
        assertEquals(AuthenticatorData.MAX_CREDENTIAL_ID_BYTES, parsed.credentialId().length);
        byte[] rebuilt = AuthenticatorData.registration(Vectors.RP_ID, 0, parsed.aaguid(), parsed.credentialId(),
                parsed.cosePublicKey());
        // Same bytes apart from the flags: the vector sets UP|BE|AT (0x49), pm sets UP|BE|BS|AT.
        byte[] vector = registrationAuthData("16.6");
        vector[32] = (byte) AuthenticatorData.REGISTRATION_FLAGS;
        assertArrayEquals(vector, rebuilt);
    }

    /** §16.2 and §16.6 client data pass; §16.4 (crossOrigin true) and §16.5 (topOrigin) do not. */
    @Test
    void clientDataOfTheVectorsIsCheckedAndHashed() throws HostException {
        for (String section : List.of("16.2", "16.6")) {
            byte[] create = Vectors.get(section + ".create.clientDataJSON");
            assertArrayEquals(Hash.sha256(create), ClientData.hash(create, ClientData.CREATE, origin()));
            byte[] get = Vectors.get(section + ".get.clientDataJSON");
            assertArrayEquals(Hash.sha256(get), ClientData.hash(get, ClientData.GET, origin()));
            // The type is part of the check.
            assertBad(get, ClientData.CREATE, origin());
        }
        for (String section : List.of("16.4", "16.5")) {
            assertBad(Vectors.get(section + ".create.clientDataJSON"), ClientData.CREATE, origin());
            assertBad(Vectors.get(section + ".get.clientDataJSON"), ClientData.GET, origin());
        }
        // Another origin, even a same-site one, is refused.
        assertBad(Vectors.get("16.2.get.clientDataJSON"), ClientData.GET, Origin.parse("https://www.example.org"));
        assertBad(Vectors.get("16.2.get.clientDataJSON"), ClientData.GET, Origin.parse("https://example.org:8443"));
    }

    @Test
    void clientDataMustBeOneBoundedObjectWithTheRequiredMembers() throws HostException {
        Origin o = origin();
        String ok = "{\"type\":\"webauthn.get\",\"challenge\":\"AA\",\"origin\":\"https://example.org\"}";
        assertEquals(RP_ID_HASH_BYTES, ClientData.hash(utf8(ok), ClientData.GET, o).length);
        assertEquals(RP_ID_HASH_BYTES, ClientData.hash(utf8(ok.replace("}", ",\"crossOrigin\":false}")),
                ClientData.GET, o).length);
        for (String bad : List.of(
                "[]", "{", "\"x\"",
                "{\"challenge\":\"AA\",\"origin\":\"https://example.org\"}",
                "{\"type\":1,\"challenge\":\"AA\",\"origin\":\"https://example.org\"}",
                "{\"type\":\"webauthn.get\",\"origin\":\"https://example.org\"}",
                "{\"type\":\"webauthn.get\",\"challenge\":1,\"origin\":\"https://example.org\"}",
                "{\"type\":\"webauthn.get\",\"challenge\":\"\",\"origin\":\"https://example.org\"}",
                "{\"type\":\"webauthn.get\",\"challenge\":\"AA\"}",
                "{\"type\":\"webauthn.get\",\"challenge\":\"AA\",\"origin\":1}",
                "{\"type\":\"webauthn.get\",\"challenge\":\"AA\",\"origin\":\"https://EXAMPLE.org\"}",
                "{\"type\":\"webauthn.get\",\"challenge\":\"AA\",\"origin\":\"https://example.org:443\"}",
                ok.replace("}", ",\"crossOrigin\":true}"),
                ok.replace("}", ",\"crossOrigin\":\"false\"}"),
                ok.replace("}", ",\"topOrigin\":\"https://example.org\"}"),
                ok.replace("}", ",\"type\":\"webauthn.get\"}"))) {
            assertBad(utf8(bad), ClientData.GET, o);
        }
        assertBad(new byte[0], ClientData.GET, o);
        assertBad(new byte[] {(byte) 0xC0, (byte) 0x80}, ClientData.GET, o);
        byte[] big = utf8(ok.replace("\"AA\"", "\"" + "A".repeat(ClientData.MAX_BYTES) + "\""));
        assertBad(big, ClientData.GET, o);
    }

    /** Our own outputs, read back with the independent decoder. */
    @Test
    void ourAttestationObjectDecodesIndependently() {
        byte[] credentialId = new byte[32];
        Arrays.fill(credentialId, (byte) 7);
        byte[] cose = AuthenticatorData.parse(registrationAuthData("16.2")).cosePublicKey();
        byte[] authData = AuthenticatorData.registration("login.example.com", credentialId, cose);
        Map<?, ?> decoded = assertInstanceOf(Map.class, TestCbor.decode(AttestationObject.none(authData)));
        assertEquals(List.of("fmt", "attStmt", "authData"), List.copyOf(decoded.keySet()));
        assertEquals("none", decoded.get("fmt"));
        assertEquals(Map.of(), decoded.get("attStmt"));
        byte[] inner = assertInstanceOf(byte[].class, decoded.get("authData"));
        assertArrayEquals(authData, inner);

        // Field by field, without the production parser.
        assertArrayEquals(Hash.sha256("login.example.com".getBytes(StandardCharsets.US_ASCII)),
                Arrays.copyOfRange(inner, 0, 32));
        assertEquals(0x59, inner[32] & 0xFF);
        assertArrayEquals(new byte[4], Arrays.copyOfRange(inner, 33, 37));
        assertArrayEquals(new byte[16], Arrays.copyOfRange(inner, 37, 53));
        assertEquals(32, ((inner[53] & 0xFF) << 8) | (inner[54] & 0xFF));
        assertArrayEquals(credentialId, Arrays.copyOfRange(inner, 55, 87));
        Map<?, ?> key = assertInstanceOf(Map.class, TestCbor.decode(Arrays.copyOfRange(inner, 87, inner.length)));
        assertEquals(List.of(1L, 3L, -1L, -2L, -3L), List.copyOf(key.keySet()));
        assertEquals(2L, key.get(1L));
        assertEquals(-7L, key.get(3L));
        assertEquals(1L, key.get(-1L));
        assertEquals(CoseKey.EC2_BYTES, inner.length - 87);
    }

    /** Assertion data for counters, read back without the production parser: big-endian u32. */
    @Test
    void assertionCountersAreBigEndianU32() {
        for (long count : new long[] {0, 1, 0x0102_0304L, 0xFFFF_FFFFL}) {
            byte[] data = AuthenticatorData.assertion("example.com", count);
            assertEquals(AuthenticatorData.HEADER_BYTES, data.length);
            assertEquals(HexFormat.of().toHexDigits((int) count), HexFormat.of().formatHex(data, 33, 37));
            assertEquals(count, AuthenticatorData.parse(data).signCount());
        }
        assertThrows(IllegalArgumentException.class, () -> AuthenticatorData.assertion("example.com", -1));
        assertThrows(IllegalArgumentException.class, () -> AuthenticatorData.assertion("example.com", 1L << 32));
    }

    private static void assertBad(byte[] json, String type, Origin origin) {
        HostException e = assertThrows(HostException.class, () -> ClientData.hash(json, type, origin));
        assertEquals(HostException.Code.BAD_CLIENT_DATA, e.code());
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
