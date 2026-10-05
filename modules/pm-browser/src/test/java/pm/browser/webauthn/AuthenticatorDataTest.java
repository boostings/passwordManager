package pm.browser.webauthn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** The authenticator data builder and parser refuse every shape pm does not produce (SR-118). */
@Tag("T-PK-04")
final class AuthenticatorDataTest {
    private static final String RP = "example.com";
    private static final byte[] CREDENTIAL = filled(32, 5);

    private static byte[] filled(int length, int value) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) value);
        return out;
    }

    /** The §16.2 credential public key: the last 77 bytes of its attestation object. */
    private static byte[] cose() {
        byte[] attestation = Vectors.get("16.2.create.attestationObject");
        return Arrays.copyOfRange(attestation, attestation.length - 77, attestation.length);
    }

    @Test
    void registrationRoundTrips() {
        byte[] data = AuthenticatorData.registration(RP, CREDENTIAL, cose());
        AuthenticatorData parsed = AuthenticatorData.parse(data);
        assertTrue(parsed.hasAttestedCredential());
        assertTrue(parsed.isFor(RP));
        assertFalse(parsed.isFor("example.org"));
        assertArrayEquals(AuthenticatorData.rpIdHash(RP), parsed.rpIdHash());
        assertArrayEquals(new byte[AuthenticatorData.AAGUID_BYTES], parsed.aaguid());
        assertArrayEquals(CREDENTIAL, parsed.credentialId());
        assertArrayEquals(cose(), parsed.cosePublicKey());
        assertEquals(0, parsed.signCount());
        assertEquals(0, parsed.flags() & (AuthenticatorData.FLAG_UV | AuthenticatorData.FLAG_ED));
    }

    @Test
    void assertionDataHasNoAttestedFields() {
        AuthenticatorData parsed = AuthenticatorData.parse(AuthenticatorData.assertion(RP, 9));
        assertEquals(9, parsed.signCount());
        assertEquals("NO_ATTESTED_CREDENTIAL", assertThrows(IllegalStateException.class, parsed::aaguid).getMessage());
        assertThrows(IllegalStateException.class, parsed::credentialId);
        assertThrows(IllegalStateException.class, parsed::cosePublicKey);
    }

    @Test
    void theBuilderRefusesBadCredentials() {
        byte[] cose = cose();
        assertThrows(IllegalArgumentException.class,
                () -> AuthenticatorData.registration(RP, 0, new byte[15], CREDENTIAL, cose));
        assertThrows(IllegalArgumentException.class, () -> AuthenticatorData.registration(RP, new byte[0], cose));
        assertThrows(IllegalArgumentException.class,
                () -> AuthenticatorData.registration(RP, new byte[AuthenticatorData.MAX_CREDENTIAL_ID_BYTES + 1], cose));
    }

    @Test
    void theParserRefusesOtherShapes() {
        byte[] assertion = AuthenticatorData.assertion(RP, 1);
        byte[] registration = AuthenticatorData.registration(RP, CREDENTIAL, cose());

        assertBad(Arrays.copyOf(assertion, 36));
        assertBad(Arrays.copyOf(assertion, 38));
        byte[] extensions = assertion.clone();
        extensions[32] |= (byte) AuthenticatorData.FLAG_ED;
        assertBad(extensions);
        // AT set but too short for an AAGUID and a length.
        byte[] attestedShort = Arrays.copyOf(registration, 54);
        assertBad(attestedShort);
        // Credential ID length 0, above 1023, or not matching the rest.
        byte[] zero = registration.clone();
        zero[53] = 0;
        zero[54] = 0;
        assertBad(zero);
        byte[] huge = registration.clone();
        huge[53] = 0x04;
        huge[54] = 0x00;
        assertBad(huge);
        assertBad(Arrays.copyOf(registration, registration.length - 1));
        assertBad(Arrays.copyOf(registration, registration.length + 1));
        // A key that is not a canonical ES256 COSE_Key.
        byte[] badKey = registration.clone();
        badKey[registration.length - 77] = (byte) 0xa4;
        assertBad(badKey);
    }

    private static void assertBad(byte[] data) {
        assertEquals("BAD_AUTHENTICATOR_DATA",
                assertThrows(IllegalArgumentException.class, () -> AuthenticatorData.parse(data)).getMessage());
    }
}
