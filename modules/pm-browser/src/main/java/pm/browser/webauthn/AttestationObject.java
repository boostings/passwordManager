package pm.browser.webauthn;

import java.util.Map;
import java.util.Objects;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/**
 * The attestation object of a registration (WebAuthn Level 3 §6.5.4, ADR 0016 M6.3 addendum,
 * SR-118) with the {@code none} attestation statement format (§8.7): the CBOR map
 * {@code {"fmt": "none", "attStmt": {}, "authData": <bytes>}}, written by the vault's
 * deterministic encoder (RFC 8949 §4.2.1 key order: {@code fmt}, {@code attStmt},
 * {@code authData}), which is also the order of the §16 test vectors.
 */
public final class AttestationObject {
    /** The attestation statement format. */
    public static final String FORMAT_NONE = "none";

    private AttestationObject() {
    }

    /** The {@code none} attestation object around {@code authenticatorData}. */
    public static byte[] none(byte[] authenticatorData) {
        Objects.requireNonNull(authenticatorData, "authenticatorData");
        return CborWriter.encode(new CborValue.MapV(Map.of(
                "fmt", new CborValue.Text(FORMAT_NONE),
                "attStmt", new CborValue.MapV(Map.of()),
                "authData", new CborValue.Bytes(authenticatorData))));
    }
}
