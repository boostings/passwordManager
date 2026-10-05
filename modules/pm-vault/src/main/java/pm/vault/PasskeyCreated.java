package pm.vault;

import java.util.Objects;
import java.util.UUID;

/**
 * What {@link Vault#createPasskey} hands back (ADR 0016 M6.3 addendum, SR-115): the new record's
 * id and the public credential, already saved. Never the private key, which stays in the vault.
 * Not a secret: the credential ID and the COSE public key go to the relying party. Arrays are
 * copied in and out (OBJ05-J, OBJ06-J).
 */
public final class PasskeyCreated {
    private final UUID recordId;
    private final String relyingParty;
    private final byte[] credential;
    private final byte[] coseKey;

    PasskeyCreated(UUID id, String rpId, byte[] credentialId, byte[] cosePublicKey) {
        this.recordId = Objects.requireNonNull(id, "id");
        this.relyingParty = Objects.requireNonNull(rpId, "rpId");
        this.credential = Objects.requireNonNull(credentialId, "credentialId").clone();
        this.coseKey = Objects.requireNonNull(cosePublicKey, "cosePublicKey").clone();
    }

    /** Returns the vault record id of the new passkey. */
    public UUID id() {
        return recordId;
    }

    /** Returns the relying-party ID the credential is scoped to. */
    public String rpId() {
        return relyingParty;
    }

    /** Returns a copy of the random credential ID (32 bytes). */
    public byte[] credentialId() {
        return credential.clone();
    }

    /** Returns a copy of the credential public key as a CTAP2 canonical COSE_Key (ES256, 77 bytes). */
    public byte[] cosePublicKey() {
        return coseKey.clone();
    }

    /** The record id and RP ID only. */
    @Override
    public String toString() {
        return "PasskeyCreated[id=" + recordId + ", rpId=" + relyingParty + "]";
    }
}
