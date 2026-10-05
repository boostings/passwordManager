package pm.browser.bridge;

import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.LongFunction;
import pm.approval.Grant;
import pm.browser.host.HostException;

/**
 * What the WebAuthn actions need from the vault (ADR 0016 M6.3 addendum). Like {@link VaultPort},
 * the two methods that use a key take the broker's {@link Grant} and must
 * {@link Grant#consume() consume} it; the bridge answers nothing if they did not. No method ever
 * returns a private key: enrollment returns the public credential, signing returns the
 * signature. {@code pm.browser.webauthn.VaultPasskeys} implements it over an open
 * {@code pm.vault.Vault}.
 */
public interface PasskeyPort {

    /** The port of a bridge with no passkey support: every WebAuthn request is refused. */
    PasskeyPort NONE = new PasskeyPort() {
        @Override
        public List<Passkey> passkeys() throws HostException {
            throw new HostException(HostException.Code.UNKNOWN_TYPE);
        }

        @Override
        public Created create(Grant grant, String rpId, byte[] userHandle, String accountName,
                              String displayName) throws HostException {
            throw new HostException(HostException.Code.UNKNOWN_TYPE);
        }

        @Override
        public Signed sign(Grant grant, UUID id, byte[] clientDataHash, LongFunction<byte[]> authenticatorData)
                throws HostException {
            throw new HostException(HostException.Code.UNKNOWN_TYPE);
        }
    };

    /** Public metadata of one passkey: never its key. Arrays are copied in and out. */
    final class Passkey {
        private final UUID recordId;
        private final String relyingParty;
        private final byte[] credential;
        private final byte[] handle;
        private final String account;

        /**
         * Creates the metadata.
         *
         * @param id vault record id
         * @param rpId the RP ID the passkey is scoped to
         * @param credentialId credential ID
         * @param userHandle WebAuthn user handle
         * @param accountName account name shown in prompts
         */
        public Passkey(UUID id, String rpId, byte[] credentialId, byte[] userHandle, String accountName) {
            this.recordId = Objects.requireNonNull(id, "id");
            this.relyingParty = Objects.requireNonNull(rpId, "rpId");
            this.credential = Objects.requireNonNull(credentialId, "credentialId").clone();
            this.handle = Objects.requireNonNull(userHandle, "userHandle").clone();
            this.account = Objects.requireNonNull(accountName, "accountName");
        }

        /** The vault record id. */
        public UUID id() {
            return recordId;
        }

        /** The RP ID. */
        public String rpId() {
            return relyingParty;
        }

        /** A copy of the credential ID. */
        public byte[] credentialId() {
            return credential.clone();
        }

        /** A copy of the user handle. */
        public byte[] userHandle() {
            return handle.clone();
        }

        /** The account name. */
        public String accountName() {
            return account;
        }
    }

    /** A new passkey, already saved: its record id, credential ID and COSE public key. */
    final class Created {
        private final UUID recordId;
        private final byte[] credential;
        private final byte[] coseKey;

        /** Creates the result; arrays are copied. */
        public Created(UUID id, byte[] credentialId, byte[] cosePublicKey) {
            this.recordId = Objects.requireNonNull(id, "id");
            this.credential = Objects.requireNonNull(credentialId, "credentialId").clone();
            this.coseKey = Objects.requireNonNull(cosePublicKey, "cosePublicKey").clone();
        }

        /** The vault record id. */
        public UUID id() {
            return recordId;
        }

        /** A copy of the credential ID. */
        public byte[] credentialId() {
            return credential.clone();
        }

        /** A copy of the COSE_Key public key. */
        public byte[] cosePublicKey() {
            return coseKey.clone();
        }
    }

    /** One assertion: the counter it carries, the signed authenticator data and the signature. */
    final class Signed {
        private final long count;
        private final byte[] data;
        private final byte[] sig;

        /** Creates the result; arrays are copied. */
        public Signed(long signCount, byte[] authenticatorData, byte[] signature) {
            this.count = signCount;
            this.data = Objects.requireNonNull(authenticatorData, "authenticatorData").clone();
            this.sig = Objects.requireNonNull(signature, "signature").clone();
        }

        /** The persisted counter the authenticator data carries. */
        public long signCount() {
            return count;
        }

        /** A copy of the signed authenticator data. */
        public byte[] authenticatorData() {
            return data.clone();
        }

        /** A copy of the DER ECDSA signature. */
        public byte[] signature() {
            return sig.clone();
        }
    }

    /**
     * Metadata of every passkey in the open vault.
     *
     * @throws HostException {@code DENIED} ({@code DENIED_LOCKED}) if the vault is locked
     */
    List<Passkey> passkeys() throws HostException;

    /**
     * Generates and saves a new passkey for {@code rpId} under {@code grant}, which this call
     * consumes. The grant must be for operation {@code PASSKEY}, profile {@link #createProfile()},
     * on an origin that may use {@code rpId}.
     *
     * @throws HostException {@code GRANT_MISMATCH} for any other grant (nothing created),
     *     {@code BAD_FIELD} if a name or the user handle breaks the record's rules,
     *     {@code DENIED_LOCKED}, or {@code INTERNAL} if it could not be saved
     */
    Created create(Grant grant, String rpId, byte[] userHandle, String accountName, String displayName)
            throws HostException;

    /**
     * Signs {@code clientDataHash} with passkey {@code id} under {@code grant}, which this call
     * consumes. The grant must be for operation {@code PASSKEY}, profile {@link #signInProfile(UUID)}
     * of {@code id}, on an origin that may use the passkey's RP ID. The counter is advanced and saved
     * first; {@code authenticatorData} builds the authenticator data for that saved counter, and
     * only data bound to the passkey's RP ID and counter is signed.
     *
     * @throws HostException {@code GRANT_MISMATCH} for any other grant (nothing signed, counter
     *     unchanged), {@code NOT_FOUND}, {@code COUNTER_EXHAUSTED}, {@code DENIED_LOCKED}, or
     *     {@code INTERNAL}
     */
    Signed sign(Grant grant, UUID id, byte[] clientDataHash, LongFunction<byte[]> authenticatorData)
            throws HostException;

    /** The approval profile of an enrollment: {@code passkey-create}. */
    static String createProfile() {
        return Bridge.ACTION_PASSKEY_CREATE;
    }

    /** The approval profile of a sign-in with passkey {@code id}: {@code pk-} and its id in base 36. */
    static String signInProfile(UUID id) {
        return Bridge.profile(Bridge.PASSKEY_GET_PROFILE_PREFIX, Objects.requireNonNull(id, "id"));
    }
}
