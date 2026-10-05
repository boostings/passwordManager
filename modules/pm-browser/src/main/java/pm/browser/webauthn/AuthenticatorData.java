package pm.browser.webauthn;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;
import pm.crypto.Hash;
import pm.crypto.passkey.CoseKey;

/**
 * WebAuthn authenticator data (WebAuthn Level 3 §6.1, ADR 0016 M6.3 addendum, SR-118):
 * {@code rpIdHash} (32) || {@code flags} (1) || {@code signCount} (4, big-endian) ||
 * [{@code attestedCredentialData}: {@code aaguid} (16) || {@code credentialIdLength} (2,
 * big-endian) || {@code credentialId} || {@code credentialPublicKey} (COSE_Key)].
 *
 * <p>pm sets UP (it prompted the user), never UV (it does not verify the user itself), BE and BS
 * (the key lives in the vault, which is backed up and can be restored elsewhere, so the credential
 * is a backed-up multi-device credential), AT on registration only, and never ED (no extensions).
 * The AAGUID is all zero, as attestation is {@code none}. The parser accepts this shape only:
 * ES256 keys in CTAP2 canonical form and no extensions.
 */
public final class AuthenticatorData {
    /** User present. */
    public static final int FLAG_UP = 0x01;
    /** User verified. */
    public static final int FLAG_UV = 0x04;
    /** Backup eligible. */
    public static final int FLAG_BE = 0x08;
    /** Backed up. */
    public static final int FLAG_BS = 0x10;
    /** Attested credential data present. */
    public static final int FLAG_AT = 0x40;
    /** Extension data present. */
    public static final int FLAG_ED = 0x80;
    /** The flags of every assertion pm makes: UP, BE, BS ({@code 0x19}). */
    public static final int ASSERTION_FLAGS = FLAG_UP | FLAG_BE | FLAG_BS;
    /** The flags of every registration pm makes: UP, BE, BS, AT ({@code 0x59}). */
    public static final int REGISTRATION_FLAGS = ASSERTION_FLAGS | FLAG_AT;
    /** Length of the AAGUID. */
    public static final int AAGUID_BYTES = 16;
    /** Length of authenticator data without attested credential data. */
    public static final int HEADER_BYTES = 37;
    /** Longest credential ID (WebAuthn Level 3 §6.5.1). */
    public static final int MAX_CREDENTIAL_ID_BYTES = 1023;
    /** Largest signature counter. */
    public static final long MAX_SIGN_COUNT = 0xFFFF_FFFFL;

    private static final int RP_ID_HASH_BYTES = 32;
    private static final int FLAGS_AT = 32;
    private static final int LENGTH_BYTES = 2;
    private static final int CREDENTIAL_AT = HEADER_BYTES + AAGUID_BYTES + LENGTH_BYTES;
    private static final int BYTE_MASK = 0xFF;
    private static final int SHORT_MASK = 0xFFFF;

    private final byte[] hashBytes;
    private final int flagBits;
    private final long counter;
    private final byte[] aaguidBytes;
    private final byte[] credentialBytes;
    private final byte[] coseKeyBytes;

    private AuthenticatorData(byte[] rpIdHash, int flags, long signCount, byte[] aaguid, byte[] credentialId,
                              byte[] cosePublicKey) {
        this.hashBytes = rpIdHash;
        this.flagBits = flags;
        this.counter = signCount;
        this.aaguidBytes = aaguid;
        this.credentialBytes = credentialId;
        this.coseKeyBytes = cosePublicKey;
    }

    /**
     * Authenticator data for an assertion: flags {@link #ASSERTION_FLAGS}, no attested credential
     * data, no extensions.
     *
     * @throws IllegalArgumentException if {@code signCount} is not a u32
     */
    public static byte[] assertion(String rpId, long signCount) {
        return header(rpId, ASSERTION_FLAGS, signCount, 0).array();
    }

    /**
     * Authenticator data for a registration: flags {@link #REGISTRATION_FLAGS}, counter 0, an
     * all-zero AAGUID, then the credential ID and COSE public key.
     *
     * @throws IllegalArgumentException if the credential ID is empty or longer than
     *     {@link #MAX_CREDENTIAL_ID_BYTES}
     */
    public static byte[] registration(String rpId, byte[] credentialId, byte[] cosePublicKey) {
        return registration(rpId, 0, new byte[AAGUID_BYTES], credentialId, cosePublicKey);
    }

    /** {@link #registration(String, byte[], byte[])} with any counter and AAGUID (spec vectors). */
    static byte[] registration(String rpId, long signCount, byte[] aaguid, byte[] credentialId,
                               byte[] cosePublicKey) {
        if (aaguid.length != AAGUID_BYTES || credentialId.length == 0
                || credentialId.length > MAX_CREDENTIAL_ID_BYTES) {
            throw new IllegalArgumentException("BAD_CREDENTIAL");
        }
        int attested = AAGUID_BYTES + LENGTH_BYTES + credentialId.length + cosePublicKey.length;
        return header(rpId, REGISTRATION_FLAGS, signCount, attested)
                .put(aaguid)
                .putShort((short) credentialId.length)
                .put(credentialId)
                .put(cosePublicKey)
                .array();
    }

    private static ByteBuffer header(String rpId, int flags, long signCount, int extra) {
        Objects.requireNonNull(rpId, "rpId");
        if (signCount < 0 || signCount > MAX_SIGN_COUNT) {
            throw new IllegalArgumentException("BAD_SIGN_COUNT");
        }
        return ByteBuffer.allocate(HEADER_BYTES + extra)
                .put(rpIdHash(rpId))
                .put((byte) flags)
                .putInt((int) signCount);
    }

    /** SHA-256 of the RP ID's ASCII bytes. */
    public static byte[] rpIdHash(String rpId) {
        return Hash.sha256(rpId.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Parses authenticator data of the shape pm produces (see the class comment).
     *
     * @throws IllegalArgumentException {@code BAD_AUTHENTICATOR_DATA} for any other shape: too
     *     short, ED set, AT set without a whole credential and canonical ES256 key, or trailing
     *     bytes
     */
    public static AuthenticatorData parse(byte[] data) {
        Objects.requireNonNull(data, "data");
        if (data.length < HEADER_BYTES || (data[FLAGS_AT] & FLAG_ED) != 0) {
            throw bad();
        }
        ByteBuffer in = ByteBuffer.wrap(data);
        byte[] hash = new byte[RP_ID_HASH_BYTES];
        in.get(hash);
        int flags = in.get() & BYTE_MASK;
        long count = Integer.toUnsignedLong(in.getInt());
        if ((flags & FLAG_AT) == 0) {
            if (data.length != HEADER_BYTES) {
                throw bad();
            }
            return new AuthenticatorData(hash, flags, count, null, null, null);
        }
        if (data.length < CREDENTIAL_AT) {
            throw bad();
        }
        byte[] aaguid = new byte[AAGUID_BYTES];
        in.get(aaguid);
        int idLength = in.getShort() & SHORT_MASK;
        if (idLength == 0 || idLength > MAX_CREDENTIAL_ID_BYTES
                || data.length != CREDENTIAL_AT + idLength + CoseKey.EC2_BYTES) {
            throw bad();
        }
        byte[] id = new byte[idLength];
        in.get(id);
        byte[] cose = Arrays.copyOfRange(data, CREDENTIAL_AT + idLength, data.length);
        try {
            CoseKey.decodeEc2(cose);
        } catch (CryptoException e) {
            throw bad();
        }
        return new AuthenticatorData(hash, flags, count, aaguid, id, cose);
    }

    /** True if the RP ID hash is SHA-256 of {@code rpId}. */
    public boolean isFor(String rpId) {
        return ConstantTime.equals(hashBytes, rpIdHash(rpId));
    }

    /** A copy of the 32-byte RP ID hash. */
    public byte[] rpIdHash() {
        return hashBytes.clone();
    }

    /** The flags byte. */
    public int flags() {
        return flagBits;
    }

    /** The signature counter. */
    public long signCount() {
        return counter;
    }

    /** True if attested credential data is present (AT). */
    public boolean hasAttestedCredential() {
        return credentialBytes != null;
    }

    /**
     * A copy of the AAGUID.
     *
     * @throws IllegalStateException {@code NO_ATTESTED_CREDENTIAL} for assertion data
     */
    public byte[] aaguid() {
        return attested(aaguidBytes);
    }

    /**
     * A copy of the credential ID.
     *
     * @throws IllegalStateException {@code NO_ATTESTED_CREDENTIAL} for assertion data
     */
    public byte[] credentialId() {
        return attested(credentialBytes);
    }

    /**
     * A copy of the COSE_Key credential public key.
     *
     * @throws IllegalStateException {@code NO_ATTESTED_CREDENTIAL} for assertion data
     */
    public byte[] cosePublicKey() {
        return attested(coseKeyBytes);
    }

    private byte[] attested(byte[] field) {
        if (!hasAttestedCredential()) {
            throw new IllegalStateException("NO_ATTESTED_CREDENTIAL");
        }
        return field.clone();
    }

    private static IllegalArgumentException bad() {
        return new IllegalArgumentException("BAD_AUTHENTICATOR_DATA");
    }
}
