package pm.crypto.passkey;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.IntFunction;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;
import pm.crypto.Csprng;
import pm.crypto.SecretBytes;
import pm.crypto.passkey.internal.PasskeyAccess;

/**
 * A passkey credential key pair: ECDSA on P-256 used as WebAuthn ES256 (ADR 0016, SR-080).
 *
 * <p>The private key is the raw 32-byte big-endian scalar d, held only in a {@link SecretBytes}
 * owned by this object. Signing happens here; no public method of this class returns d. The
 * storage form the vault encrypts at rest is reachable only through
 * {@link pm.crypto.passkey.storage.PasskeyStorage}, whose package is exported to {@code pm.vault}
 * alone (SR-080, ADR 0016). The public key is the uncompressed point and its COSE_Key. Not
 * thread-safe; close it when done.
 *
 * <p>Storage form: 98 bytes,
 * {@code 0x01 (version) || d (32) || 0x04 || X (32) || Y (32)}. Loading is strict: exact length
 * and version, d in [1, n-1], the point on the curve, and d·G equal to the stored point (compared
 * in constant time), so a corrupted or mismatched record never signs.
 */
public final class PasskeyKey implements AutoCloseable {
    /** Storage form version. */
    static final byte STORAGE_VERSION = 0x01;
    /** Length of the storage form. */
    static final int STORAGE_BYTES = 1 + P256.FIELD_BYTES + P256.POINT_BYTES;
    /** Length of a credential ID from {@link #newCredentialId()}. */
    public static final int CREDENTIAL_ID_BYTES = 32;

    private final SecretBytes scalar;
    private final byte[] point;

    static {
        // The storage form crosses into pm.crypto.passkey.storage only through this unexported hook.
        PasskeyAccess.install(new StorageHook());
    }

    /** The storage codec handed to {@link PasskeyAccess}; private so no other class can construct it. */
    private static final class StorageHook implements PasskeyAccess.Storage {
        @Override
        public SecretBytes toStorage(PasskeyKey key) {
            return key.toStorage();
        }

        @Override
        public PasskeyKey fromStorage(SecretBytes stored) throws CryptoException {
            return PasskeyKey.fromStorage(stored);
        }
    }

    private PasskeyKey(SecretBytes scalar, byte[] point) {
        this.scalar = scalar;
        this.point = point;
    }

    /** A new key pair whose scalar is drawn from {@link Csprng}. */
    public static PasskeyKey generate() {
        return generate(Csprng::bytes);
    }

    /**
     * A new key pair from {@code random}: 32-byte candidates are drawn until one is in [1, n-1]
     * (rejection sampling, so d is uniform; a rejection has probability below 2^-32).
     */
    static PasskeyKey generate(IntFunction<byte[]> random) {
        byte[] d = random.apply(P256.FIELD_BYTES);
        BigInteger v = new BigInteger(1, d);
        while (!P256.inRange(v)) {
            Arrays.fill(d, (byte) 0);
            d = random.apply(P256.FIELD_BYTES);
            v = new BigInteger(1, d);
        }
        try {
            return new PasskeyKey(SecretBytes.copyOf(d), P256.publicPoint(v));
        } finally {
            Arrays.fill(d, (byte) 0);
        }
    }

    /**
     * Loads a key from its storage form. The caller keeps ownership of {@code stored}.
     *
     * @throws CryptoException {@code BAD_INPUT} unless {@code stored} is exactly a valid storage
     *     form whose point is d·G
     */
    static PasskeyKey fromStorage(SecretBytes stored) throws CryptoException {
        Objects.requireNonNull(stored, "stored");
        byte[] raw = stored.apply(byte[]::clone);
        byte[] d = new byte[P256.FIELD_BYTES];
        try {
            if (raw.length != STORAGE_BYTES || raw[0] != STORAGE_VERSION) {
                throw new CryptoException(CryptoException.Code.BAD_INPUT);
            }
            System.arraycopy(raw, 1, d, 0, P256.FIELD_BYTES);
            byte[] q = Arrays.copyOfRange(raw, 1 + P256.FIELD_BYTES, STORAGE_BYTES);
            BigInteger v = P256.scalar(d);
            P256.point(q);
            if (!ConstantTime.equals(P256.publicPoint(v), q)) {
                throw new CryptoException(CryptoException.Code.BAD_INPUT);
            }
            return new PasskeyKey(SecretBytes.copyOf(d), q);
        } finally {
            Arrays.fill(raw, (byte) 0);
            Arrays.fill(d, (byte) 0);
        }
    }

    /** The storage form, a new secret owned by the caller, for the vault to encrypt at rest. */
    SecretBytes toStorage() {
        byte[] out = new byte[STORAGE_BYTES];
        out[0] = STORAGE_VERSION;
        scalar.withBytes(d -> System.arraycopy(d, 0, out, 1, P256.FIELD_BYTES));
        System.arraycopy(point, 0, out, 1 + P256.FIELD_BYTES, P256.POINT_BYTES);
        return SecretBytes.takeOwnership(out);
    }

    /**
     * The WebAuthn assertion signature over {@code authenticatorData || clientDataHash}: ES256,
     * ASN.1 DER, deterministic nonce (RFC 6979).
     *
     * @throws CryptoException {@code BAD_INPUT} unless the authenticator data is 37 bytes to
     *     16 KiB and the client data hash is exactly 32 bytes
     * @throws IllegalStateException {@code SECRET_CLOSED} after {@link #close()}
     */
    public byte[] sign(byte[] authenticatorData, byte[] clientDataHash) throws CryptoException {
        return signMessage(Es256.signedData(authenticatorData, clientDataHash));
    }

    /** ES256 over an arbitrary message; package-private for the RFC 6979 vectors. */
    byte[] signMessage(byte[] message) {
        BigInteger d = scalar.apply(b -> new BigInteger(1, b));
        return Es256.sign(d, message);
    }

    /** A copy of the uncompressed public point (0x04, X, Y). */
    public byte[] publicPoint() {
        return point.clone();
    }

    /** The public key as a CTAP2 canonical COSE_Key (see {@link CoseKey}). */
    public byte[] cosePublicKey() {
        byte[] out = new byte[CoseKey.EC2_BYTES];
        CoseKey.writeEc2(point, out);
        return out;
    }

    /** A new random credential ID of {@link #CREDENTIAL_ID_BYTES} bytes from {@link Csprng}. */
    public static byte[] newCredentialId() {
        return Csprng.bytes(CREDENTIAL_ID_BYTES);
    }

    /** Whether {@link #close()} has run. */
    public boolean isClosed() {
        return scalar.isClosed();
    }

    /** Zero-fills the private scalar. Idempotent. */
    @Override
    public void close() {
        scalar.close();
    }

    @Override
    public String toString() {
        return "PasskeyKey[ES256 P-256]";
    }
}
