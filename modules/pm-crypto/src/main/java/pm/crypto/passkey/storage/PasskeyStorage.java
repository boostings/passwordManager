package pm.crypto.passkey.storage;

import java.util.Objects;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;
import pm.crypto.passkey.PasskeyKey;
import pm.crypto.passkey.internal.PasskeyAccess;

/**
 * The passkey storage form, for the vault to encrypt at rest (ADR 0016, SR-080, SR-081). This is
 * the only way the private scalar leaves {@code pm-crypto}; the package is exported to
 * {@code pm.vault} alone, so the browser and domain modules, which sign with {@link PasskeyKey},
 * cannot extract the scalar.
 *
 * <p>Form: 98 bytes, {@code 0x01 (version) || d (32) || 0x04 || X (32) || Y (32)}. Loading is
 * strict: exact length and version, d in [1, n-1], the point uncompressed with coordinates below
 * p and on the curve, and d·G equal to the stored point (constant-time compare).
 */
public final class PasskeyStorage {
    /** Length of the storage form. */
    public static final int STORAGE_BYTES = 98;

    private PasskeyStorage() {
    }

    /**
     * The storage form of {@code key}, a new secret owned by the caller.
     *
     * @throws IllegalStateException {@code SECRET_CLOSED} if {@code key} is closed
     */
    public static SecretBytes toStorage(PasskeyKey key) {
        return PasskeyAccess.storage().toStorage(Objects.requireNonNull(key, "key"));
    }

    /**
     * Loads a key from its storage form. The caller keeps ownership of {@code stored}.
     *
     * @throws CryptoException {@code BAD_INPUT} unless {@code stored} is exactly a valid storage
     *     form whose point is d·G
     */
    public static PasskeyKey fromStorage(SecretBytes stored) throws CryptoException {
        return PasskeyAccess.storage().fromStorage(Objects.requireNonNull(stored, "stored"));
    }
}
