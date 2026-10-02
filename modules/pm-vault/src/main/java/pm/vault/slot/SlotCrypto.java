package pm.vault.slot;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.Argon2Params;
import pm.crypto.CryptoException;
import pm.crypto.Kdf;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.vault.envelope.KdfHeader;

/**
 * Derives a slot's key-encryption key (ADR 0004):
 *
 * <pre>
 * KEK = HKDF-SHA256(ikm = input, salt = none, info = "pm/slot/v1/" + slotUuid, 32)
 * </pre>
 *
 * <p>The passphrase slot's input is the Argon2id output. The recovery slot's input is the
 * 32-byte recovery key. Binding the slot UUID into {@code info} means two slots never share
 * a KEK, even from the same input. Every intermediate secret is closed before return.
 */
public final class SlotCrypto {

    /** KEK length in bytes (AES-256). */
    public static final int KEK_LENGTH = 32;

    private static final String INFO_PREFIX = "pm/slot/v1/";

    private SlotCrypto() {
    }

    /**
     * Derives the passphrase slot KEK. Always runs Argon2id to completion before returning
     * or failing, so timing does not depend on whether the passphrase is right.
     *
     * @param pw   master passphrase; not closed by this method
     * @param k    KDF parameters from the header
     * @param slot passphrase slot UUID
     * @return the KEK; the caller closes it
     * @throws CryptoException {@code BAD_PARAMS} if the header parameters are out of range
     */
    public static SecretBytes kekFromPassphrase(SecretChars pw, KdfHeader k, UUID slot) throws CryptoException {
        Objects.requireNonNull(pw, "pw");
        Objects.requireNonNull(k, "k");
        Objects.requireNonNull(slot, "slot");
        Argon2Params params;
        try {
            params = new Argon2Params(k.m(), k.t(), k.p());
        } catch (IllegalArgumentException e) {
            throw new CryptoException(CryptoException.Code.BAD_PARAMS);
        }
        try (SecretBytes utf8 = pw.toUtf8();
             SecretBytes stretched = Kdf.argon2id(utf8, k.salt(), params)) {
            return Kdf.hkdfSha256(stretched, null, info(slot), KEK_LENGTH);
        }
    }

    /**
     * Derives the recovery slot KEK.
     *
     * @param rk   32-byte recovery key; not closed by this method
     * @param slot recovery slot UUID
     * @return the KEK; the caller closes it
     * @throws CryptoException if HKDF fails
     */
    public static SecretBytes kekFromRecovery(SecretBytes rk, UUID slot) throws CryptoException {
        Objects.requireNonNull(rk, "rk");
        Objects.requireNonNull(slot, "slot");
        return Kdf.hkdfSha256(rk, null, info(slot), KEK_LENGTH);
    }

    private static byte[] info(UUID slot) {
        return (INFO_PREFIX + slot).getBytes(StandardCharsets.UTF_8);
    }
}
