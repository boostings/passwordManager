package pm.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

/**
 * The pairing ceremony's cryptography (docs/protocols/lan-share.md §5 as amended by ADR 0010
 * Amendment 1): commit-then-reveal nonces, the short authentication string (SAS) and the
 * confirmation MAC.
 *
 * <p>Why a commitment: a 6-digit SAS has only 10^6 values. If either side's contribution could be
 * chosen after seeing the other's, a machine in the middle could try contributions offline until
 * both screens show the same digits. Here the initiator commits to its nonce before the responder
 * sends one, and reveals it only after; so whichever role an attacker plays in each of its two
 * sessions, the digits each victim sees depend on a value the attacker could not know when it
 * fixed its own. One guess per attempt, 1 in 10^6, then the lockout (SR-203).
 *
 * <p>Every input is public except the derived key: the nonces travel inside the TLS tunnel, and the
 * public keys are the peers' authenticated certificate keys.
 */
public final class Pairing {
    /** Nonce length in bytes. */
    public static final int NONCE_BYTES = 32;
    /** Number of SAS digits. */
    public static final int SAS_DIGITS = 6;
    private static final long SAS_MODULUS = 1_000_000L;
    private static final int KEY_BYTES = 32;
    private static final int SAS_SOURCE_BYTES = Long.BYTES;
    private static final byte[] COMMIT_LABEL = ascii("pm/pair/commit/v1");
    private static final byte[] KEY_SALT = ascii("pm/pair/v1");
    private static final byte[] KEY_INFO = ascii("pm/sas/v1");
    private static final byte[] CONFIRM_LABEL = ascii("ok");

    private Pairing() {
    }

    /** A fresh random nonce. */
    public static byte[] nonce() {
        return Csprng.bytes(NONCE_BYTES);
    }

    /**
     * The commitment the initiator sends before seeing the responder's nonce:
     * SHA-256("pm/pair/commit/v1" ‖ own public key ‖ nonce). Binding the sender's key stops a
     * commitment being reflected back to the side that made it.
     */
    public static byte[] commitment(byte[] ownPublicKey, byte[] nonce) {
        checkKey(ownPublicKey);
        checkNonce(nonce);
        return Hash.sha256(concat(COMMIT_LABEL, ownPublicKey, nonce));
    }

    /** Whether {@code nonce} opens {@code commitment} made by {@code publicKey}, in constant time. */
    public static boolean opens(byte[] commitment, byte[] publicKey, byte[] nonce) {
        Objects.requireNonNull(commitment, "commitment");
        return ConstantTime.equals(commitment(publicKey, nonce), commitment);
    }

    /**
     * The SAS key: HKDF-SHA256(ikm = initiator nonce ‖ responder nonce, salt = "pm/pair/v1",
     * info = "pm/sas/v1" ‖ lower key ‖ higher key), 32 bytes. Keys are ordered by unsigned byte
     * comparison, so both sides get the same key whichever key they call their own.
     */
    public static SecretBytes sasKey(byte[] keyA, byte[] keyB, byte[] initiatorNonce, byte[] responderNonce)
            throws CryptoException {
        checkKey(keyA);
        checkKey(keyB);
        checkNonce(initiatorNonce);
        checkNonce(responderNonce);
        boolean aFirst = Arrays.compareUnsigned(keyA, keyB) <= 0;
        byte[] info = concat(KEY_INFO, aFirst ? keyA : keyB, aFirst ? keyB : keyA);
        byte[] ikm = concat(initiatorNonce, responderNonce);
        try (SecretBytes material = SecretBytes.takeOwnership(ikm)) {
            return Kdf.hkdfSha256(material, KEY_SALT, info, KEY_BYTES);
        }
    }

    /** The six digits both screens show: the first 8 bytes of the SAS key, unsigned, mod 10^6. */
    public static String sas(SecretBytes sasKey) {
        long value = sasKey.apply(k -> {
            long v = 0;
            for (int i = 0; i < SAS_SOURCE_BYTES; i++) {
                v = (v << Byte.SIZE) | (k[i] & 0xff);
            }
            return v;
        });
        return String.format(Locale.ROOT, "%06d", Long.remainderUnsigned(value, SAS_MODULUS));
    }

    /** The confirmation a side sends once its user matched the digits: HMAC(sasKey, "ok" ‖ own key). */
    public static byte[] confirmation(SecretBytes sasKey, byte[] ownPublicKey) throws CryptoException {
        checkKey(ownPublicKey);
        return Hmac.sha256(sasKey, concat(CONFIRM_LABEL, ownPublicKey));
    }

    /** Whether {@code mac} is the peer's confirmation under this side's SAS key. */
    public static boolean confirms(SecretBytes sasKey, byte[] peerPublicKey, byte[] mac) throws CryptoException {
        checkKey(peerPublicKey);
        return Hmac.verify(sasKey, concat(CONFIRM_LABEL, peerPublicKey), mac);
    }

    private static void checkKey(byte[] key) {
        if (Objects.requireNonNull(key, "key").length != DeviceIdentity.PUBLIC_KEY_BYTES) {
            throw new IllegalArgumentException("BAD_KEY");
        }
    }

    private static void checkNonce(byte[] nonce) {
        if (Objects.requireNonNull(nonce, "nonce").length != NONCE_BYTES) {
            throw new IllegalArgumentException("BAD_NONCE");
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int at = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, at, p.length);
            at += p.length;
        }
        return out;
    }
}
