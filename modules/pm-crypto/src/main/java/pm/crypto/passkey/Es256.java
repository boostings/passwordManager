package pm.crypto.passkey;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;
import pm.crypto.Hash;

/**
 * WebAuthn ES256 (COSE algorithm -7): ECDSA on P-256 with SHA-256 over
 * {@code authenticatorData || clientDataHash}, the signature encoded as an ASN.1 DER
 * {@code Ecdsa-Sig-Value} (WebAuthn Level 3, "Signature Formats for Packed Attestation,
 * FIDO U2F Attestation, and Assertion Signatures"). The nonce is derived deterministically
 * (RFC 6979 with HMAC-SHA-256), so signing needs no random source and is checked against the
 * RFC's P-256 vectors (ADR 0016, SR-082).
 */
public final class Es256 {
    /** COSE algorithm identifier for ES256. */
    public static final int COSE_ALG = -7;
    /** Length of a WebAuthn client data hash (SHA-256). */
    public static final int CLIENT_DATA_HASH_BYTES = Hash.SHA256_BYTES;
    /** Shortest authenticator data: rpIdHash (32), flags (1), signCount (4). */
    public static final int MIN_AUTHENTICATOR_DATA_BYTES = 37;
    /** Longest authenticator data accepted for signing (extensions included). */
    public static final int MAX_AUTHENTICATOR_DATA_BYTES = 16 * 1024;
    /** Longest DER signature: SEQUENCE of two 33-byte INTEGERs. */
    public static final int MAX_SIGNATURE_BYTES = 72;
    /** Shortest DER signature: SEQUENCE of two 1-byte INTEGERs. */
    static final int MIN_SIGNATURE_BYTES = 8;
    private static final byte SEQUENCE_TAG = 0x30;
    private static final byte INTEGER_TAG = 0x02;
    private static final int HEADER = 2;

    private Es256() {
    }

    /**
     * Whether {@code signature} is a valid ES256 assertion signature by the COSE EC2 key
     * {@code coseKey} over {@code authenticatorData || clientDataHash}. A signature that is not
     * canonical DER, or whose r or s is outside [1, n-1], is invalid. High-S signatures (s greater
     * than n/2) are accepted: ECDSA signatures are malleable ((r, s) and (r, n - s) both verify),
     * WebAuthn relying parties do not require low-S, and this signer does not normalize s. Do not
     * use this helper where a signature must be unique.
     *
     * @throws CryptoException {@code BAD_INPUT} if the key is not a canonical ES256 COSE_Key
     *     ({@link CoseKey#decodeEc2}) or the signed inputs have the wrong length
     */
    public static boolean verify(byte[] coseKey, byte[] authenticatorData, byte[] clientDataHash, byte[] signature)
            throws CryptoException {
        Objects.requireNonNull(signature, "signature");
        byte[] message = signedData(authenticatorData, clientDataHash);
        ECPublicKeyParameters pub = new ECPublicKeyParameters(P256.point(CoseKey.decodeEc2(coseKey)), P256.DOMAIN);
        BigInteger[] rs = decodeDer(signature);
        if (rs.length == 0) {
            return false;
        }
        ECDSASigner v = new ECDSASigner();
        v.init(false, pub);
        return v.verifySignature(Hash.sha256(message), rs[0], rs[1]);
    }

    /**
     * {@code authenticatorData || clientDataHash}, the bytes a WebAuthn assertion signs.
     *
     * @throws CryptoException {@code BAD_INPUT} unless the authenticator data is 37 bytes to
     *     16 KiB and the client data hash is exactly 32 bytes
     */
    static byte[] signedData(byte[] authenticatorData, byte[] clientDataHash) throws CryptoException {
        Objects.requireNonNull(authenticatorData, "authenticatorData");
        Objects.requireNonNull(clientDataHash, "clientDataHash");
        if (authenticatorData.length < MIN_AUTHENTICATOR_DATA_BYTES
                || authenticatorData.length > MAX_AUTHENTICATOR_DATA_BYTES
                || clientDataHash.length != CLIENT_DATA_HASH_BYTES) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        byte[] out = Arrays.copyOf(authenticatorData, authenticatorData.length + clientDataHash.length);
        System.arraycopy(clientDataHash, 0, out, authenticatorData.length, clientDataHash.length);
        return out;
    }

    /** RFC 6979 ECDSA-SHA-256 of {@code message} under scalar {@code d}, as canonical DER. */
    static byte[] sign(BigInteger d, byte[] message) {
        ECDSASigner s = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        s.init(true, new ECPrivateKeyParameters(d, P256.DOMAIN));
        BigInteger[] rs = s.generateSignature(Hash.sha256(message));
        return encodeDer(rs[0], rs[1]);
    }

    /** {@code SEQUENCE { INTEGER r, INTEGER s }} in DER for non-negative r and s below 2^256. */
    static byte[] encodeDer(BigInteger r, BigInteger s) {
        byte[] re = r.toByteArray();
        byte[] se = s.toByteArray();
        int body = 2 * HEADER + re.length + se.length;
        byte[] out = new byte[HEADER + body];
        out[0] = SEQUENCE_TAG;
        out[1] = (byte) body;
        int at = putInteger(out, HEADER, re);
        putInteger(out, at, se);
        return out;
    }

    private static int putInteger(byte[] out, int at, byte[] value) {
        out[at] = INTEGER_TAG;
        out[at + 1] = (byte) value.length;
        System.arraycopy(value, 0, out, at + HEADER, value.length);
        return at + HEADER + value.length;
    }

    /**
     * {@code {r, s}} from a canonical DER signature, or an empty array if {@code sig} is not
     * exactly the DER encoding {@link #encodeDer} would produce (wrong tags or lengths, long-form
     * lengths, non-minimal or negative integers, trailing bytes).
     */
    static BigInteger[] decodeDer(byte[] sig) {
        if (sig.length < MIN_SIGNATURE_BYTES || sig.length > MAX_SIGNATURE_BYTES
                || sig[0] != SEQUENCE_TAG || sig[1] != sig.length - HEADER) {
            return new BigInteger[0];
        }
        int rEnd = integerEnd(sig, HEADER);
        int sEnd = integerEnd(sig, rEnd);
        if (sEnd != sig.length) {
            return new BigInteger[0];
        }
        BigInteger r = new BigInteger(1, sig, HEADER + HEADER, rEnd - 2 * HEADER);
        BigInteger s = new BigInteger(1, sig, rEnd + HEADER, sEnd - rEnd - HEADER);
        return ConstantTime.equals(encodeDer(r, s), sig) ? new BigInteger[] {r, s} : new BigInteger[0];
    }

    /** End offset of the INTEGER whose tag is at {@code at}, or {@code sig.length + 1} if malformed. */
    private static int integerEnd(byte[] sig, int at) {
        int bad = sig.length + 1;
        if (at + HEADER > sig.length || sig[at] != INTEGER_TAG) {
            return bad;
        }
        int len = sig[at + 1];
        int end = at + HEADER + len;
        return len < 1 || end > sig.length ? bad : end;
    }
}
