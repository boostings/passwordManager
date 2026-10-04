package pm.crypto.passkey;

import java.math.BigInteger;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import pm.crypto.CryptoException;

/**
 * The NIST P-256 (secp256r1) curve and the strict checks every passkey scalar and point passes
 * (ADR 0016, SR-081). P-256 has cofactor 1, so a point that decodes and lies on the curve is in
 * the prime-order group.
 */
final class P256 {
    /** Length of a scalar and of each affine coordinate. */
    static final int FIELD_BYTES = 32;
    /** Uncompressed SEC 1 point: 0x04, X, Y. */
    static final int POINT_BYTES = 1 + 2 * FIELD_BYTES;
    static final byte UNCOMPRESSED = 0x04;

    private static final X9ECParameters CURVE = CustomNamedCurves.getByName("secp256r1");
    /** Domain parameters for the BouncyCastle low-level signer. */
    static final ECDomainParameters DOMAIN = new ECDomainParameters(CURVE);
    /** Order n of the base point. */
    static final BigInteger ORDER = CURVE.getN();

    private P256() {
    }

    /**
     * The scalar in {@code d}, a 32-byte big-endian value.
     *
     * @throws CryptoException {@code BAD_INPUT} unless the value is in [1, n-1]
     */
    static BigInteger scalar(byte[] d) throws CryptoException {
        BigInteger v = new BigInteger(1, d);
        if (!inRange(v)) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        return v;
    }

    /** Whether {@code v} is a valid private scalar, in [1, n-1]. */
    static boolean inRange(BigInteger v) {
        return v.signum() > 0 && v.compareTo(ORDER) < 0;
    }

    /** The uncompressed encoding of {@code d}·G for a scalar already in [1, n-1]. */
    static byte[] publicPoint(BigInteger d) {
        return new FixedPointCombMultiplier().multiply(CURVE.getG(), d).normalize().getEncoded(false);
    }

    /**
     * The point in a 65-byte uncompressed encoding.
     *
     * @throws CryptoException {@code BAD_INPUT} for any other length or prefix, a coordinate not
     *     below the field prime, or a point not on the curve
     */
    static ECPoint point(byte[] encoded) throws CryptoException {
        if (encoded.length != POINT_BYTES || encoded[0] != UNCOMPRESSED) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        try {
            return CURVE.getCurve().decodePoint(encoded);
        } catch (IllegalArgumentException e) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
    }
}
