package pm.crypto.passkey;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;

/**
 * The credential public key as a COSE_Key (RFC 9052 §7, RFC 9053 §7.1.1) in CTAP2 canonical CBOR
 * (CTAP 2.1 §8, "CTAP2 canonical CBOR encoding form"): a 5-entry map
 * {@code {1: 2, 3: -7, -1: 1, -2: x, -3: y}} (kty EC2, alg ES256, crv P-256, 32-byte
 * coordinates), keys in canonical order 1, 3, -1, -2, -3. Every ES256 P-256 key has this exact
 * 77-byte shape, so encoding is a fixed 10-byte prefix, X, a 3-byte separator and Y, and decoding
 * accepts only that layout (ADR 0016, SR-083). No general CBOR codec is needed in pm-crypto.
 */
public final class CoseKey {
    /** Length of an ES256 P-256 COSE_Key. */
    public static final int EC2_BYTES = 77;
    /**
     * {@code A5} map(5); {@code 01 02} kty: EC2; {@code 03 26} alg: -7; {@code 20 01} crv: P-256;
     * {@code 21 58 20} x: bstr(32).
     */
    private static final byte[] PREFIX = HexFormat.of().parseHex("a5010203262001215820");
    /** {@code 22 58 20} y: bstr(32). */
    private static final byte[] Y_LABEL = HexFormat.of().parseHex("225820");
    private static final int Y_AT = PREFIX.length + P256.FIELD_BYTES;

    private CoseKey() {
    }

    /**
     * The COSE_Key of an uncompressed P-256 point.
     *
     * @throws CryptoException {@code BAD_INPUT} unless {@code point} is a 65-byte uncompressed
     *     point on the curve
     */
    public static byte[] encodeEc2(byte[] point) throws CryptoException {
        Objects.requireNonNull(point, "point");
        P256.point(point);
        byte[] out = new byte[EC2_BYTES];
        writeEc2(point, out);
        return out;
    }

    /** Writes the COSE_Key of an already validated uncompressed point into {@code out} (77 bytes). */
    static void writeEc2(byte[] point, byte[] out) {
        System.arraycopy(PREFIX, 0, out, 0, PREFIX.length);
        System.arraycopy(point, 1, out, PREFIX.length, P256.FIELD_BYTES);
        System.arraycopy(Y_LABEL, 0, out, Y_AT, Y_LABEL.length);
        System.arraycopy(point, 1 + P256.FIELD_BYTES, out, Y_AT + Y_LABEL.length, P256.FIELD_BYTES);
    }

    /**
     * The uncompressed P-256 point (0x04, X, Y) of a canonical ES256 COSE_Key.
     *
     * @throws CryptoException {@code BAD_INPUT} if {@code cose} is not exactly the canonical
     *     77-byte encoding (other key type, algorithm or curve, other key order, extra entries,
     *     non-minimal lengths, trailing bytes) or the point is not on the curve
     */
    public static byte[] decodeEc2(byte[] cose) throws CryptoException {
        Objects.requireNonNull(cose, "cose");
        if (cose.length != EC2_BYTES
                || !ConstantTime.equals(PREFIX, Arrays.copyOf(cose, PREFIX.length))
                || !ConstantTime.equals(Y_LABEL, Arrays.copyOfRange(cose, Y_AT, Y_AT + Y_LABEL.length))) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        byte[] point = new byte[P256.POINT_BYTES];
        point[0] = P256.UNCOMPRESSED;
        System.arraycopy(cose, PREFIX.length, point, 1, P256.FIELD_BYTES);
        System.arraycopy(cose, Y_AT + Y_LABEL.length, point, 1 + P256.FIELD_BYTES, P256.FIELD_BYTES);
        P256.point(point);
        return point;
    }
}
