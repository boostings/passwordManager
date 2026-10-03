package pm.crypto.ssh;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import pm.crypto.DeviceIdentity;

/**
 * Proves that a parsed private key belongs to its public half by signing a fixed probe with the
 * private key and verifying it with the public key, as {@code DeviceIdentity.restore} does. A key
 * file whose halves disagree, or whose ECDSA point is not on the curve, is refused here rather
 * than handed to an agent that would sign with the wrong key.
 *
 * <p>ADR 0008 residual risk, recorded in ADR 0013: the JCA key objects and the ECDSA scalar
 * {@code BigInteger} hold copies of the private key that cannot be zeroed; they are dropped as
 * soon as the probe finishes.
 */
final class KeyCheck {
    /** Ed25519 private seed length. */
    static final int ED25519_SEED_BYTES = 32;
    /** Order of the P-256 base point (SEC 2 v2 §2.4.2). */
    static final BigInteger P256_ORDER = new BigInteger(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    /** Largest canonical mpint for a P-256 scalar: 32 bytes plus a leading zero. */
    static final int P256_MPINT_MAX = 33;
    /** Uncompressed P-256 point: 0x04, X, Y. */
    static final int P256_POINT_BYTES = 65;
    static final int P256_COORD_BYTES = 32;
    static final byte UNCOMPRESSED = 0x04;
    private static final int SIGN_BIT = 0x80;
    private static final byte[] PROBE = "pm ssh key consistency probe".getBytes(StandardCharsets.US_ASCII);

    private KeyCheck() {
    }

    /** Throws {@code MALFORMED_KEY} unless the 32-byte seed at {@code buf[at]} yields public key {@code pub}. */
    static void ed25519(byte[] buf, int at, byte[] pub) throws SshException {
        byte[] scalar = Arrays.copyOfRange(buf, at, at + ED25519_SEED_BYTES);
        try {
            PrivateKey k = KeyFactory.getInstance("Ed25519")
                    .generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, scalar));
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(k);
            s.update(PROBE);
            if (!DeviceIdentity.verify(pub, PROBE, s.sign())) {
                throw new SshException(SshException.Code.MALFORMED_KEY);
            }
        } catch (GeneralSecurityException e) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        } finally {
            Arrays.fill(scalar, (byte) 0);
        }
    }

    /**
     * The P-256 private scalar in the {@code mpint} (RFC 4251 §5) of {@code len} bytes at
     * {@code buf[at]}.
     *
     * @throws SshException {@code MALFORMED_KEY} unless the encoding is minimal and non-negative and
     *     the value is in [1, n-1]
     */
    static BigInteger mpintScalar(byte[] buf, int at, int len) throws SshException {
        if (len == 0 || (buf[at] & SIGN_BIT) != 0 || (len > 1 && buf[at] == 0 && (buf[at + 1] & SIGN_BIT) == 0)) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        BigInteger d = new BigInteger(1, buf, at, len);
        if (d.signum() == 0 || d.compareTo(P256_ORDER) >= 0) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        return d;
    }

    /** Throws {@code MALFORMED_KEY} unless scalar {@code d} and the uncompressed point {@code q} form a P-256 key pair. */
    static void ecdsaP256(byte[] q, BigInteger d) throws SshException {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec curve = params.getParameterSpec(ECParameterSpec.class);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PrivateKey priv = kf.generatePrivate(new ECPrivateKeySpec(d, curve));
            ECPoint w = new ECPoint(new BigInteger(1, q, 1, P256_COORD_BYTES),
                    new BigInteger(1, q, 1 + P256_COORD_BYTES, P256_COORD_BYTES));
            PublicKey pub = kf.generatePublic(new ECPublicKeySpec(w, curve));
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(priv);
            s.update(PROBE);
            byte[] sig = s.sign();
            s.initVerify(pub);
            s.update(PROBE);
            if (!s.verify(sig)) {
                throw new SshException(SshException.Code.MALFORMED_KEY);
            }
        } catch (GeneralSecurityException e) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
    }
}
