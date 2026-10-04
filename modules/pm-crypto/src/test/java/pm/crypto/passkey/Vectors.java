package pm.crypto.passkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.HexFormat;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;

/**
 * Shared fixtures: the P-256 key of RFC 6979 Appendix A.2.5 and an independent JCA verifier. The
 * RFC scalar is a published test value, not a credential.
 */
final class Vectors {
    static final HexFormat HEX_FORMAT = HexFormat.of();
    /** RFC 6979 A.2.5 private scalar x. */
    static final String RFC_X = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    /** RFC 6979 A.2.5 public point coordinates Ux, Uy. */
    static final String RFC_UX = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
    static final String RFC_UY = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
    /** The order n of P-256 (SEC 2 v2 §2.4.2). */
    static final String ORDER = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    /** The field prime p of P-256. */
    static final String PRIME = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

    private Vectors() {
    }

    /** Functional call that may throw a {@link CryptoException}. */
    @FunctionalInterface
    interface Call {
        void run() throws CryptoException;
    }

    static void assertBadInput(Call call) {
        CryptoException e = assertThrows(CryptoException.class, call::run);
        assertEquals(CryptoException.Code.BAD_INPUT, e.code());
    }

    static byte[] hex(String s) {
        return HEX_FORMAT.parseHex(s);
    }

    /** The uncompressed point of the RFC 6979 key. */
    static byte[] rfcPoint() {
        return hex("04" + RFC_UX + RFC_UY);
    }

    /** The storage form of the RFC 6979 key. */
    static SecretBytes rfcStorage() {
        return SecretBytes.takeOwnership(hex("01" + RFC_X + "04" + RFC_UX + RFC_UY));
    }

    /** A JCA public key for an uncompressed point; the JCA rejects off-curve points itself. */
    static PublicKey jcaPublic(byte[] point) throws GeneralSecurityException {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec curve = params.getParameterSpec(ECParameterSpec.class);
        ECPoint w = new ECPoint(new BigInteger(1, point, 1, 32), new BigInteger(1, point, 33, 32));
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, curve));
    }

    /** Verifies a DER ECDSA-SHA-256 signature with the JDK provider (independent of BouncyCastle). */
    static boolean jcaVerify(byte[] point, byte[] message, byte[] der) throws GeneralSecurityException {
        Signature v = Signature.getInstance("SHA256withECDSA", "SunEC");
        v.initVerify(jcaPublic(point));
        v.update(message);
        return v.verify(der);
    }
}
