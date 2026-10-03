package pm.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/**
 * A throwaway HTTPS identity for one browser-only share (lan-share.md §7, ADR 0010 Amendment 2):
 * an ECDSA P-256 key and a self-signed certificate for the listener's address. Browsers do not
 * accept Ed25519 server certificates, so the device identity cannot be used here. The key lives
 * only as long as the share; nothing is stored. The recipient compares {@link #fingerprint()},
 * which is what browsers display as the certificate's SHA-256 fingerprint.
 */
public final class WebIdentity {
    /** Longest validity: a share window is at most 24 h, plus clock skew either side. */
    public static final Duration MAX_VALIDITY = Duration.ofHours(26);
    static final String KEY_TYPE = "EC";
    private static final String CURVE = "secp256r1";
    private static final String SIGNATURE = "SHA256withECDSA";
    private static final Duration CLOCK_SKEW = Duration.ofHours(1);
    private static final int SERIAL_BYTES = 16;

    private final PrivateKey signer;
    private final X509Certificate cert;
    private final byte[] der;

    private WebIdentity(X509Certificate parsed, byte[] encoded, PrivateKey signing) {
        this.cert = parsed;
        this.der = encoded;
        this.signer = signing;
    }

    /**
     * A new identity whose certificate names {@code host} and is valid from {@code now} minus one
     * hour until {@code now} plus {@code validity}.
     *
     * @param validity at most {@link #MAX_VALIDITY}
     */
    public static WebIdentity generate(Instant now, Duration validity, InetAddress host) throws CryptoException {
        Objects.requireNonNull(now, "now");
        Objects.requireNonNull(host, "host");
        if (validity.isNegative() || validity.isZero() || validity.compareTo(MAX_VALIDITY) > 0) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance(KEY_TYPE);
            g.initialize(new ECGenParameterSpec(CURVE));
            KeyPair pair = g.generateKeyPair();
            byte[] encoded = selfSign(pair, host, now, validity);
            X509Certificate parsed = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(encoded));
            parsed.verify(pair.getPublic());
            return new WebIdentity(parsed, encoded, pair.getPrivate());
        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException(CryptoException.Code.INTERNAL);
        }
    }

    private static byte[] selfSign(KeyPair pair, InetAddress host, Instant now, Duration validity)
            throws GeneralSecurityException, IOException {
        X500Name name = new X500Name("CN=pm share");
        AlgorithmIdentifier ecdsa = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
        V3TBSCertificateGenerator tbs = new V3TBSCertificateGenerator();
        tbs.setSerialNumber(new ASN1Integer(new BigInteger(1, Csprng.bytes(SERIAL_BYTES))));
        tbs.setIssuer(name);
        tbs.setSubject(name);
        tbs.setStartDate(new Time(Date.from(now.minus(CLOCK_SKEW))));
        tbs.setEndDate(new Time(Date.from(now.plus(validity))));
        tbs.setSignature(ecdsa);
        tbs.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()));
        GeneralNames san = new GeneralNames(new GeneralName(GeneralName.iPAddress,
                new DEROctetString(host.getAddress())));
        tbs.setExtensions(new Extensions(new Extension[] {
            new Extension(Extension.basicConstraints, true, new BasicConstraints(false).getEncoded()),
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).getEncoded()),
            new Extension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth).getEncoded()),
            new Extension(Extension.subjectAlternativeName, false, san.getEncoded()),
        }));
        TBSCertificate body = tbs.generateTBSCertificate();
        Signature s = Signature.getInstance(SIGNATURE);
        s.initSign(pair.getPrivate());
        s.update(body.getEncoded(ASN1Encoding.DER));
        ASN1EncodableVector cert = new ASN1EncodableVector();
        cert.add(body);
        cert.add(ecdsa);
        cert.add(new DERBitString(s.sign()));
        return new DERSequence(cert).getEncoded(ASN1Encoding.DER);
    }

    /** The certificate's DER encoding. */
    public byte[] certificate() {
        return der.clone();
    }

    /** SHA-256 of the certificate as uppercase hex pairs joined by colons, as browsers show it. */
    public String fingerprint() {
        return HexFormat.ofDelimiter(":").formatHex(Hash.sha256(der)).toUpperCase(Locale.ROOT);
    }

    PrivateKey key() {
        return signer;
    }

    X509Certificate x509() {
        return cert;
    }
}
