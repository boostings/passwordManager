package pm.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;

/**
 * This install's LAN identity (docs/protocols/lan-share.md §1): an Ed25519 key pair and a
 * self-signed X.509 certificate for it, CN = base32(device_id), valid for 10 years. The private
 * key stays in pm-crypto: callers get signatures, the public key and TLS contexts ({@link Tls}),
 * never the key. {@link #privateKeyPkcs8()} exists only so the vault can store it as a secret.
 *
 * <p>ADR 0008 residual risk: the JCA {@code PrivateKey} object holds its own copy of the key bytes,
 * which cannot be zeroed from here ({@code destroy()} is unsupported); {@link #close()} zeroes the
 * PKCS#8 copy and drops the reference.
 */
public final class DeviceIdentity implements AutoCloseable {
    /** Raw Ed25519 public key length. */
    public static final int PUBLIC_KEY_BYTES = 32;
    /** Device id length: the first 16 bytes of SHA-256(public key). */
    public static final int DEVICE_ID_BYTES = 16;
    /** Ed25519 signature length. */
    public static final int SIGNATURE_BYTES = 64;
    /** Certificate lifetime (lan-share.md §1). */
    public static final Duration VALIDITY = Duration.ofDays(3653);
    /** Backdating of {@code notBefore}, so a peer whose clock is a little behind still accepts it. */
    static final Duration CLOCK_SKEW = Duration.ofDays(1);
    static final String ALGORITHM = "Ed25519";
    /** RFC 8410: id-Ed25519. */
    static final ASN1ObjectIdentifier ED25519_OID = new ASN1ObjectIdentifier("1.3.101").branch("112");
    /** RFC 8410 SubjectPublicKeyInfo prefix for an Ed25519 key; the raw key follows. */
    private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final int FINGERPRINT_GROUP = 4;
    private static final int FINGERPRINT_GROUPS = 8;
    private static final char[] BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567".toCharArray();
    private static final int BASE32_BITS = 5;
    private static final int BASE32_MASK = 0x1f;
    private static final int SERIAL_BYTES = 16;

    private final SecretBytes pkcs8;
    private final byte[] rawKey;
    private final byte[] certificateDer;
    private PrivateKey privateKey;

    private DeviceIdentity(SecretBytes pkcs8, PrivateKey privateKey, byte[] rawKey, byte[] certificateDer) {
        this.pkcs8 = pkcs8;
        this.privateKey = privateKey;
        this.rawKey = rawKey;
        this.certificateDer = certificateDer;
    }

    /** A new identity whose certificate is valid from {@code now} minus one day for 10 years. */
    public static DeviceIdentity generate(Instant now) throws CryptoException {
        Objects.requireNonNull(now, "now");
        try {
            KeyPair pair = KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
            byte[] raw = rawPublicKey(pair.getPublic());
            byte[] der = selfSign(pair, raw, now);
            byte[] encoded = pair.getPrivate().getEncoded();
            return new DeviceIdentity(SecretBytes.takeOwnership(encoded), pair.getPrivate(), raw, der);
        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException(CryptoException.Code.INTERNAL);
        }
    }

    /**
     * Restores an identity from its stored parts. Takes a copy of {@code pkcs8}; the caller keeps
     * ownership of its argument.
     *
     * @throws CryptoException {@code BAD_INPUT} if either part does not parse, the certificate is
     *     not a self-signed Ed25519 certificate, or the key and the certificate do not belong together
     */
    public static DeviceIdentity restore(SecretBytes pkcs8, byte[] certificateDer) throws CryptoException {
        Objects.requireNonNull(pkcs8, "pkcs8");
        X509Certificate cert = parseSelfSigned(certificateDer);
        SecretBytes copy = pkcs8.apply(SecretBytes::copyOf);
        try {
            PrivateKey key = copy.applyCrypto(k -> KeyFactory.getInstance(ALGORITHM)
                    .generatePrivate(new PKCS8EncodedKeySpec(k)));
            byte[] raw = rawPublicKey(cert.getPublicKey());
            byte[] probe = Hash.sha256(raw);
            if (!verify(raw, probe, sign(key, probe))) {
                throw new CryptoException(CryptoException.Code.BAD_INPUT);
            }
            return new DeviceIdentity(copy, key, raw, certificateDer.clone());
        } catch (CryptoException e) {
            copy.close();
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
    }

    /**
     * Parses a peer's certificate as this protocol requires: one self-signed Ed25519 certificate
     * whose signature verifies under its own key. Validity dates are not checked here; see
     * {@link Tls}.
     *
     * @throws CryptoException {@code BAD_INPUT} otherwise
     */
    static X509Certificate parseSelfSigned(byte[] der) throws CryptoException {
        Objects.requireNonNull(der, "der");
        try {
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            checkSelfSigned(cert);
            return cert;
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
    }

    /**
     * Throws unless {@code cert} carries an Ed25519 key and is signed by it. A certificate claiming
     * any other signature algorithm cannot verify under an Ed25519 key, so this also pins the
     * algorithm.
     */
    static void checkSelfSigned(X509Certificate cert) throws CryptoException {
        try {
            rawPublicKey(cert.getPublicKey());
            cert.verify(cert.getPublicKey());
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
    }

    /** The raw 32-byte Ed25519 key inside {@code key}'s X.509 encoding. */
    static byte[] rawPublicKey(PublicKey key) throws CryptoException {
        byte[] spki = key.getEncoded();
        if (spki == null || spki.length != SPKI_PREFIX.length + PUBLIC_KEY_BYTES
                || !ConstantTime.equals(SPKI_PREFIX, Arrays.copyOf(spki, SPKI_PREFIX.length))) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        return Arrays.copyOfRange(spki, SPKI_PREFIX.length, spki.length);
    }

    private static byte[] selfSign(KeyPair pair, byte[] raw, Instant now)
            throws GeneralSecurityException, IOException, CryptoException {
        X500Name name = new X500Name("CN=" + base32(deviceId(raw)));
        AlgorithmIdentifier ed25519 = new AlgorithmIdentifier(ED25519_OID);
        V3TBSCertificateGenerator tbs = new V3TBSCertificateGenerator();
        tbs.setSerialNumber(new ASN1Integer(new BigInteger(1, Csprng.bytes(SERIAL_BYTES))));
        tbs.setIssuer(name);
        tbs.setSubject(name);
        tbs.setStartDate(new Time(Date.from(now.minus(CLOCK_SKEW))));
        tbs.setEndDate(new Time(Date.from(now.plus(VALIDITY))));
        tbs.setSignature(ed25519);
        tbs.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()));
        tbs.setExtensions(new Extensions(new Extension[] {
            new Extension(Extension.basicConstraints, true, new BasicConstraints(false).getEncoded()),
            new Extension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature).getEncoded()),
        }));
        TBSCertificate body = tbs.generateTBSCertificate();
        byte[] signature = sign(pair.getPrivate(), body.getEncoded(ASN1Encoding.DER));
        ASN1EncodableVector cert = new ASN1EncodableVector();
        cert.add(body);
        cert.add(ed25519);
        cert.add(new DERBitString(signature));
        ASN1Encodable sequence = new DERSequence(cert);
        return sequence.toASN1Primitive().getEncoded(ASN1Encoding.DER);
    }

    private static byte[] sign(PrivateKey key, byte[] message) throws CryptoException {
        try {
            Signature s = Signature.getInstance(ALGORITHM);
            s.initSign(key);
            s.update(message);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoException.Code.INTERNAL);
        }
    }

    /** Whether {@code signature} is a valid Ed25519 signature of {@code message} by raw key {@code publicKey}. */
    public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(signature, "signature");
        if (Objects.requireNonNull(publicKey, "publicKey").length != PUBLIC_KEY_BYTES) {
            return false;
        }
        byte[] spki = new byte[SPKI_PREFIX.length + PUBLIC_KEY_BYTES];
        System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
        System.arraycopy(publicKey, 0, spki, SPKI_PREFIX.length, PUBLIC_KEY_BYTES);
        try {
            Signature s = Signature.getInstance(ALGORITHM);
            s.initVerify(KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(spki)));
            s.update(message);
            return s.verify(signature);
        } catch (GeneralSecurityException e) {
            return false; // a malformed key or signature is simply not valid
        }
    }

    /** First 16 bytes of SHA-256({@code publicKey}). */
    public static byte[] deviceId(byte[] publicKey) {
        return Arrays.copyOf(Hash.sha256(publicKey), DEVICE_ID_BYTES);
    }

    /** SHA-256({@code publicKey}) as 8 groups of 4 lowercase hex digits, for comparing by eye. */
    public static String fingerprint(byte[] publicKey) {
        String hex = HexFormat.of().formatHex(Hash.sha256(publicKey));
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < FINGERPRINT_GROUPS; i++) {
            if (i > 0) {
                out.append(' ');
            }
            out.append(hex, i * FINGERPRINT_GROUP, (i + 1) * FINGERPRINT_GROUP);
        }
        return out.toString();
    }

    /** RFC 4648 base32, lowercase, no padding. */
    static String base32(byte[] data) {
        StringBuilder out = new StringBuilder();
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << Byte.SIZE) | (b & 0xff);
            bits += Byte.SIZE;
            while (bits >= BASE32_BITS) {
                bits -= BASE32_BITS;
                out.append(BASE32_ALPHABET[(buffer >> bits) & BASE32_MASK]);
            }
        }
        if (bits > 0) {
            out.append(BASE32_ALPHABET[(buffer << (BASE32_BITS - bits)) & BASE32_MASK]);
        }
        return out.toString();
    }

    /** Signs {@code message} with this identity. */
    public byte[] sign(byte[] message) throws CryptoException {
        return sign(key(), Objects.requireNonNull(message, "message"));
    }

    /** A copy of the raw 32-byte public key. */
    public byte[] publicKey() {
        return rawKey.clone();
    }

    /** This identity's device id. */
    public byte[] deviceId() {
        return deviceId(rawKey);
    }

    /** A copy of the certificate in DER. */
    public byte[] certificate() {
        return certificateDer.clone();
    }

    /** The PKCS#8 private key as a new secret, for storing in the vault. The caller closes it. */
    public SecretBytes privateKeyPkcs8() {
        key();
        return pkcs8.apply(SecretBytes::copyOf);
    }

    /** The JCA key, for {@link Tls}; never leaves pm-crypto. */
    PrivateKey key() {
        if (privateKey == null) {
            throw new IllegalStateException("CLOSED");
        }
        return privateKey;
    }

    X509Certificate x509() throws CryptoException {
        return parseSelfSigned(certificateDer);
    }

    /** Zeroes the stored key bytes and drops the key. Idempotent. */
    @Override
    public void close() {
        pkcs8.close();
        privateKey = null;
    }

    @Override
    public String toString() {
        return "DeviceIdentity[" + fingerprint(rawKey) + "]";
    }
}
