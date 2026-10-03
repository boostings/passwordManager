package pm.crypto;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Date;
import java.util.Objects;
import java.util.function.Predicate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Mutual TLS 1.3 for the LAN protocol (docs/protocols/lan-share.md §2): each side presents its
 * {@link DeviceIdentity} certificate, and accepts exactly one self-signed Ed25519 certificate whose
 * raw public key passes the caller's pin. There are no certificate authorities: during pairing the
 * pin accepts any well-formed key (the SAS then authenticates it); afterwards it is the paired
 * device's key, compared in constant time.
 */
public final class Tls {
    /** The only protocol version offered or accepted. */
    public static final String PROTOCOL = "TLSv1.3";
    private static final String[] PROTOCOLS = {PROTOCOL};
    private static final String[] CIPHER_SUITES = {"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"};
    private static final String KEY_ALIAS = "device";
    private static final String KEY_TYPE = "EdDSA";
    /** Peers present exactly their own self-signed certificate; there is no chain. */
    private static final int SINGLE_CERTIFICATE = 1;

    private Tls() {
    }

    /** A pin that accepts only {@code publicKey}, compared in constant time. */
    public static Predicate<byte[]> pinnedTo(byte[] publicKey) {
        byte[] expected = Objects.requireNonNull(publicKey, "publicKey").clone();
        return key -> ConstantTime.equals(expected, key);
    }

    /**
     * An {@code SSLContext} presenting {@code self} and accepting a peer whose key passes
     * {@code pin} and whose certificate is valid at {@code clock}'s time. The caller still applies
     * {@link #parameters(boolean)} to each socket or engine.
     */
    public static SSLContext context(DeviceIdentity self, Predicate<byte[]> pin, Clock clock) throws CryptoException {
        Objects.requireNonNull(self, "self");
        Objects.requireNonNull(pin, "pin");
        Objects.requireNonNull(clock, "clock");
        try {
            SSLContext context = SSLContext.getInstance(PROTOCOL);
            context.init(new X509ExtendedKeyManager[] {new KeyManager(self)},
                    new X509ExtendedTrustManager[] {new PinningTrustManager(pin, clock)}, null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoException.Code.INTERNAL);
        }
    }

    /** TLS 1.3 only, AEAD suites only, client authentication required. */
    public static SSLParameters parameters(boolean server) {
        SSLParameters p = new SSLParameters(CIPHER_SUITES.clone(), PROTOCOLS.clone());
        p.setNeedClientAuth(server);
        p.setEndpointIdentificationAlgorithm(null);
        return p;
    }

    /**
     * The raw public key of the authenticated peer of {@code session}.
     *
     * @throws CryptoException {@code BAD_INPUT} if the session has no verified Ed25519 peer
     */
    public static byte[] peerPublicKey(SSLSession session) throws CryptoException {
        try {
            Certificate[] chain = Objects.requireNonNull(session, "session").getPeerCertificates();
            if (chain.length != SINGLE_CERTIFICATE) {
                throw new CryptoException(CryptoException.Code.BAD_INPUT);
            }
            return DeviceIdentity.rawPublicKey(chain[0].getPublicKey());
        } catch (SSLPeerUnverifiedException e) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
    }

    /** Presents the device certificate, whatever the peer asks for. */
    static final class KeyManager extends X509ExtendedKeyManager {
        private final PrivateKey signer;
        private final X509Certificate certificate;

        KeyManager(DeviceIdentity self) throws CryptoException {
            this.signer = self.key();
            this.certificate = self.x509();
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return new String[] {KEY_ALIAS};
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return KEY_ALIAS;
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            return KEY_ALIAS;
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return new String[] {KEY_ALIAS};
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return serverAlias(keyType);
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return serverAlias(keyType);
        }

        private static String serverAlias(String keyType) {
            return KEY_TYPE.equals(keyType) ? KEY_ALIAS : null;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return new X509Certificate[] {certificate};
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return signer;
        }
    }

    /** Accepts one self-signed Ed25519 certificate, valid now, whose key passes the pin. */
    static final class PinningTrustManager extends X509ExtendedTrustManager {
        private final Predicate<byte[]> pin;
        private final Clock clock;

        PinningTrustManager(Predicate<byte[]> pin, Clock clock) {
            this.pin = pin;
            this.clock = clock;
        }

        void check(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length != SINGLE_CERTIFICATE) {
                throw new CertificateException("PEER_CHAIN");
            }
            try {
                DeviceIdentity.checkSelfSigned(chain[0]);
                chain[0].checkValidity(Date.from(clock.instant()));
                if (!pin.test(DeviceIdentity.rawPublicKey(chain[0].getPublicKey()))) {
                    throw new CertificateException("PEER_NOT_PINNED");
                }
            } catch (CryptoException e) {
                throw new CertificateException("PEER_CERT");
            }
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            check(chain);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            check(chain);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            check(chain);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {
            check(chain);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            check(chain);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {
            check(chain);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
