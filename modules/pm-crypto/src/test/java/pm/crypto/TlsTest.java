package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.function.Predicate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.Test;

/** Mutual TLS 1.3 with pinned Ed25519 device certificates, driven in memory through SSLEngine. */
class TlsTest {
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final int BUFFER = 1 << 17;
    private static final int MAX_STEPS = 200;

    @Test
    void pinnedPeersCompleteAMutualTls13Handshake() throws CryptoException, SSLException {
        try (DeviceIdentity a = DeviceIdentity.generate(NOW); DeviceIdentity b = DeviceIdentity.generate(NOW)) {
            SSLEngine client = engine(a, Tls.pinnedTo(b.publicKey()), CLOCK, false);
            SSLEngine server = engine(b, Tls.pinnedTo(a.publicKey()), CLOCK, true);
            handshake(client, server);
            assertEquals(Tls.PROTOCOL, client.getSession().getProtocol());
            assertArrayEquals(b.publicKey(), Tls.peerPublicKey(client.getSession()));
            assertArrayEquals(a.publicKey(), Tls.peerPublicKey(server.getSession()));
        }
    }

    @Test
    void pairingModeAcceptsAnyWellFormedPeer() throws CryptoException, SSLException {
        try (DeviceIdentity a = DeviceIdentity.generate(NOW); DeviceIdentity b = DeviceIdentity.generate(NOW)) {
            handshake(engine(a, k -> true, CLOCK, false), engine(b, k -> true, CLOCK, true));
        }
    }

    @Test
    void anUnpinnedServerIsRefusedByTheClient() throws CryptoException, SSLException {
        try (DeviceIdentity a = DeviceIdentity.generate(NOW); DeviceIdentity b = DeviceIdentity.generate(NOW);
                DeviceIdentity mallory = DeviceIdentity.generate(NOW)) {
            SSLEngine client = engine(a, Tls.pinnedTo(b.publicKey()), CLOCK, false);
            SSLEngine server = engine(mallory, k -> true, CLOCK, true);
            assertThrows(SSLException.class, () -> handshake(client, server));
        }
    }

    @Test
    void anUnpinnedClientIsRefusedByTheServer() throws CryptoException, SSLException {
        try (DeviceIdentity a = DeviceIdentity.generate(NOW); DeviceIdentity b = DeviceIdentity.generate(NOW);
                DeviceIdentity mallory = DeviceIdentity.generate(NOW)) {
            SSLEngine client = engine(mallory, k -> true, CLOCK, false);
            SSLEngine server = engine(b, Tls.pinnedTo(a.publicKey()), CLOCK, true);
            assertThrows(SSLException.class, () -> handshake(client, server));
        }
    }

    @Test
    void anExpiredCertificateIsRefused() throws CryptoException, SSLException {
        Clock later = Clock.offset(CLOCK, DeviceIdentity.VALIDITY.plus(Duration.ofDays(1)));
        try (DeviceIdentity a = DeviceIdentity.generate(NOW); DeviceIdentity b = DeviceIdentity.generate(NOW)) {
            SSLEngine client = engine(a, k -> true, later, false);
            SSLEngine server = engine(b, k -> true, CLOCK, true);
            assertThrows(SSLException.class, () -> handshake(client, server));
        }
    }

    @Test
    void trustManagerRefusesChainsThatAreNotOneSelfSignedPinnedCertificate() throws CryptoException {
        try (DeviceIdentity a = DeviceIdentity.generate(NOW); DeviceIdentity b = DeviceIdentity.generate(NOW)) {
            X509Certificate certA = a.x509();
            X509Certificate certB = b.x509();
            Tls.PinningTrustManager tm = new Tls.PinningTrustManager(Tls.pinnedTo(a.publicKey()), CLOCK);
            assertThrows(CertificateException.class, () -> tm.check(null));
            assertThrows(CertificateException.class, () -> tm.check(new X509Certificate[0]));
            assertThrows(CertificateException.class, () -> tm.check(new X509Certificate[] {certA, certA}));
            assertThrows(CertificateException.class, () -> tm.check(new X509Certificate[] {certB}));
            X509Certificate[] good = {certA};
            assertDoesNotThrow(() -> tm.checkClientTrusted(good, "EdDSA"));
            assertDoesNotThrow(() -> tm.checkServerTrusted(good, "EdDSA"));
            assertDoesNotThrow(() -> tm.checkClientTrusted(good, "EdDSA", (java.net.Socket) null));
            assertDoesNotThrow(() -> tm.checkServerTrusted(good, "EdDSA", (java.net.Socket) null));
            assertDoesNotThrow(() -> tm.checkClientTrusted(good, "EdDSA", (SSLEngine) null));
            assertDoesNotThrow(() -> tm.checkServerTrusted(good, "EdDSA", (SSLEngine) null));
            assertEquals(0, tm.getAcceptedIssuers().length);
            Tls.PinningTrustManager notYet = new Tls.PinningTrustManager(k -> true,
                    Clock.offset(CLOCK, Duration.ofDays(-2)));
            assertThrows(CertificateException.class, () -> notYet.check(good));
        }
    }

    @Test
    void keyManagerAlwaysPresentsTheDeviceCertificate() throws CryptoException {
        try (DeviceIdentity a = DeviceIdentity.generate(NOW)) {
            Tls.KeyManager km = new Tls.KeyManager(a);
            assertEquals("device", km.chooseServerAlias("EdDSA", null, null));
            assertEquals("device", km.chooseEngineServerAlias("EdDSA", null, null));
            assertNull(km.chooseServerAlias("RSA", null, null));
            assertEquals("device", km.chooseClientAlias(new String[] {"EdDSA"}, null, null));
            assertEquals("device", km.chooseEngineClientAlias(new String[] {"EdDSA"}, null, null));
            assertArrayEquals(new String[] {"device"}, km.getClientAliases("EdDSA", null));
            assertArrayEquals(new String[] {"device"}, km.getServerAliases("EdDSA", null));
            assertEquals(a.x509(), km.getCertificateChain("device")[0]);
            assertNotNull(km.getPrivateKey("device"));
        }
    }

    @Test
    void parametersAllowOnlyTls13AndRequireClientAuthOnTheServer() {
        SSLParameters server = Tls.parameters(true);
        assertArrayEquals(new String[] {"TLSv1.3"}, server.getProtocols());
        assertTrue(server.getNeedClientAuth());
        assertFalse(Tls.parameters(false).getNeedClientAuth());
    }

    @Test
    void peerPublicKeyNeedsExactlyOneVerifiedCertificate() throws CryptoException {
        try (DeviceIdentity a = DeviceIdentity.generate(NOW)) {
            X509Certificate cert = a.x509();
            DeviceIdentityTest.assertBadInput(() -> Tls.peerPublicKey(session(null)));
            DeviceIdentityTest.assertBadInput(() -> Tls.peerPublicKey(session(new Certificate[] {cert, cert})));
            assertArrayEquals(a.publicKey(), Tls.peerPublicKey(session(new Certificate[] {cert})));
        }
    }

    private static SSLSession session(Certificate[] chain) {
        return (SSLSession) Proxy.newProxyInstance(TlsTest.class.getClassLoader(), new Class<?>[] {SSLSession.class},
                (proxy, method, args) -> {
                    if (chain == null) {
                        throw new SSLPeerUnverifiedException("none");
                    }
                    return chain.clone();
                });
    }

    private static SSLEngine engine(DeviceIdentity self, Predicate<byte[]> pin, Clock clock, boolean server)
            throws CryptoException {
        SSLContext context = Tls.context(self, pin, clock);
        SSLEngine engine = context.createSSLEngine();
        engine.setUseClientMode(!server);
        engine.setSSLParameters(Tls.parameters(server));
        return engine;
    }

    /** Pumps records between the two engines until both finish, or throws the first failure. */
    private static void handshake(SSLEngine client, SSLEngine server) throws SSLException {
        ByteBuffer toServer = ByteBuffer.allocate(BUFFER);
        ByteBuffer toClient = ByteBuffer.allocate(BUFFER);
        client.beginHandshake();
        server.beginHandshake();
        for (int i = 0; i < MAX_STEPS && !(finished(client) && finished(server)); i++) {
            step(client, toClient, toServer);
            step(server, toServer, toClient);
        }
        assertTrue(finished(client) && finished(server), "handshake did not finish");
    }

    private static boolean finished(SSLEngine e) {
        return e.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING;
    }

    private static void step(SSLEngine e, ByteBuffer in, ByteBuffer out) throws SSLException {
        ByteBuffer sink = ByteBuffer.allocate(BUFFER);
        switch (e.getHandshakeStatus()) {
            case NEED_TASK -> {
                for (Runnable task = e.getDelegatedTask(); task != null; task = e.getDelegatedTask()) {
                    task.run();
                }
            }
            case NEED_WRAP -> e.wrap(ByteBuffer.allocate(0), out);
            case NEED_UNWRAP, NEED_UNWRAP_AGAIN -> {
                in.flip();
                e.unwrap(in, sink);
                in.compact();
            }
            default -> {
                // finished or not started: nothing to do
            }
        }
    }
}
