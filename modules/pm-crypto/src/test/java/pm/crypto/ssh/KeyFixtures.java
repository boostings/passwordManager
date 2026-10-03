package pm.crypto.ssh;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import pm.crypto.SecretBytes;

/**
 * Builds {@code openssh-key-v1} files in the test, from keys the JDK generates, byte for byte as
 * {@code ssh-keygen -N ''} lays them out (OpenSSH PROTOCOL.key). A committed {@code ssh-keygen}
 * fixture would be flagged by gitleaks (checked 2026-10-03: "leaks found: 1"), so no private key
 * file is committed; real {@code ssh-keygen} output was checked by hand (ADR 0013). Every key here
 * is generated per run and is a throwaway test key.
 */
final class KeyFixtures {
    static final String COMMENT = "throwaway@test";

    private KeyFixtures() {
    }

    /** A fresh Ed25519 key: 32-byte seed and 32-byte public key. */
    static final class Ed {
        final byte[] seed;
        final byte[] pub;

        Ed(byte[] seed, byte[] pub) {
            this.seed = seed.clone();
            this.pub = pub.clone();
        }
    }

    /** A fresh P-256 key: uncompressed point and the scalar's mpint encoding. */
    static final class Ec {
        final byte[] q;
        final byte[] d;

        Ec(byte[] q, byte[] d) {
            this.q = q.clone();
            this.d = d.clone();
        }
    }

    static Ed ed25519() {
        try {
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            // PKCS#8 for Ed25519 (RFC 8410) ends with the 32-byte seed.
            byte[] pkcs8 = kp.getPrivate().getEncoded();
            byte[] seed = Arrays.copyOfRange(pkcs8, pkcs8.length - 32, pkcs8.length);
            byte[] spki = kp.getPublic().getEncoded();
            return new Ed(seed, Arrays.copyOfRange(spki, spki.length - 32, spki.length));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static Ec p256() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = g.generateKeyPair();
            ECPublicKey pub = (ECPublicKey) kp.getPublic();
            byte[] q = new byte[65];
            q[0] = 4;
            put32(pub.getW().getAffineX(), q, 1);
            put32(pub.getW().getAffineY(), q, 33);
            return new Ec(q, ((ECPrivateKey) kp.getPrivate()).getS().toByteArray());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void put32(BigInteger v, byte[] out, int at) {
        byte[] b = v.toByteArray();
        int n = Math.min(b.length, 32);
        System.arraycopy(b, b.length - n, out, at + 32 - n, n);
    }

    /** Agent/private-section key fields for an Ed25519 key. */
    static byte[] fields(Ed k) {
        return new W().str("ssh-ed25519").str(k.pub).str(cat(k.seed, k.pub)).bytes();
    }

    /** Agent/private-section key fields for a P-256 key. */
    static byte[] fields(Ec k) {
        return new W().str("ecdsa-sha2-nistp256").str("nistp256").str(k.q).str(k.d).bytes();
    }

    static byte[] blob(Ed k) {
        return new W().str("ssh-ed25519").str(k.pub).bytes();
    }

    static byte[] blob(Ec k) {
        return new W().str("ecdsa-sha2-nistp256").str("nistp256").str(k.q).bytes();
    }

    static byte[] cat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** A mutable description of one key file; {@link #binary()} and {@link #text()} render it. */
    static final class File {
        String cipher = "none";
        String kdf = "none";
        byte[] kdfOptions = new byte[0];
        long nkeys = 1;
        byte[] publicBlob;
        long check1 = 0x1234_5678L;
        long check2 = 0x1234_5678L;
        byte[] fields;
        byte[] comment = COMMENT.getBytes(StandardCharsets.UTF_8);
        /** Null: the standard 1, 2, 3 ... padding to a multiple of 8. */
        byte[] padding;
        byte[] trailer = new byte[0];

        File(byte[] publicBlob, byte[] fields) {
            this.publicBlob = publicBlob.clone();
            this.fields = fields.clone();
        }

        static File of(Ed k) {
            return new File(blob(k), fields(k));
        }

        static File of(Ec k) {
            return new File(blob(k), fields(k));
        }

        byte[] privateSection() {
            W p = new W().u32(check1).u32(check2).raw(fields).str(comment);
            if (padding == null) {
                for (int i = 1; p.size() % 8 != 0; i++) {
                    p.u8(i);
                }
            } else {
                p.raw(padding);
            }
            return p.bytes();
        }

        byte[] binary() {
            return new W().raw("openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII))
                    .str(cipher).str(kdf).str(kdfOptions).u32(nkeys).str(publicBlob)
                    .str(privateSection()).raw(trailer).bytes();
        }

        byte[] text() {
            return armour(binary());
        }

        SecretBytes secret() {
            return SecretBytes.copyOf(text());
        }
    }

    static byte[] armour(byte[] bin) {
        String b64 = Base64.getMimeEncoder(70, new byte[] {'\n'}).encodeToString(bin);
        return (OpenSshFormat.BEGIN + "\n" + b64 + "\n" + OpenSshFormat.END + "\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

    /** Tiny SSH wire writer for fixtures. */
    static final class W {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        W u8(int v) {
            out.write(v);
            return this;
        }

        W u32(long v) {
            for (int s = 24; s >= 0; s -= 8) {
                out.write((int) (v >>> s) & 0xff);
            }
            return this;
        }

        W raw(byte[] b) {
            out.write(b, 0, b.length);
            return this;
        }

        W str(byte[] b) {
            return u32(b.length).raw(b);
        }

        W str(String s) {
            return str(s.getBytes(StandardCharsets.UTF_8));
        }

        int size() {
            return out.size();
        }

        byte[] bytes() {
            return out.toByteArray();
        }
    }
}
