package pm.cli;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.Base64;

/**
 * Throwaway Ed25519 keys for the CLI tests, written as {@code ssh-keygen -N ''} lays out an
 * unencrypted {@code openssh-key-v1} file (OpenSSH PROTOCOL.key). Keys are generated per run; no
 * private key file is committed (ADR 0013: a committed fixture is flagged by gitleaks). The armour
 * label is split across literals so this source holds no BEGIN-to-END private key block.
 */
final class SshTestKeys {
    static final String ARMOUR_KIND = "OPENSSH " + "PRIVATE KEY";
    private static final int ED25519_BYTES = 32;
    private static final int BLOCK = 8;

    /** One generated key: its file text and its public key blob. */
    static final class Key {
        private final byte[] fileBytes;
        private final byte[] blobBytes;

        Key(byte[] file, byte[] blob) {
            fileBytes = file.clone();
            blobBytes = blob.clone();
        }

        byte[] file() {
            return fileBytes.clone();
        }

        byte[] blob() {
            return blobBytes.clone();
        }
    }

    private SshTestKeys() {
    }

    /** A fresh Ed25519 key with {@code comment}. */
    static Key ed25519(String comment) {
        KeyPair kp;
        try {
            kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        byte[] pkcs8 = kp.getPrivate().getEncoded();
        byte[] seed = Arrays.copyOfRange(pkcs8, pkcs8.length - ED25519_BYTES, pkcs8.length);
        byte[] spki = kp.getPublic().getEncoded();
        byte[] pub = Arrays.copyOfRange(spki, spki.length - ED25519_BYTES, spki.length);
        byte[] both = Arrays.copyOf(seed, ED25519_BYTES * 2);
        System.arraycopy(pub, 0, both, ED25519_BYTES, ED25519_BYTES);
        byte[] blob = new W().str("ssh-ed25519").str(pub).bytes();
        W priv = new W().u32(0x5eed_cafeL).u32(0x5eed_cafeL)
                .str("ssh-ed25519").str(pub).str(both).str(comment);
        for (int i = 1; priv.size() % BLOCK != 0; i++) {
            priv.u8(i);
        }
        byte[] bin = new W().raw("openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII))
                .str("none").str("none").str(new byte[0]).u32(1).str(blob).str(priv.bytes()).bytes();
        String b64 = Base64.getMimeEncoder(70, new byte[] {'\n'}).encodeToString(bin);
        String text = "-----BEGIN " + ARMOUR_KIND + "-----\n" + b64 + "\n-----END " + ARMOUR_KIND + "-----\n";
        return new Key(text.getBytes(StandardCharsets.US_ASCII), blob);
    }

    /** Tiny SSH wire writer. */
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
