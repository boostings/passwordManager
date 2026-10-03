package pm.crypto.ssh;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.function.Consumer;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;
import org.junit.jupiter.api.Test;
import pm.crypto.Hash;
import pm.crypto.SecretBytes;

/** openssh-key-v1 parsing (ADR 0013, SR-062): what is accepted, and every way a file is refused. */
class SshKeyTest {

    private static SshKey parse(byte[] text) throws SshException {
        try (SecretBytes s = SecretBytes.copyOf(text)) {
            return SshKey.parse(s);
        }
    }

    private static SshException.Code refused(byte[] text) {
        return assertThrows(SshException.class, () -> parse(text).close()).code();
    }

    private static SshException.Code refusedEd(Consumer<KeyFixtures.File> change) {
        KeyFixtures.File f = KeyFixtures.File.of(KeyFixtures.ed25519());
        change.accept(f);
        return refused(f.text());
    }

    private static SshException.Code refusedEc(Consumer<KeyFixtures.File> change) {
        KeyFixtures.File f = KeyFixtures.File.of(KeyFixtures.p256());
        change.accept(f);
        return refused(f.text());
    }

    @Test
    void parsesAnEd25519KeyLaidOutAsSshKeygenWritesIt() throws SshException {
        KeyFixtures.Ed k = KeyFixtures.ed25519();
        byte[] blob = KeyFixtures.blob(k);
        try (SshKey key = parse(KeyFixtures.File.of(k).text())) {
            assertEquals(SshKeyType.ED25519, key.type());
            assertEquals("ssh-ed25519", key.type().wireName());
            assertEquals(KeyFixtures.COMMENT, key.comment());
            assertArrayEquals(blob, key.publicKeyBlob());
            String fp = "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(Hash.sha256(blob));
            assertEquals(fp, key.fingerprint());
            assertEquals("ssh-ed25519 " + Base64.getEncoder().encodeToString(blob) + " " + KeyFixtures.COMMENT,
                    key.publicKeyLine());
            assertEquals("SshKey[ssh-ed25519 " + fp + "]", key.toString());
            try (WireWriter w = new WireWriter()) {
                key.writeFields(w);
                assertArrayEquals(KeyFixtures.fields(k), w.toBytes());
            }
            assertFalse(key.isClosed());
            shut(key);
            assertTrue(key.isClosed());
            shut(key);
            try (WireWriter w = new WireWriter()) {
                assertThrows(IllegalStateException.class, () -> key.writeFields(w));
            }
            assertArrayEquals(blob, key.publicKeyBlob());
        }
    }

    /** Closes outside try-with-resources so idempotent close can be tested. */
    static void shut(SshKey key) {
        key.close();
    }

    @Test
    void parsesAnEcdsaP256Key() throws SshException {
        KeyFixtures.Ec k = KeyFixtures.p256();
        try (SshKey key = parse(KeyFixtures.File.of(k).text())) {
            assertEquals(SshKeyType.ECDSA_P256, key.type());
            assertArrayEquals(KeyFixtures.blob(k), key.publicKeyBlob());
            try (WireWriter w = new WireWriter()) {
                key.writeFields(w);
                assertArrayEquals(KeyFixtures.fields(k), w.toBytes());
            }
        }
    }

    @Test
    void anEmptyCommentLeavesItOffThePublicLine() throws SshException {
        KeyFixtures.File f = KeyFixtures.File.of(KeyFixtures.ed25519());
        f.comment = new byte[0];
        try (SshKey key = parse(f.text())) {
            assertEquals("", key.comment());
            assertFalse(key.publicKeyLine().endsWith(" "));
            assertEquals(2, key.publicKeyLine().split(" ").length);
        }
    }

    @Test
    void acceptsCrlfLineEndingsAndTrailingBlankLines() throws SshException {
        KeyFixtures.Ed k = KeyFixtures.ed25519();
        String unix = new String(KeyFixtures.File.of(k).text(), StandardCharsets.US_ASCII);
        byte[] dos = (unix.replace("\n", "\r\n") + "\r\n\n").getBytes(StandardCharsets.US_ASCII);
        try (SshKey key = parse(dos)) {
            assertArrayEquals(KeyFixtures.blob(k), key.publicKeyBlob());
        }
    }

    @Test
    void parseLeavesTheCallersSecretOpenAndIntact() throws SshException {
        byte[] text = KeyFixtures.File.of(KeyFixtures.ed25519()).text();
        try (SecretBytes s = SecretBytes.copyOf(text); SshKey key = SshKey.parse(s)) {
            assertFalse(s.isClosed());
            assertEquals(SshKeyType.ED25519, key.type());
            assertTrue(s.equals(SecretBytes.copyOf(text)));
        }
    }

    @Test
    void refusesBadArmour() {
        byte[] good = KeyFixtures.File.of(KeyFixtures.ed25519()).text();
        String g = new String(good, StandardCharsets.US_ASCII);
        assertEquals(SshException.Code.MALFORMED_KEY, refused(new byte[SshKey.MAX_FILE_BYTES + 1]));
        assertEquals(SshException.Code.MALFORMED_KEY, refused("-----BEGIN".getBytes(StandardCharsets.US_ASCII)));
        assertEquals(SshException.Code.MALFORMED_KEY, refused(g.replace("OPENSSH PRIVATE", "RSA PRIVATE")
                .getBytes(StandardCharsets.US_ASCII)));
        assertEquals(SshException.Code.MALFORMED_KEY, refused(OpenSshFormat.BEGIN.getBytes(StandardCharsets.US_ASCII)));
        assertEquals(SshException.Code.MALFORMED_KEY, refused((OpenSshFormat.BEGIN + "x" + g.substring(OpenSshFormat.BEGIN.length()))
                .getBytes(StandardCharsets.US_ASCII)));
        assertEquals(SshException.Code.MALFORMED_KEY, refused(g.substring(0, g.indexOf("-----END"))
                .getBytes(StandardCharsets.US_ASCII)));
        assertEquals(SshException.Code.MALFORMED_KEY, refused((g + "trailing").getBytes(StandardCharsets.US_ASCII)));
        assertEquals(SshException.Code.MALFORMED_KEY, refused(g.replaceFirst("\n([A-Za-z0-9+/])", "\n*")
                .getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void refusesTheWrongMagicOrAShortBody() {
        assertEquals(SshException.Code.MALFORMED_KEY, refused(KeyFixtures.armour("openssh-key-v0\0xxxx".getBytes(StandardCharsets.US_ASCII))));
        assertEquals(SshException.Code.MALFORMED_KEY, refused(KeyFixtures.armour("open".getBytes(StandardCharsets.US_ASCII))));
        assertEquals(SshException.Code.MALFORMED_KEY, refused(KeyFixtures.armour(OpenSshFormat.MAGIC)));
        byte[] good = KeyFixtures.File.of(KeyFixtures.ed25519()).binary();
        for (int cut : new int[] {good.length - 1, good.length - 40, 60}) {
            assertEquals(SshException.Code.MALFORMED_KEY, refused(KeyFixtures.armour(Arrays.copyOf(good, cut))));
        }
    }

    @Test
    void refusesEncryptedKeysWithoutTryingToDecryptThem() {
        assertEquals(SshException.Code.ENCRYPTED_KEY, refusedEd(f -> {
            f.cipher = "aes256-ctr";
            f.kdf = "bcrypt";
            f.kdfOptions = new KeyFixtures.W().str(new byte[16]).u32(16).bytes();
        }));
        assertEquals(SshException.Code.ENCRYPTED_KEY, refusedEd(f -> f.cipher = "chacha20-poly1305@openssh.com"));
    }

    @Test
    void refusesInconsistentHeaderFields() {
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEd(f -> f.kdf = "bcrypt"));
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEd(f -> f.kdfOptions = new byte[] {0}));
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEd(f -> f.nkeys = 2));
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEd(f -> f.nkeys = 0));
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEd(f -> f.trailer = new byte[] {0}));
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEd(f -> f.check2 = f.check1 + 1));
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEd(f -> f.cipher = "x".repeat(SshKey.MAX_NAME_BYTES + 1)));
    }

    @Test
    void refusesOversizedOrOverlongLengths() {
        KeyFixtures.Ed k = KeyFixtures.ed25519();
        byte[] bin = KeyFixtures.File.of(k).binary();
        // The cipher-name length is the uint32 right after the magic: claim 2^32-1 and 2^31.
        for (long claim : new long[] {0xFFFF_FFFFL, 0x8000_0000L, bin.length}) {
            byte[] b = bin.clone();
            int at = OpenSshFormat.MAGIC.length;
            for (int i = 0; i < 4; i++) {
                b[at + i] = (byte) (claim >>> (24 - 8 * i));
            }
            assertEquals(SshException.Code.MALFORMED_KEY, refused(KeyFixtures.armour(b)));
        }
    }

    @Test
    void refusesUnknownAlgorithms() {
        assertEquals(SshException.Code.UNSUPPORTED_KEY, refusedEd(f ->
                f.fields = new KeyFixtures.W().str("ssh-rsa").str(new byte[3]).bytes()));
        assertEquals(SshException.Code.UNSUPPORTED_KEY, refusedEd(f ->
                f.fields = new KeyFixtures.W().str("ssh-ed448").bytes()));
    }

    @Test
    void refusesEd25519FieldsOfTheWrongSizeOrThatDisagree() {
        KeyFixtures.Ed k = KeyFixtures.ed25519();
        KeyFixtures.Ed other = KeyFixtures.ed25519();
        byte[] seedPub = KeyFixtures.cat(k.seed, k.pub);
        assertEquals(SshException.Code.MALFORMED_KEY, refused(withFields(k,
                new KeyFixtures.W().str("ssh-ed25519").str(Arrays.copyOf(k.pub, 31)).str(seedPub).bytes())));
        assertEquals(SshException.Code.MALFORMED_KEY, refused(withFields(k,
                new KeyFixtures.W().str("ssh-ed25519").str(Arrays.copyOf(k.pub, 33)).str(seedPub).bytes())));
        assertEquals(SshException.Code.MALFORMED_KEY, refused(withFields(k,
                new KeyFixtures.W().str("ssh-ed25519").str(k.pub).str(Arrays.copyOf(seedPub, 63)).bytes())));
        // The private half's copy of the public key differs from the public field.
        assertEquals(SshException.Code.MALFORMED_KEY, refused(withFields(k,
                new KeyFixtures.W().str("ssh-ed25519").str(k.pub).str(KeyFixtures.cat(k.seed, other.pub)).bytes())));
        // Both copies agree, but the seed belongs to another key.
        assertEquals(SshException.Code.MALFORMED_KEY, refused(withFields(k,
                new KeyFixtures.W().str("ssh-ed25519").str(k.pub).str(KeyFixtures.cat(other.seed, k.pub)).bytes())));
        // A consistent key whose outer public blob names a different key.
        KeyFixtures.File f = KeyFixtures.File.of(k);
        f.publicBlob = KeyFixtures.blob(other);
        assertEquals(SshException.Code.MALFORMED_KEY, refused(f.text()));
    }

    private static byte[] withFields(KeyFixtures.Ed k, byte[] fields) {
        KeyFixtures.File f = KeyFixtures.File.of(k);
        f.fields = fields;
        return f.text();
    }

    @Test
    void refusesBadEcdsaFields() {
        KeyFixtures.Ec k = KeyFixtures.p256();
        KeyFixtures.Ec other = KeyFixtures.p256();
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEc(f -> f.fields =
                new KeyFixtures.W().str("ecdsa-sha2-nistp256").str("nistp384").str(k.q).str(k.d).bytes()));
        byte[] compressed = k.q.clone();
        compressed[0] = 2;
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEc(f -> f.fields =
                new KeyFixtures.W().str("ecdsa-sha2-nistp256").str("nistp256").str(compressed).str(k.d).bytes()));
        byte[] offCurve = k.q.clone();
        offCurve[64] ^= 1;
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEc(f -> f.fields =
                new KeyFixtures.W().str("ecdsa-sha2-nistp256").str("nistp256").str(offCurve).str(k.d).bytes()));
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEc(f -> {
            f.fields = new KeyFixtures.W().str("ecdsa-sha2-nistp256").str("nistp256").str(k.q).str(other.d).bytes();
            f.publicBlob = KeyFixtures.blob(k);
        }));
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEc(f -> f.fields =
                new KeyFixtures.W().str("ecdsa-sha2-nistp256").str("nistp256").str(k.q).str(new byte[34]).bytes()));
    }

    @Test
    void mpintScalarAcceptsOnlyMinimalValuesInRange() throws SshException {
        assertThrows(SshException.class, () -> KeyCheck.mpintScalar(new byte[0], 0, 0));
        assertThrows(SshException.class, () -> KeyCheck.mpintScalar(new byte[] {(byte) 0x80}, 0, 1));
        assertThrows(SshException.class, () -> KeyCheck.mpintScalar(new byte[] {0, 0x7f}, 0, 2));
        assertThrows(SshException.class, () -> KeyCheck.mpintScalar(new byte[] {0}, 0, 1));
        byte[] n = KeyCheck.P256_ORDER.toByteArray();
        assertThrows(SshException.class, () -> KeyCheck.mpintScalar(n, 0, n.length));
        byte[] nMinus1 = KeyCheck.P256_ORDER.subtract(BigInteger.ONE).toByteArray();
        assertEquals(KeyCheck.P256_ORDER.subtract(BigInteger.ONE), KeyCheck.mpintScalar(nMinus1, 0, nMinus1.length));
        assertEquals(BigInteger.valueOf(0x80), KeyCheck.mpintScalar(new byte[] {0, (byte) 0x80}, 0, 2));
        assertEquals(BigInteger.valueOf(0x0102), KeyCheck.mpintScalar(new byte[] {1, 2}, 0, 2));
        assertEquals(BigInteger.ONE, KeyCheck.mpintScalar(new byte[] {1}, 0, 1));
    }

    @Test
    void refusesBadCommentsAndPadding() {
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEd(f -> f.comment = new byte[] {(byte) 0xff}));
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEd(f -> f.comment = "a\u001b[2Jb".getBytes(StandardCharsets.UTF_8)));
        // Bidi override, isolate, zero-width and line/paragraph separators would let a comment
        // reorder or hide what the terminal shows.
        for (String c : new String[] {"\u202e", "\u2066", "\u200b", "\u200f", "\u2028", "\u2029"}) {
            assertEquals(SshException.Code.MALFORMED_KEY,
                    refusedEd(f -> f.comment = ("gpj." + c + "exe").getBytes(StandardCharsets.UTF_8)), c);
        }
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEd(f -> f.comment = new byte[SshKey.MAX_COMMENT_BYTES + 1]));
        // Wrong padding bytes, padding that makes the section not a multiple of 8, and a full extra block.
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEd(f -> f.padding = padTo(f, (byte) 9)));
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEd(f -> f.padding = new byte[] {1}));
        assertEquals(SshException.Code.MALFORMED_KEY, refusedEd(f -> {
            byte[] std = padTo(f, (byte) 0);
            f.padding = new byte[std.length + 8];
            for (int i = 0; i < f.padding.length; i++) {
                f.padding[i] = (byte) (i + 1);
            }
        }));
    }

    /** Standard-length padding for {@code f}, with its last byte replaced by {@code last} if non-zero. */
    private static byte[] padTo(KeyFixtures.File f, byte last) {
        int unpadded = 8 + f.fields.length + 4 + f.comment.length;
        int n = (8 - unpadded % 8) % 8;
        byte[] p = new byte[n == 0 ? 8 : n];
        for (int i = 0; i < p.length; i++) {
            p[i] = (byte) (i + 1);
        }
        if (last != 0) {
            p[p.length - 1] = last;
        }
        return p;
    }

    @Test
    void acceptsAKeyThatNeedsNoPadding() throws SshException {
        // Find a comment length that makes the private section an exact multiple of 8.
        KeyFixtures.Ed k = KeyFixtures.ed25519();
        for (int extra = 0; extra < 8; extra++) {
            KeyFixtures.File f = KeyFixtures.File.of(k);
            f.comment = "c".repeat(extra).getBytes(StandardCharsets.US_ASCII);
            try (SshKey key = parse(f.text())) {
                assertEquals("c".repeat(extra), key.comment());
            }
        }
    }

    /** Fuzz property: no corruption of a valid file escapes as anything but {@link SshException}. */
    @Property(tries = 300)
    void anySingleByteCorruptionIsRefusedCleanlyOrStillValid(@ForAll @IntRange(min = 0, max = 10_000) int where,
            @ForAll @IntRange(min = 1, max = 255) int xor, @ForAll boolean ecdsa) {
        KeyFixtures.File f = ecdsa ? KeyFixtures.File.of(KeyFixtures.p256()) : KeyFixtures.File.of(KeyFixtures.ed25519());
        byte[] bin = f.binary();
        bin[where % bin.length] ^= (byte) xor;
        try (SshKey key = parse(KeyFixtures.armour(bin))) {
            // Only bytes the format does not check (comment text) can change and still parse.
            assertEquals(ecdsa ? SshKeyType.ECDSA_P256 : SshKeyType.ED25519, key.type());
        } catch (SshException e) {
            assertEquals(e.code().name(), e.getMessage());
        }
    }
}
