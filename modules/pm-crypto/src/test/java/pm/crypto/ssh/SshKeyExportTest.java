package pm.crypto.ssh;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.SecretBytes;

/**
 * The explicit export fallback (ADR 0013, SR-063): an OpenSSH private key file created new, owner
 * read/write only, never through a link, that parses back to the same key.
 */
class SshKeyExportTest {
    @TempDir
    Path tmp;

    private static SshKey key(KeyFixtures.File f) throws SshException {
        try (SecretBytes s = f.secret()) {
            return SshKey.parse(s);
        }
    }

    private static SshKey reread(Path p) throws IOException, SshException {
        try (SecretBytes s = SecretBytes.takeOwnership(Files.readAllBytes(p))) {
            return SshKey.parse(s);
        }
    }

    @Test
    void writesAnOwnerOnlyFileThatParsesBack() throws IOException, SshException {
        // Comments of every length mod 8, so the private section needs every amount of padding.
        for (int extra = 0; extra < 8; extra++) {
            KeyFixtures.File f = extra % 2 == 0
                    ? KeyFixtures.File.of(KeyFixtures.ed25519()) : KeyFixtures.File.of(KeyFixtures.p256());
            f.comment = "c".repeat(extra).getBytes(StandardCharsets.US_ASCII);
            Path out = tmp.resolve("id" + extra);
            try (SshKey k = key(f)) {
                SshKeyExport.write(k, out);
                assertEquals("rw-------", PosixFilePermissions.toString(
                        Files.getPosixFilePermissions(out, LinkOption.NOFOLLOW_LINKS)));
                try (SshKey back = reread(out)) {
                    assertEquals(k.type(), back.type());
                    assertEquals(k.comment(), back.comment());
                    assertArrayEquals(k.publicKeyBlob(), back.publicKeyBlob());
                    try (WireWriter a = new WireWriter(); WireWriter b = new WireWriter()) {
                        k.writeFields(a);
                        back.writeFields(b);
                        assertArrayEquals(a.toBytes(), b.toBytes());
                    }
                }
            }
        }
    }

    @Test
    void neverOverwritesOrFollowsALink() throws IOException, SshException {
        try (SshKey k = key(KeyFixtures.File.of(KeyFixtures.ed25519()))) {
            Path existing = Files.writeString(tmp.resolve("existing"), "keep");
            assertEquals(SshException.Code.TARGET_EXISTS,
                    assertThrows(SshException.class, () -> SshKeyExport.write(k, existing)).code());
            assertEquals("keep", Files.readString(existing));
            Path dangling = Files.createSymbolicLink(tmp.resolve("link"), tmp.resolve("elsewhere"));
            assertEquals(SshException.Code.TARGET_EXISTS,
                    assertThrows(SshException.class, () -> SshKeyExport.write(k, dangling)).code());
            assertFalse(Files.exists(tmp.resolve("elsewhere"), LinkOption.NOFOLLOW_LINKS));
            assertEquals(SshException.Code.IO, assertThrows(SshException.class,
                    () -> SshKeyExport.write(k, tmp.resolve("no").resolve("such"))).code());
        }
    }

    @Test
    void aFailedWriteLeavesNoPartialFile() throws SshException {
        Path out = tmp.resolve("id");
        try (SshKey k = key(KeyFixtures.File.of(KeyFixtures.ed25519()))) {
            SshException e = assertThrows(SshException.class, () -> SshKeyExport.write(k, out, (ch, text) -> {
                ch.write(ByteBuffer.wrap(new byte[10]));
                throw new IOException("disk full");
            }));
            assertEquals(SshException.Code.IO, e.code());
        }
        assertFalse(Files.exists(out, LinkOption.NOFOLLOW_LINKS));
    }

    @Test
    void aClosedKeyCreatesNoFile() throws SshException {
        Path out = tmp.resolve("id");
        try (SshKey k = key(KeyFixtures.File.of(KeyFixtures.ed25519()))) {
            SshKeyTest.shut(k);
            assertThrows(IllegalStateException.class, () -> SshKeyExport.write(k, out));
        }
        assertFalse(Files.exists(out, LinkOption.NOFOLLOW_LINKS));
    }
}
