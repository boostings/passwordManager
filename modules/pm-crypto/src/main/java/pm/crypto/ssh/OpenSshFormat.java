package pm.crypto.ssh;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import pm.crypto.ConstantTime;
import pm.crypto.Csprng;
import pm.crypto.SecretBytes;

/**
 * The OpenSSH private key file format, {@code openssh-key-v1} (OpenSSH {@code PROTOCOL.key}),
 * unencrypted only (ADR 0013): armour, base64, then
 * <pre>
 * "openssh-key-v1\0" string cipher ("none") string kdf ("none") string kdfoptions ("")
 * uint32 1  string publickey  string private-section
 * private-section = uint32 check, uint32 check, key fields, string comment, padding 1, 2, 3 ...
 * </pre>
 * Every intermediate buffer that holds private key bytes, including the base64 text, is
 * zero-filled before it is dropped.
 */
final class OpenSshFormat {
    // Built from pieces so the source never holds a literal key-armour block that secret scanners
    // (gitleaks private-key) would match across the two lines.
    private static final String LABEL = "OPENSSH " + "PRIVATE " + "KEY";
    private static final String DASHES = "-----";
    static final String BEGIN = DASHES + "BEGIN " + LABEL + DASHES;
    static final String END = DASHES + "END " + LABEL + DASHES;
    static final byte[] MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII);
    static final String NONE = "none";
    /**
     * Base64 body line length on export. ssh-keygen wraps at 70 columns, but the JDK MIME encoder
     * rounds a line length down to a multiple of 4, so 68 is what it can produce; OpenSSH reads
     * any line length, and so does {@link #decode}.
     */
    static final int LINE = 68;
    private static final byte[] BEGIN_BYTES = BEGIN.getBytes(StandardCharsets.US_ASCII);
    private static final byte[] END_BYTES = END.getBytes(StandardCharsets.US_ASCII);
    private static final byte[] NEWLINE = {'\n'};
    private static final int CHECK_BYTES = 4;
    private static final int MAX_KDF_OPTIONS = 1024;

    private OpenSshFormat() {
    }

    /** Parses armoured key file text. Never modifies {@code text}. */
    static SshKey decode(byte[] text) throws SshException {
        if (text.length > SshKey.MAX_FILE_BYTES) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        byte[] bin = dearmour(text);
        try {
            return decodeBinary(bin);
        } finally {
            Arrays.fill(bin, (byte) 0);
        }
    }

    private static byte[] dearmour(byte[] text) throws SshException {
        int body = BEGIN_BYTES.length;
        if (!startsWith(text, 0, BEGIN_BYTES) || body >= text.length || !isNewline(text[body])) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        // The END line must start a line (end > body, since text[body] is a line break).
        int end = indexOf(text, body, END_BYTES);
        if (end < 0 || !isNewline(text[end - 1])) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        for (int i = end + END_BYTES.length; i < text.length; i++) {
            if (!isNewline(text[i])) {
                throw new SshException(SshException.Code.MALFORMED_KEY);
            }
        }
        byte[] b64 = new byte[end - body];
        int n = 0;
        for (int i = body; i < end; i++) {
            if (!isNewline(text[i])) {
                b64[n++] = text[i];
            }
        }
        byte[] exact = Arrays.copyOf(b64, n);
        Arrays.fill(b64, (byte) 0);
        try {
            return strictBase64(exact);
        } finally {
            Arrays.fill(exact, (byte) 0);
        }
    }

    /**
     * Strict base64 (ADR 0013): the JDK decoder also takes a body without its {@code =} padding and
     * non-zero unused bits before the padding, which OpenSSH's {@code b64_pton} refuses. So the
     * binary is re-encoded and must give back exactly the text it came from: one encoding per key.
     */
    private static byte[] strictBase64(byte[] b64) throws SshException {
        byte[] bin;
        try {
            bin = Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        byte[] canonical = Base64.getEncoder().encode(bin);
        boolean strict = ConstantTime.equals(canonical, b64);
        Arrays.fill(canonical, (byte) 0);
        if (!strict) {
            Arrays.fill(bin, (byte) 0);
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        return bin;
    }

    static SshKey decodeBinary(byte[] bin) throws SshException {
        if (!startsWith(bin, 0, MAGIC)) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        WireReader r = WireReader.over(bin, MAGIC.length, bin.length, SshException.Code.MALFORMED_KEY);
        String cipher = SshKey.ascii(r.string(SshKey.MAX_NAME_BYTES));
        String kdf = SshKey.ascii(r.string(SshKey.MAX_NAME_BYTES));
        byte[] kdfOptions = r.string(MAX_KDF_OPTIONS);
        if (!NONE.equals(cipher)) {
            // bcrypt-pbkdf + aes256-ctr and friends: refused, not decrypted (ADR 0013).
            throw new SshException(SshException.Code.ENCRYPTED_KEY);
        }
        if (!NONE.equals(kdf) || kdfOptions.length != 0 || r.u32() != 1) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        byte[] publicBlob = r.string(SshKey.MAX_BLOB_BYTES);
        int start = r.skipString(SshKey.MAX_FILE_BYTES);
        int end = r.position();
        r.expectEnd();
        if ((end - start) % SshKey.BLOCK != 0) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        WireReader p = WireReader.over(bin, start, end, SshException.Code.MALFORMED_KEY);
        long check1 = p.u32();
        long check2 = p.u32();
        if (check1 != check2) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        return SshKey.read(p, bin, publicBlob);
    }

    /** The armoured, unencrypted key file for {@code key}, with fresh random check integers. */
    static SecretBytes encode(SshKey key) {
        long check = Integer.toUnsignedLong(ByteBuffer.wrap(Csprng.bytes(CHECK_BYTES)).getInt());
        try (WireWriter outer = new WireWriter()) {
            outer.raw(MAGIC);
            outer.string(NONE);
            outer.string(NONE);
            outer.u32(0);
            outer.u32(1);
            outer.string(key.publicKeyBlob());
            try (WireWriter priv = new WireWriter()) {
                priv.u32(check);
                priv.u32(check);
                key.writeFields(priv);
                priv.string(key.comment().getBytes(StandardCharsets.UTF_8));
                for (int pad = 1; priv.length() % SshKey.BLOCK != 0; pad++) {
                    priv.u8(pad);
                }
                outer.u32(priv.length());
                priv.writeTo(outer);
            }
            return armour(outer);
        }
    }

    private static SecretBytes armour(WireWriter outer) {
        byte[] bin = outer.toBytes();
        try {
            byte[] b64 = Base64.getMimeEncoder(LINE, NEWLINE).encode(bin);
            try (WireWriter text = new WireWriter()) {
                text.raw(BEGIN_BYTES);
                text.raw(NEWLINE);
                text.raw(b64);
                text.raw(NEWLINE);
                text.raw(END_BYTES);
                text.raw(NEWLINE);
                return text.toSecret();
            } finally {
                Arrays.fill(b64, (byte) 0);
            }
        } finally {
            Arrays.fill(bin, (byte) 0);
        }
    }

    private static boolean isNewline(byte b) {
        return b == '\n' || b == '\r';
    }

    private static boolean startsWith(byte[] a, int from, byte[] prefix) {
        return a.length - from >= prefix.length
                && Arrays.equals(a, from, from + prefix.length, prefix, 0, prefix.length);
    }

    private static int indexOf(byte[] a, int from, byte[] needle) {
        for (int i = from; i <= a.length - needle.length; i++) {
            if (startsWith(a, i, needle)) {
                return i;
            }
        }
        return -1;
    }
}
