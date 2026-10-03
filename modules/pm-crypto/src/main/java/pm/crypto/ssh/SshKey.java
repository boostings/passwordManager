package pm.crypto.ssh;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import pm.crypto.ConstantTime;
import pm.crypto.Hash;
import pm.crypto.SecretBytes;

/**
 * A parsed SSH private key (ADR 0013): its type, public key blob and comment are public; the
 * private fields stay in a {@link SecretBytes} owned by this object and are only ever written to
 * an agent socket ({@link SshAgentClient#add}) or an owner-only file ({@link SshKeyExport}). No
 * method returns private key bytes (TM-61, SR-060).
 *
 * <p>The private fields are kept exactly as the agent protocol and the {@code openssh-key-v1}
 * private section both encode them: {@code string type} followed by the type's key fields
 * (draft-miller-ssh-agent §3.2.3, PROTOCOL.key). Not thread-safe; close it when done.
 */
public final class SshKey implements AutoCloseable {
    /** Largest key file accepted, the vault's per-secret limit. */
    public static final int MAX_FILE_BYTES = 64 * 1024;
    /** Largest comment accepted. */
    public static final int MAX_COMMENT_BYTES = 4096;
    /** Largest public key blob accepted from a file or an agent. */
    static final int MAX_BLOB_BYTES = 16 * 1024;
    /** Largest algorithm or curve name. */
    static final int MAX_NAME_BYTES = 64;
    static final int ED25519_PUBLIC_BYTES = 32;
    static final int ED25519_PRIVATE_BYTES = 64;
    static final String NISTP256 = "nistp256";
    /** openssh-key-v1 private sections are padded to this block size when unencrypted. */
    static final int BLOCK = 8;

    private final SshKeyType keyType;
    private final byte[] publicBlob;
    private final String commentText;
    private final SecretBytes fields;

    private SshKey(SshKeyType type, byte[] publicBlob, String comment, SecretBytes fields) {
        this.keyType = type;
        this.publicBlob = publicBlob;
        this.commentText = comment;
        this.fields = fields;
    }

    /**
     * Parses an unencrypted OpenSSH private key file (armoured as {@code BEGIN OPENSSH PRIVATE KEY}),
     * as stored in a vault SSH key record. The caller keeps ownership of {@code file}.
     *
     * @throws SshException {@code ENCRYPTED_KEY} for a passphrase-protected key,
     *     {@code UNSUPPORTED_KEY} for an algorithm other than Ed25519 or ECDSA P-256, and
     *     {@code MALFORMED_KEY} for anything else that is not exactly a valid key
     */
    public static SshKey parse(SecretBytes file) throws SshException {
        Objects.requireNonNull(file, "file");
        byte[] text = file.apply(byte[]::clone);
        try {
            return OpenSshFormat.decode(text);
        } finally {
            Arrays.fill(text, (byte) 0);
        }
    }

    /**
     * Reads the private fields, comment and padding of an unencrypted private section (after its
     * two check integers) and checks them against {@code publicBlob}. {@code buf} backs {@code p}.
     */
    static SshKey read(WireReader p, byte[] buf, byte[] publicBlob) throws SshException {
        int fieldsStart = p.position();
        SshKeyType type = SshKeyType.fromWireName(ascii(p.string(MAX_NAME_BYTES)));
        byte[] derived = type == SshKeyType.ED25519 ? readEd25519(p, buf) : readEcdsaP256(p, buf);
        int fieldsEnd = p.position();
        String comment = comment(p.string(MAX_COMMENT_BYTES), SshException.Code.MALFORMED_KEY);
        int pad = p.remaining();
        if (pad >= BLOCK) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        for (int i = 1; i <= pad; i++) {
            if (p.u8() != i) {
                throw new SshException(SshException.Code.MALFORMED_KEY);
            }
        }
        if (!ConstantTime.equals(publicBlob, derived)) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        return new SshKey(type, publicBlob.clone(), comment,
                SecretBytes.takeOwnership(Arrays.copyOfRange(buf, fieldsStart, fieldsEnd)));
    }

    private static byte[] readEd25519(WireReader p, byte[] buf) throws SshException {
        int pubAt = p.fixedString(ED25519_PUBLIC_BYTES);
        int privAt = p.fixedString(ED25519_PRIVATE_BYTES);
        byte[] pub = Arrays.copyOfRange(buf, pubAt, pubAt + ED25519_PUBLIC_BYTES);
        // PROTOCOL.key: the 64-byte private half is seed || public key.
        byte[] tail = Arrays.copyOfRange(buf, privAt + KeyCheck.ED25519_SEED_BYTES, privAt + ED25519_PRIVATE_BYTES);
        if (!ConstantTime.equals(pub, tail)) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        KeyCheck.ed25519(buf, privAt, pub);
        try (WireWriter w = new WireWriter()) {
            w.string(SshKeyType.ED25519.wireName());
            w.string(pub);
            return w.toBytes();
        }
    }

    private static byte[] readEcdsaP256(WireReader p, byte[] buf) throws SshException {
        if (!NISTP256.equals(ascii(p.string(MAX_NAME_BYTES)))) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        int qAt = p.fixedString(KeyCheck.P256_POINT_BYTES);
        if (buf[qAt] != KeyCheck.UNCOMPRESSED) {
            throw new SshException(SshException.Code.MALFORMED_KEY);
        }
        byte[] q = Arrays.copyOfRange(buf, qAt, qAt + KeyCheck.P256_POINT_BYTES);
        int dAt = p.skipString(KeyCheck.P256_MPINT_MAX);
        KeyCheck.ecdsaP256(q, KeyCheck.mpintScalar(buf, dAt, p.position() - dAt));
        try (WireWriter w = new WireWriter()) {
            w.string(SshKeyType.ECDSA_P256.wireName());
            w.string(NISTP256);
            w.string(q);
            return w.toBytes();
        }
    }

    /**
     * A comment decoded as strict UTF-8 with no character {@link #unsafeToShow}, so it can be shown
     * in a terminal without carrying escape sequences or reordering text.
     */
    static String comment(byte[] raw, SshException.Code onError) throws SshException {
        try {
            String s = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw)).toString();
            if (s.codePoints().anyMatch(SshKey::unsafeToShow)) {
                throw new SshException(onError);
            }
            return s;
        } catch (CharacterCodingException e) {
            throw new SshException(onError);
        }
    }

    /**
     * Whether a code point must not reach a terminal from untrusted text: C0/C1 controls, format
     * characters (category Cf: bidi overrides and isolates such as U+202E and U+2066 to U+2069,
     * zero-width characters U+200B to U+200F) and line or paragraph separators (U+2028, U+2029).
     */
    static boolean unsafeToShow(int c) {
        int t = Character.getType(c);
        return Character.isISOControl(c) || t == Character.FORMAT
                || t == Character.LINE_SEPARATOR || t == Character.PARAGRAPH_SEPARATOR;
    }

    static String ascii(byte[] b) {
        return new String(b, StandardCharsets.US_ASCII);
    }

    /** {@code SHA256:} and the unpadded base64 SHA-256 of {@code blob}, as {@code ssh-keygen -l} prints it. */
    static String fingerprint(byte[] blob) {
        return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(Hash.sha256(blob));
    }

    /** The key algorithm. */
    public SshKeyType type() {
        return keyType;
    }

    /** The comment, possibly empty. */
    public String comment() {
        return commentText;
    }

    /** A copy of the public key blob (RFC 4253 §6.6), as an agent lists it. */
    public byte[] publicKeyBlob() {
        return publicBlob.clone();
    }

    /** The {@code SHA256:} fingerprint. */
    public String fingerprint() {
        return fingerprint(publicBlob);
    }

    /** The {@code authorized_keys} / {@code .pub} line: type, base64 blob and comment if any. */
    public String publicKeyLine() {
        String line = keyType.wireName() + " " + Base64.getEncoder().encodeToString(publicBlob);
        return commentText.isEmpty() ? line : line + " " + commentText;
    }

    /** Appends the private fields to {@code w}; package-private so the bytes stay in this package. */
    void writeFields(WireWriter w) {
        fields.withBytes(w::raw);
    }

    /** Whether {@link #close()} has run. */
    public boolean isClosed() {
        return fields.isClosed();
    }

    /** Zero-fills the private fields. Idempotent. */
    @Override
    public void close() {
        fields.close();
    }

    @Override
    public String toString() {
        return "SshKey[" + keyType.wireName() + " " + fingerprint() + "]";
    }
}
