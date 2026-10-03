package pm.vault;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;
import pm.crypto.Hash;
import pm.crypto.Hmac;
import pm.crypto.Kdf;
import pm.crypto.SecretBytes;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;
import pm.vault.envelope.EnvelopeCodec;

/**
 * Backup file layout (ADR 0015):
 * {@code "PMBACKUP"(8) ‖ u16 version=1 ‖ u32 headerLen ‖ CBOR header ‖ vault file ‖
 * HMAC-SHA256(BK, everything before the tag)(32)}, where {@code BK = HKDF-SHA256(VK, mac_salt,
 * "pm/backup/v1", 32)} and the header is the deterministic map {@code {created, format_version,
 * vault_length, content_sha256, mac_salt}} with exactly those keys.
 *
 * <p>The vault file is embedded unchanged, so it stays encrypted and authenticated by its own
 * AES-GCM tag. The header adds a content hash that detects truncation and corruption without a
 * passphrase, and the HMAC binds the header to the vault key so that its fields cannot be edited.
 */
final class BackupFormat {

    /** Backup layout version, the only one written or read. */
    static final int VERSION = 1;
    static final int SALT_LENGTH = 32;
    /** Latest accepted creation time, 9999-12-31T23:59:59Z, so every value is a valid Instant. */
    static final long MAX_CREATED = 253_402_300_799L;

    private static final byte[] MAGIC = "PMBACKUP".getBytes(StandardCharsets.US_ASCII);
    private static final int PREFIX = MAGIC.length + Short.BYTES + Integer.BYTES;
    private static final int MAX_HEADER = 4096;
    private static final int MAX_U16 = 0xFFFF;
    private static final long U32_MASK = 0xFFFF_FFFFL;
    private static final byte[] MAC_INFO = "pm/backup/v1".getBytes(StandardCharsets.US_ASCII);
    private static final String K_CREATED = "created";
    private static final String K_FORMAT = "format_version";
    private static final String K_LENGTH = "vault_length";
    private static final String K_SHA256 = "content_sha256";
    private static final String K_SALT = "mac_salt";
    private static final Set<String> KEYS = Set.of(K_CREATED, K_FORMAT, K_LENGTH, K_SHA256, K_SALT);

    private BackupFormat() {
    }

    /**
     * The authenticated header. The byte strings are {@link CborValue.Bytes}, which copy in and
     * out (OBJ05-J).
     *
     * @param created       creation time, epoch seconds, 0 to {@link #MAX_CREATED}
     * @param formatVersion format version of the embedded vault file
     * @param vaultLength   length of the embedded vault file
     * @param contentSha256 SHA-256 of the embedded vault file
     * @param macSalt       HKDF salt of the backup MAC key
     */
    record Header(long created, int formatVersion, long vaultLength, CborValue.Bytes contentSha256,
                  CborValue.Bytes macSalt) {
        /** Validates ranges and lengths. */
        Header {
            if (created < 0 || created > MAX_CREATED || formatVersion < 0 || formatVersion > MAX_U16 || vaultLength < 0
                    || contentSha256.length() != Hash.SHA256_BYTES || macSalt.length() != SALT_LENGTH) {
                throw new IllegalArgumentException("header");
            }
        }

        /** Header for {@code vault} created at {@code created} with the given MAC salt. */
        static Header of(long created, byte[] vault, byte[] macSalt) throws VaultException {
            return new Header(created, EnvelopeCodec.peekVersion(vault), vault.length,
                    new CborValue.Bytes(Hash.sha256(vault)), new CborValue.Bytes(macSalt));
        }

        byte[] encode() {
            return CborWriter.encode(new CborValue.MapV(Map.of(
                    K_CREATED, new CborValue.UInt(created),
                    K_FORMAT, new CborValue.UInt(formatVersion),
                    K_LENGTH, new CborValue.UInt(vaultLength),
                    K_SHA256, contentSha256,
                    K_SALT, macSalt)), CborLimits.HEADER);
        }
    }

    /** A structurally valid backup whose content hash matches; the tag is not yet checked. */
    static final class Parsed {
        private final Header parsedHeader;
        private final byte[] file;
        private final int vaultStart;
        private final int tagStart;

        private Parsed(Header header, byte[] file, int vaultStart, int tagStart) {
            parsedHeader = header;
            this.file = file;
            this.vaultStart = vaultStart;
            this.tagStart = tagStart;
        }

        Header header() {
            return parsedHeader;
        }

        /** Returns a copy of the embedded vault file. */
        byte[] vault() {
            return Arrays.copyOfRange(file, vaultStart, tagStart);
        }

        /** Whether the tag is the HMAC of everything before it under the key derived from {@code vk}. */
        boolean tagValid(SecretBytes vk) throws VaultException {
            try (SecretBytes bk = macKey(vk, parsedHeader.macSalt().value())) {
                return Hmac.verify(bk, Arrays.copyOf(file, tagStart),
                        Arrays.copyOfRange(file, tagStart, file.length));
            } catch (CryptoException e) {
                throw new VaultException(VaultException.Code.CORRUPT, e);
            }
        }
    }

    /**
     * Builds a backup of {@code vault} under {@code vk}.
     *
     * @param header header describing {@code vault}
     * @param vault  the saved vault file
     * @param vk     vault key; not closed
     * @return the complete backup file
     * @throws VaultException {@code CORRUPT} if a crypto primitive fails
     */
    static byte[] assemble(Header header, byte[] vault, SecretBytes vk) throws VaultException {
        Objects.requireNonNull(vault, "vault");
        if (header.vaultLength() != vault.length) {
            throw new IllegalArgumentException("vault length");
        }
        byte[] headerCbor = header.encode();
        int bodyLength = Math.addExact(Math.addExact(PREFIX, headerCbor.length), vault.length);
        ByteBuffer out = ByteBuffer.allocate(Math.addExact(bodyLength, Hmac.TAG_BYTES));
        out.put(MAGIC).putShort((short) VERSION).putInt(headerCbor.length).put(headerCbor).put(vault);
        try (SecretBytes bk = macKey(vk, header.macSalt().value())) {
            out.put(Hmac.sha256(bk, Arrays.copyOf(out.array(), bodyLength)));
        } catch (CryptoException e) {
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
        return out.array();
    }

    /**
     * Checks the framing, the header and the content hash; the tag needs the key and is checked
     * by {@link Parsed#tagValid}.
     *
     * @param file the backup file; retained, so the caller must not change it
     * @return the parsed backup
     * @throws VaultException {@code UNSUPPORTED_VERSION} for a newer backup layout, otherwise
     *                        {@code CORRUPT}
     */
    static Parsed parse(byte[] file) throws VaultException {
        Objects.requireNonNull(file, "file");
        if (file.length < PREFIX + Hmac.TAG_BYTES || !ConstantTime.equals(Arrays.copyOf(file, MAGIC.length), MAGIC)) {
            throw corrupt();
        }
        ByteBuffer in = ByteBuffer.wrap(file);
        int version = Short.toUnsignedInt(in.getShort(MAGIC.length));
        if (version > VERSION) {
            throw new VaultException(VaultException.Code.UNSUPPORTED_VERSION, null);
        }
        long headerLength = in.getInt(MAGIC.length + Short.BYTES) & U32_MASK;
        if (version != VERSION || headerLength == 0 || headerLength > MAX_HEADER
                || PREFIX + headerLength + Hmac.TAG_BYTES > file.length) {
            throw corrupt();
        }
        int vaultStart = PREFIX + (int) headerLength;
        Header header = decodeHeader(Arrays.copyOfRange(file, PREFIX, vaultStart));
        int tagStart = file.length - Hmac.TAG_BYTES;
        if (header.vaultLength() != tagStart - vaultStart) {
            throw corrupt();
        }
        byte[] vault = Arrays.copyOfRange(file, vaultStart, tagStart);
        if (!ConstantTime.equals(Hash.sha256(vault), header.contentSha256().value())
                || EnvelopeCodec.peekVersion(vault) != header.formatVersion()) {
            throw corrupt();
        }
        return new Parsed(header, file, vaultStart, tagStart);
    }

    private static Header decodeHeader(byte[] cbor) throws VaultException {
        CborValue root;
        try {
            root = CborReader.decode(cbor, CborLimits.HEADER);
        } catch (CborException e) {
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
        if (!(root instanceof CborValue.MapV map) || map.entries().size() != KEYS.size()
                || !map.entries().keySet().containsAll(KEYS)) {
            throw corrupt();
        }
        Map<String, CborValue> m = map.entries();
        if (m.get(K_CREATED) instanceof CborValue.UInt created && created.value() <= MAX_CREATED
                && m.get(K_FORMAT) instanceof CborValue.UInt format && format.value() <= MAX_U16
                && m.get(K_LENGTH) instanceof CborValue.UInt length
                && m.get(K_SHA256) instanceof CborValue.Bytes sha && sha.length() == Hash.SHA256_BYTES
                && m.get(K_SALT) instanceof CborValue.Bytes salt && salt.length() == SALT_LENGTH) {
            return new Header(created.value(), (int) format.value(), length.value(), sha, salt);
        }
        throw corrupt();
    }

    private static SecretBytes macKey(SecretBytes vk, byte[] salt) throws CryptoException {
        return Kdf.hkdfSha256(vk, salt, MAC_INFO, Vault.KEY_LENGTH);
    }

    private static VaultException corrupt() {
        return new VaultException(VaultException.Code.CORRUPT, null);
    }
}
