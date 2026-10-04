package pm.vault.record;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import pm.crypto.DeviceIdentity;
import pm.crypto.SecretBytes;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/**
 * Hand-written codec between the record model and the vault's plaintext payload (ADR 0006,
 * schema in {@code docs/schemas/records.cddl}):
 * {@code {"schema_version": 1, "records": [record, ...]}} in deterministic CBOR.
 *
 * <p><b>All or nothing (SR-021).</b> {@link #decodePayload} returns every record or throws
 * {@link RecordException}. Whatever goes wrong, every record and every secret built up to that
 * point is closed and nothing is returned, so corrupted input never yields a partial record.
 *
 * <p><b>Symmetry.</b> {@link #encodePayload} writes under {@link CborLimits#PAYLOAD} and the record
 * constructors bound every field, so a payload this class writes is always one it can read back.
 *
 * <p><b>Secrets (ADR 0008, SR-505).</b> A secret field is a CBOR byte string and never becomes a
 * {@code String}. Encoding and decoding copy secrets into intermediate arrays: the {@link CborValue}
 * tree, the writer's working buffer and the encoded result before it is wrapped. Each of those
 * copies is zero-filled before the method returns, on success and on failure. This is best effort
 * only: the JVM may have moved or copied an array before it was cleared (risk R-003).
 *
 * <p>Unknown keys are ignored on read for forward compatibility (ADR 0006) and are not written
 * back. Exception messages are fixed text and never contain payload content (SR-501, ERR01-J).
 */
public final class RecordCodec {
    /** The only payload schema version this codec reads and writes. */
    public static final int SCHEMA_VERSION = 1;

    private static final String K_SCHEMA_VERSION = "schema_version";
    private static final String K_RECORDS = "records";
    private static final String K_TYPE = "type";
    private static final String K_ID = "id";
    private static final String K_TITLE = "title";
    private static final String K_CREATED = "created";
    private static final String K_UPDATED = "updated";
    private static final String K_USERNAME = "username";
    private static final String K_PASSWORD = "password";
    private static final String K_URLS = "urls";
    private static final String K_NOTES = "notes";
    private static final String K_TAGS = "tags";
    private static final String K_LAST_USED = "last_used";
    private static final String K_SSID = "ssid";
    private static final String K_SECURITY = "security";
    private static final String K_HIDDEN = "hidden";
    private static final String K_KEY_TYPE = "key_type";
    private static final String K_PRIVATE_KEY = "private_key";
    private static final String K_PUBLIC_KEY = "public_key";
    private static final String K_FINGERPRINT = "fingerprint";
    private static final String K_COMMENT = "comment";
    private static final String K_HOSTS = "hosts";
    private static final String K_CANONICAL_PATH = "canonical_path";
    private static final String K_GIT_REMOTE = "git_remote";
    private static final String K_VARIABLES = "variables";
    private static final String K_CONFIG = "config";
    private static final String K_CERTIFICATE = "certificate";
    private static final String K_SHARED = "shared";
    private static final String K_RECEIVED = "received";
    private static final Pattern RECEIVED_ENTRY =
            Pattern.compile("([0-9a-f]{32})@(0|[1-9][0-9]{0,11})");

    private static final String T_LOGIN = "login";
    private static final String T_WIFI = "wifi";
    private static final String T_SSH_KEY = "ssh_key";
    private static final String T_PROJECT = "project";
    private static final String T_DEVICE_IDENTITY = "device_identity";
    private static final String T_TRUSTED_DEVICE = "trusted_device";

    /** The canonical text form of a UUID: lower-case hex in groups of 8-4-4-4-12. */
    private static final Pattern CANONICAL_UUID =
            Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private RecordCodec() {
    }

    /**
     * Encodes {@code records} as the vault payload. The records are not closed and stay owned by
     * the caller.
     *
     * @param records the records to store; their ids must be distinct
     * @return the plaintext payload; the caller closes it
     * @throws IllegalArgumentException if two records share an id, or the payload would exceed
     *     {@link CborLimits#PAYLOAD} (more than 1,000,000 data items or 256 MiB); nothing is
     *     returned
     * @throws IllegalStateException if a record's secret is already closed
     */
    public static SecretBytes encodePayload(List<VaultRecord> records) {
        Objects.requireNonNull(records, "records");
        if (records.stream().map(VaultRecord::id).distinct().count() != records.size()) {
            throw new IllegalArgumentException("duplicate record id");
        }
        List<CborValue> items = new ArrayList<>(records.size());
        try {
            records.stream().map(RecordCodec::encodeRecord).forEach(items::add);
            CborValue root = new CborValue.MapV(Map.of(
                    K_SCHEMA_VERSION, new CborValue.UInt(SCHEMA_VERSION),
                    K_RECORDS, new CborValue.Array(items)));
            // takeOwnership copies the encoding and zero-fills the array the writer returned.
            return SecretBytes.takeOwnership(CborWriter.encode(root, CborLimits.PAYLOAD));
        } finally {
            items.forEach(CborValue::wipe);
        }
    }

    /**
     * Decodes a payload that has already been authenticated (SR-020). All or nothing: see the class
     * comment.
     *
     * @param plaintext the payload; not closed, the caller keeps ownership
     * @return every record in the payload, in payload order; the caller owns and closes them
     * @throws RecordException {@code MALFORMED} if the bytes are not deterministic CBOR,
     *     {@code LIMIT} if a bound is exceeded, {@code SCHEMA} if the content does not match
     *     {@code records.cddl} (wrong {@code schema_version}, missing or mistyped field, unknown
     *     record type, duplicate or non-canonical id, field out of bounds)
     * @throws IllegalStateException if {@code plaintext} is closed
     */
    public static List<VaultRecord> decodePayload(SecretBytes plaintext) throws RecordException {
        Objects.requireNonNull(plaintext, "plaintext");
        AtomicReference<RecordException> rejection = new AtomicReference<>();
        List<VaultRecord> records = plaintext.apply(bytes -> {
            try {
                return decodeBytes(bytes);
            } catch (RecordException e) {
                rejection.set(e);
                return List.of();
            }
        });
        RecordException rejected = rejection.get();
        if (rejected != null) {
            throw rejected;
        }
        return records;
    }

    // ---- decode -------------------------------------------------------------------------------

    private static List<VaultRecord> decodeBytes(byte[] plaintext) throws RecordException {
        CborValue root;
        try {
            root = CborReader.decode(plaintext, CborLimits.PAYLOAD);
        } catch (CborException e) {
            RecordException.Code code = e.code() == CborException.Code.LIMIT
                    ? RecordException.Code.LIMIT : RecordException.Code.MALFORMED;
            throw new RecordException(code, "payload is not valid deterministic CBOR", e);
        }
        try {
            return decodeRoot(root);
        } finally {
            // The tree still holds a copy of every secret byte string.
            root.wipe();
        }
    }

    private static List<VaultRecord> decodeRoot(CborValue root) throws RecordException {
        Map<String, CborValue> top = mapOf(root);
        if (uint(top, K_SCHEMA_VERSION) != SCHEMA_VERSION) {
            throw schema("unsupported schema_version");
        }
        if (!(top.get(K_RECORDS) instanceof CborValue.Array array)) {
            throw schema("records is missing or not an array");
        }
        List<VaultRecord> decoded = new ArrayList<>();
        Set<UUID> ids = new HashSet<>();
        boolean complete = false;
        try {
            for (CborValue item : array.items()) {
                decoded.add(decodeRecord(item, ids));
            }
            List<VaultRecord> result = List.copyOf(decoded);
            complete = true;
            return result;
        } finally {
            if (!complete) {
                decoded.forEach(VaultRecord::close);
            }
        }
    }

    private static VaultRecord decodeRecord(CborValue item, Set<UUID> ids) throws RecordException {
        Map<String, CborValue> fields = mapOf(item);
        String type = text(fields, K_TYPE);
        UUID id = uuid(fields);
        if (!ids.add(id)) {
            throw schema("duplicate record id");
        }
        try (Pending pending = new Pending()) {
            return pending.commit(switch (type) {
                case T_LOGIN -> decodeLogin(id, fields, pending);
                case T_WIFI -> decodeWifi(id, fields, pending);
                case T_SSH_KEY -> decodeSshKey(id, fields, pending);
                case T_PROJECT -> decodeProject(id, fields, pending);
                case T_DEVICE_IDENTITY -> decodeDeviceIdentity(id, fields, pending);
                case T_TRUSTED_DEVICE -> decodeTrustedDevice(id, fields);
                default -> throw schema("unknown record type");
            });
        } catch (IllegalArgumentException e) {
            // A record constructor refused a field; its message names the field, not the content.
            throw new RecordException(RecordException.Code.SCHEMA, "record field is out of bounds", e);
        }
    }

    private static VaultRecord decodeLogin(UUID id, Map<String, CborValue> fields, Pending pending)
            throws RecordException {
        return new LoginRecord(id, text(fields, K_TITLE), text(fields, K_USERNAME),
                pending.own(bytes(fields, K_PASSWORD)), texts(fields, K_URLS), text(fields, K_NOTES),
                texts(fields, K_TAGS), instant(fields, K_CREATED), instant(fields, K_UPDATED),
                instant(fields, K_LAST_USED));
    }

    private static VaultRecord decodeWifi(UUID id, Map<String, CborValue> fields, Pending pending)
            throws RecordException {
        return new WifiRecord(id, text(fields, K_TITLE), text(fields, K_SSID), text(fields, K_SECURITY),
                pending.own(bytes(fields, K_PASSWORD)), bool(fields, K_HIDDEN), text(fields, K_NOTES),
                instant(fields, K_CREATED), instant(fields, K_UPDATED));
    }

    private static VaultRecord decodeSshKey(UUID id, Map<String, CborValue> fields, Pending pending)
            throws RecordException {
        return new SshKeyRecord(id, text(fields, K_TITLE), text(fields, K_KEY_TYPE),
                pending.own(bytes(fields, K_PRIVATE_KEY)), text(fields, K_PUBLIC_KEY),
                text(fields, K_FINGERPRINT), text(fields, K_COMMENT), texts(fields, K_HOSTS),
                instant(fields, K_CREATED), instant(fields, K_UPDATED));
    }

    private static VaultRecord decodeProject(UUID id, Map<String, CborValue> fields, Pending pending)
            throws RecordException {
        Map<String, SecretBytes> variables = new HashMap<>();
        for (Map.Entry<String, CborValue> entry : mapOf(fields.get(K_VARIABLES)).entrySet()) {
            variables.put(entry.getKey(), pending.own(bytesOf(entry.getValue())));
        }
        Map<String, String> config = new HashMap<>();
        for (Map.Entry<String, CborValue> entry : mapOf(fields.get(K_CONFIG)).entrySet()) {
            config.put(entry.getKey(), textOf(entry.getValue()));
        }
        return new ProjectRecord(id, text(fields, K_TITLE), text(fields, K_CANONICAL_PATH),
                text(fields, K_GIT_REMOTE), variables, config,
                instant(fields, K_CREATED), instant(fields, K_UPDATED));
    }

    private static VaultRecord decodeDeviceIdentity(UUID id, Map<String, CborValue> fields, Pending pending)
            throws RecordException {
        byte[] certificate = bytes(fields, K_CERTIFICATE);
        return new DeviceIdentityRecord(id, text(fields, K_TITLE), pending.own(bytes(fields, K_PRIVATE_KEY)),
                Base64.getEncoder().encodeToString(certificate), instant(fields, K_CREATED),
                instant(fields, K_UPDATED));
    }

    private static VaultRecord decodeTrustedDevice(UUID id, Map<String, CborValue> fields)
            throws RecordException {
        byte[] raw = bytes(fields, K_PUBLIC_KEY);
        if (raw.length != DeviceIdentity.PUBLIC_KEY_BYTES) {
            throw schema("public_key is not a raw Ed25519 key");
        }
        return new TrustedDeviceRecord(id, text(fields, K_TITLE), HexFormat.of().formatHex(raw),
                text(fields, K_FINGERPRINT), uuids(fields, K_SHARED), received(fields), instant(fields, K_CREATED),
                instant(fields, K_UPDATED));
    }

    /** {@code received}: entries {@code <32 hex>@<epoch seconds>}. */
    private static List<TrustedDeviceRecord.Received> received(Map<String, CborValue> fields)
            throws RecordException {
        List<TrustedDeviceRecord.Received> entries = new ArrayList<>();
        for (String text : texts(fields, K_RECEIVED)) {
            Matcher m = RECEIVED_ENTRY.matcher(text);
            if (!m.matches()) {
                throw schema("received entry is not <share id>@<seconds>");
            }
            entries.add(new TrustedDeviceRecord.Received(m.group(1),
                    Instant.ofEpochSecond(Long.parseLong(m.group(2)))));
        }
        return entries;
    }

    private static List<UUID> uuids(Map<String, CborValue> fields, String key) throws RecordException {
        List<UUID> ids = new ArrayList<>();
        for (String text : texts(fields, key)) {
            if (!CANONICAL_UUID.matcher(text).matches()) {
                throw schema("id is not a canonical UUID");
            }
            ids.add(UUID.fromString(text));
        }
        return ids;
    }

    /** Accepts only the canonical text form, exactly as {@link UUID#toString} writes it. */
    private static UUID uuid(Map<String, CborValue> fields) throws RecordException {
        String text = text(fields, K_ID);
        if (!CANONICAL_UUID.matcher(text).matches()) {
            throw schema("id is not a canonical UUID");
        }
        return UUID.fromString(text);
    }

    private static Instant instant(Map<String, CborValue> fields, String key) throws RecordException {
        long seconds = uint(fields, key);
        if (seconds > FieldRules.MAX_EPOCH_SECOND) {
            throw new RecordException(RecordException.Code.LIMIT, "timestamp is out of range");
        }
        return Instant.ofEpochSecond(seconds);
    }

    private static Map<String, CborValue> mapOf(CborValue value) throws RecordException {
        if (value instanceof CborValue.MapV map) {
            return map.entries();
        }
        throw schema("expected a map");
    }

    private static String textOf(CborValue value) throws RecordException {
        if (value instanceof CborValue.Text text) {
            return text.value();
        }
        throw schema("expected a text string");
    }

    /** Returns a copy of the byte string; the caller zero-fills it. */
    private static byte[] bytesOf(CborValue value) throws RecordException {
        if (value instanceof CborValue.Bytes bytes) {
            return bytes.value();
        }
        throw schema("expected a byte string");
    }

    private static String text(Map<String, CborValue> fields, String key) throws RecordException {
        return textOf(fields.get(key));
    }

    private static byte[] bytes(Map<String, CborValue> fields, String key) throws RecordException {
        return bytesOf(fields.get(key));
    }

    private static long uint(Map<String, CborValue> fields, String key) throws RecordException {
        if (fields.get(key) instanceof CborValue.UInt uint) {
            return uint.value();
        }
        throw schema("expected an unsigned integer");
    }

    private static boolean bool(Map<String, CborValue> fields, String key) throws RecordException {
        if (fields.get(key) instanceof CborValue.Bool bool) {
            return bool.value();
        }
        throw schema("expected a boolean");
    }

    private static List<String> texts(Map<String, CborValue> fields, String key) throws RecordException {
        if (!(fields.get(key) instanceof CborValue.Array array)) {
            throw schema("expected an array");
        }
        List<String> values = new ArrayList<>(array.items().size());
        for (CborValue item : array.items()) {
            values.add(textOf(item));
        }
        return values;
    }

    private static RecordException schema(String message) {
        return new RecordException(RecordException.Code.SCHEMA, message);
    }

    // ---- encode -------------------------------------------------------------------------------

    private static CborValue encodeRecord(VaultRecord record) {
        Objects.requireNonNull(record, "record");
        // Class.cast, not a pattern variable: the record is the caller's, and a local of an
        // AutoCloseable type would have to be closed here.
        if (record instanceof LoginRecord) {
            return encodeLogin(LoginRecord.class.cast(record));
        }
        if (record instanceof WifiRecord) {
            return encodeWifi(WifiRecord.class.cast(record));
        }
        if (record instanceof SshKeyRecord) {
            return encodeSshKey(SshKeyRecord.class.cast(record));
        }
        if (record instanceof ProjectRecord) {
            return encodeProject(ProjectRecord.class.cast(record));
        }
        if (record instanceof TrustedDeviceRecord) {
            return encodeTrustedDevice(TrustedDeviceRecord.class.cast(record));
        }
        return encodeDeviceIdentity(DeviceIdentityRecord.class.cast(record));
    }

    // In each encoder the secret is copied last, so nothing can fail while an unwiped copy exists
    // outside the returned map.

    private static CborValue encodeLogin(LoginRecord login) {
        Map<String, CborValue> fields = commonFields(T_LOGIN, login);
        fields.put(K_USERNAME, new CborValue.Text(login.username()));
        fields.put(K_URLS, textArray(login.urls()));
        fields.put(K_NOTES, new CborValue.Text(login.notes()));
        fields.put(K_TAGS, textArray(login.tags()));
        fields.put(K_LAST_USED, seconds(login.lastUsed()));
        fields.put(K_PASSWORD, secretBytes(login.password()));
        return new CborValue.MapV(fields);
    }

    private static CborValue encodeWifi(WifiRecord wifi) {
        Map<String, CborValue> fields = commonFields(T_WIFI, wifi);
        fields.put(K_SSID, new CborValue.Text(wifi.ssid()));
        fields.put(K_SECURITY, new CborValue.Text(wifi.security()));
        fields.put(K_HIDDEN, new CborValue.Bool(wifi.hidden()));
        fields.put(K_NOTES, new CborValue.Text(wifi.notes()));
        fields.put(K_PASSWORD, secretBytes(wifi.password()));
        return new CborValue.MapV(fields);
    }

    private static CborValue encodeSshKey(SshKeyRecord ssh) {
        Map<String, CborValue> fields = commonFields(T_SSH_KEY, ssh);
        fields.put(K_KEY_TYPE, new CborValue.Text(ssh.keyType()));
        fields.put(K_PUBLIC_KEY, new CborValue.Text(ssh.publicKey()));
        fields.put(K_FINGERPRINT, new CborValue.Text(ssh.fingerprint()));
        fields.put(K_COMMENT, new CborValue.Text(ssh.comment()));
        fields.put(K_HOSTS, textArray(ssh.hosts()));
        fields.put(K_PRIVATE_KEY, secretBytes(ssh.privateKey()));
        return new CborValue.MapV(fields);
    }

    private static CborValue encodeProject(ProjectRecord project) {
        Map<String, CborValue> fields = commonFields(T_PROJECT, project);
        fields.put(K_CANONICAL_PATH, new CborValue.Text(project.canonicalPath()));
        fields.put(K_GIT_REMOTE, new CborValue.Text(project.gitRemote()));
        Map<String, CborValue> config = new HashMap<>();
        for (Map.Entry<String, String> entry : project.config().entrySet()) {
            config.put(entry.getKey(), new CborValue.Text(entry.getValue()));
        }
        fields.put(K_CONFIG, new CborValue.MapV(config));
        Map<String, CborValue> variables = new HashMap<>();
        boolean complete = false;
        try {
            for (Map.Entry<String, SecretBytes> entry : project.variables().entrySet()) {
                variables.put(entry.getKey(), secretBytes(entry.getValue()));
            }
            fields.put(K_VARIABLES, new CborValue.MapV(variables));
            CborValue encoded = new CborValue.MapV(fields);
            complete = true;
            return encoded;
        } finally {
            if (!complete) {
                // A later variable was closed: clear the copies of the earlier ones.
                variables.values().forEach(CborValue::wipe);
            }
        }
    }

    private static CborValue encodeDeviceIdentity(DeviceIdentityRecord identity) {
        Map<String, CborValue> fields = commonFields(T_DEVICE_IDENTITY, identity);
        fields.put(K_CERTIFICATE, new CborValue.Bytes(identity.certificateDer()));
        fields.put(K_PRIVATE_KEY, secretBytes(identity.privateKey()));
        return new CborValue.MapV(fields);
    }

    private static CborValue encodeTrustedDevice(TrustedDeviceRecord device) {
        Map<String, CborValue> fields = commonFields(T_TRUSTED_DEVICE, device);
        fields.put(K_PUBLIC_KEY, new CborValue.Bytes(device.rawPublicKey()));
        fields.put(K_FINGERPRINT, new CborValue.Text(device.fingerprint()));
        fields.put(K_SHARED, textArray(device.shared().stream().map(UUID::toString).toList()));
        fields.put(K_RECEIVED, textArray(device.received().stream()
                .map(r -> r.shareId() + "@" + r.expires().getEpochSecond()).toList()));
        return new CborValue.MapV(fields);
    }

    private static Map<String, CborValue> commonFields(String type, VaultRecord record) {
        Map<String, CborValue> fields = new HashMap<>();
        fields.put(K_TYPE, new CborValue.Text(type));
        fields.put(K_ID, new CborValue.Text(record.id().toString()));
        fields.put(K_TITLE, new CborValue.Text(record.title()));
        fields.put(K_CREATED, seconds(record.created()));
        fields.put(K_UPDATED, seconds(record.updated()));
        return fields;
    }

    private static CborValue seconds(Instant instant) {
        return new CborValue.UInt(instant.getEpochSecond());
    }

    private static CborValue textArray(List<String> values) {
        return new CborValue.Array(values.stream().<CborValue>map(CborValue.Text::new).toList());
    }

    /** Copies the secret straight into a byte string of the tree; {@code encodePayload} wipes it. */
    private static CborValue secretBytes(SecretBytes value) {
        return value.apply(CborValue.Bytes::new);
    }

    /**
     * Secrets created for a record that is still being built. Unless the record is committed,
     * closing this closes them, so a field that fails later cannot leave an open secret behind.
     */
    private static final class Pending implements AutoCloseable {
        private final List<SecretBytes> secrets = new ArrayList<>();

        /** Wraps {@code raw} in a secret tracked by this scope and zero-fills {@code raw}. */
        SecretBytes own(byte[] raw) {
            SecretBytes owned = SecretBytes.takeOwnership(raw);
            secrets.add(owned);
            return owned;
        }

        /** Hands the secrets over to the finished record. */
        <T> T commit(T built) {
            secrets.clear();
            return built;
        }

        @Override
        public void close() {
            secrets.forEach(SecretBytes::close);
            secrets.clear();
        }
    }
}
