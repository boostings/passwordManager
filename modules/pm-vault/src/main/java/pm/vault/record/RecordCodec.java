package pm.vault.record;

import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import pm.crypto.SecretBytes;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/**
 * Encodes and decodes the record payload {@code {"schema_version":1,"records":[...]}}
 * (ADR 0006). Decoding is all-or-nothing: on any error every record already built is closed
 * and nothing is returned. Intermediate {@code byte[]} copies of secrets made while encoding
 * are wiped on a best-effort basis only (R-003).
 */
public final class RecordCodec {
    /** Payload schema version. */
    public static final int SCHEMA_VERSION = 1;

    private static final String TYPE_LOGIN = "login";
    private static final String TYPE_WIFI = "wifi";
    private static final String TYPE_SSH_KEY = "ssh_key";
    private static final String TYPE_PROJECT = "project";

    private RecordCodec() {}

    /**
     * Encodes records as the plaintext payload.
     *
     * @param records the records; not closed by this method
     * @return the payload; the caller closes it
     */
    public static SecretBytes encodePayload(List<VaultRecord> records) {
        Objects.requireNonNull(records, "records");
        List<CborValue> recordValues = records.stream().map(RecordCodec::encodeRecord).toList();
        CborValue root = new CborValue.MapV(Map.of(
            "schema_version", new CborValue.UInt(SCHEMA_VERSION),
            "records", new CborValue.Array(recordValues)
        ));
        byte[] bytes = CborWriter.encode(root);
        return SecretBytes.takeOwnership(bytes);
    }

    /**
     * Decodes an authenticated payload, all or nothing. Unknown keys are ignored.
     *
     * @param plaintext the decrypted payload; not closed by this method
     * @return every record, in payload order; the caller closes them
     * @throws RecordException {@code SCHEMA}, {@code LIMIT} or {@code MALFORMED}
     */
    public static List<VaultRecord> decodePayload(SecretBytes plaintext) throws RecordException {
        Objects.requireNonNull(plaintext, "plaintext");
        CborValue root;
        try {
            root = plaintext.apply(bytes -> {
                try {
                    return CborReader.decode(bytes, CborLimits.PAYLOAD);
                } catch (CborException ex) {
                    throw new IllegalStateException(ex);
                }
            });
        } catch (IllegalStateException ex) {
            if (ex.getCause() instanceof CborException cbor) {
                throw new RecordException(cbor.code() == CborException.Code.LIMIT
                        ? RecordException.Code.LIMIT : RecordException.Code.MALFORMED, cbor);
            }
            throw ex;
        }
        return decodeRoot(root);
    }

    private static List<VaultRecord> decodeRoot(CborValue root) throws RecordException {
        if (!(root instanceof CborValue.MapV map)) {
            throw new RecordException(RecordException.Code.SCHEMA); // root must be a map
        }
        CborValue schemaValue = map.entries().get("schema_version");
        if (!(schemaValue instanceof CborValue.UInt schema) || schema.value() != SCHEMA_VERSION) {
            throw new RecordException(RecordException.Code.SCHEMA);
        }
        CborValue recordsValue = map.entries().get("records");
        if (!(recordsValue instanceof CborValue.Array recordsArray)) {
            throw new RecordException(RecordException.Code.SCHEMA);
        }
        List<VaultRecord> decoded = new ArrayList<>();
        boolean complete = false;
        try {
            for (CborValue recordValue : recordsArray.items()) {
                decoded.add(decodeRecord(recordValue));
            }
            complete = true;
            return List.copyOf(decoded);
        } catch (IllegalArgumentException | DateTimeException ex) {
            // Bad UUID, out-of-range timestamp, or a record bound (title, notes, list sizes).
            throw new RecordException(RecordException.Code.LIMIT, ex);
        } finally {
            if (!complete) {
                decoded.forEach(VaultRecord::close);
            }
        }
    }

    private static CborValue encodeRecord(VaultRecord record) {
        return switch (record) {
            case LoginRecord l -> encodeLogin(l);
            case WifiRecord w -> encodeWifi(w);
            case SshKeyRecord s -> encodeSsh(s);
            case ProjectRecord p -> encodeProject(p);
        };
    }

    private static CborValue encodeLogin(LoginRecord login) {
        Map<String, CborValue> map = common(TYPE_LOGIN, login);
        map.put("username", new CborValue.Text(login.username()));
        map.put("password", secret(login.password()));
        map.put("urls", encodeStrings(login.urls()));
        map.put("notes", new CborValue.Text(login.notes()));
        map.put("tags", encodeStrings(login.tags()));
        map.put("last_used", epoch(login.lastUsed()));
        return new CborValue.MapV(map);
    }

    private static CborValue encodeWifi(WifiRecord wifi) {
        Map<String, CborValue> map = common(TYPE_WIFI, wifi);
        map.put("ssid", new CborValue.Text(wifi.ssid()));
        map.put("security", new CborValue.Text(wifi.security()));
        map.put("password", secret(wifi.password()));
        map.put("hidden", new CborValue.Bool(wifi.hidden()));
        map.put("notes", new CborValue.Text(wifi.notes()));
        return new CborValue.MapV(map);
    }

    private static CborValue encodeSsh(SshKeyRecord ssh) {
        Map<String, CborValue> map = common(TYPE_SSH_KEY, ssh);
        map.put("key_type", new CborValue.Text(ssh.keyType()));
        map.put("private_key", secret(ssh.privateKey()));
        map.put("public_key", new CborValue.Text(ssh.publicKey()));
        map.put("fingerprint", new CborValue.Text(ssh.fingerprint()));
        map.put("comment", new CborValue.Text(ssh.comment()));
        map.put("hosts", encodeStrings(ssh.hosts()));
        return new CborValue.MapV(map);
    }

    private static CborValue encodeProject(ProjectRecord project) {
        Map<String, CborValue> map = common(TYPE_PROJECT, project);
        map.put("canonical_path", new CborValue.Text(project.canonicalPath()));
        map.put("git_remote", new CborValue.Text(project.gitRemote()));
        Map<String, CborValue> variables = new LinkedHashMap<>();
        project.variables().forEach((name, value) -> variables.put(name, secret(value)));
        map.put("variables", new CborValue.MapV(variables));
        Map<String, CborValue> config = new LinkedHashMap<>();
        project.config().forEach((name, value) -> config.put(name, new CborValue.Text(value)));
        map.put("config", new CborValue.MapV(config));
        return new CborValue.MapV(map);
    }

    private static Map<String, CborValue> common(String type, VaultRecord record) {
        Map<String, CborValue> map = new LinkedHashMap<>();
        map.put("type", new CborValue.Text(type));
        map.put("id", new CborValue.Text(record.id().toString()));
        map.put("title", new CborValue.Text(record.title()));
        map.put("created", epoch(record.created()));
        map.put("updated", epoch(record.updated()));
        return map;
    }

    /** {@code CborValue.Bytes} copies the buffer, so the internal array never escapes. */
    private static CborValue secret(SecretBytes value) {
        return value.apply(CborValue.Bytes::new);
    }

    private static CborValue epoch(Instant instant) {
        return new CborValue.UInt(instant.getEpochSecond());
    }

    private static CborValue encodeStrings(List<String> values) {
        return new CborValue.Array(values.stream().<CborValue>map(CborValue.Text::new).toList());
    }

    private static VaultRecord decodeRecord(CborValue value) throws RecordException {
        if (!(value instanceof CborValue.MapV map)) {
            throw new RecordException(RecordException.Code.MALFORMED); // record is not a map
        }
        String type = readText(map, "type");
        return switch (type) {
            case TYPE_LOGIN -> decodeLogin(map);
            case TYPE_WIFI -> decodeWifi(map);
            case TYPE_SSH_KEY -> decodeSsh(map);
            case TYPE_PROJECT -> decodeProject(map);
            default -> throw new RecordException(RecordException.Code.SCHEMA); // unknown type
        };
    }

    // Each decoder reads and bounds-checks every non-secret field first and wraps the secret
    // last, so neither a schema error nor a bound violation strands an unclosed SecretBytes.

    private static VaultRecord decodeLogin(CborValue.MapV map) throws RecordException {
        UUID id = readId(map);
        String title = readText(map, "title");
        String username = readText(map, "username");
        List<String> urls = readStrings(map, "urls");
        String notes = readText(map, "notes");
        List<String> tags = readStrings(map, "tags");
        Instant created = readInstant(map, "created");
        Instant updated = readInstant(map, "updated");
        Instant lastUsed = readInstant(map, "last_used");
        RecordLimits.checkTitle(title);
        RecordLimits.checkNotes(notes);
        RecordLimits.checkListSize(urls.size());
        RecordLimits.checkListSize(tags.size());
        return new LoginRecord(id, title, username,
                SecretBytes.takeOwnership(readBytes(map, "password")), urls, notes, tags,
                created, updated, lastUsed);
    }

    private static VaultRecord decodeWifi(CborValue.MapV map) throws RecordException {
        UUID id = readId(map);
        String title = readText(map, "title");
        String ssid = readText(map, "ssid");
        String security = readText(map, "security");
        boolean hidden = readBool(map, "hidden");
        String notes = readText(map, "notes");
        Instant created = readInstant(map, "created");
        Instant updated = readInstant(map, "updated");
        RecordLimits.checkTitle(title);
        RecordLimits.checkNotes(notes);
        return new WifiRecord(id, title, ssid, security,
                SecretBytes.takeOwnership(readBytes(map, "password")), hidden, notes,
                created, updated);
    }

    private static VaultRecord decodeSsh(CborValue.MapV map) throws RecordException {
        UUID id = readId(map);
        String title = readText(map, "title");
        String keyType = readText(map, "key_type");
        String publicKey = readText(map, "public_key");
        String fingerprint = readText(map, "fingerprint");
        String comment = readText(map, "comment");
        List<String> hosts = readStrings(map, "hosts");
        Instant created = readInstant(map, "created");
        Instant updated = readInstant(map, "updated");
        RecordLimits.checkTitle(title);
        RecordLimits.checkNotes(comment);
        RecordLimits.checkListSize(hosts.size());
        return new SshKeyRecord(id, title, keyType,
                SecretBytes.takeOwnership(readBytes(map, "private_key")), publicKey,
                fingerprint, comment, hosts, created, updated);
    }

    private static VaultRecord decodeProject(CborValue.MapV map) throws RecordException {
        UUID id = readId(map);
        String title = readText(map, "title");
        String canonicalPath = readText(map, "canonical_path");
        String gitRemote = readText(map, "git_remote");
        Map<String, String> config = new LinkedHashMap<>();
        for (Map.Entry<String, CborValue> entry : requireMap(map, "config").entries().entrySet()) {
            config.put(entry.getKey(), readTextValue(entry.getValue()));
        }
        Instant created = readInstant(map, "created");
        Instant updated = readInstant(map, "updated");
        Map<String, CborValue> rawVariables = requireMap(map, "variables").entries();
        for (CborValue variable : rawVariables.values()) {
            readBytesFromValue(variable); // type-check every value before wrapping any secret
        }
        RecordLimits.checkTitle(title);
        Map<String, SecretBytes> variables = new LinkedHashMap<>();
        for (Map.Entry<String, CborValue> entry : rawVariables.entrySet()) {
            variables.put(entry.getKey(),
                    SecretBytes.takeOwnership(readBytesFromValue(entry.getValue())));
        }
        return new ProjectRecord(id, title, canonicalPath, gitRemote, variables, config,
                created, updated);
    }

    private static UUID readId(CborValue.MapV map) throws RecordException {
        return UUID.fromString(readText(map, "id")); // IllegalArgumentException mapped by caller
    }

    private static Instant readInstant(CborValue.MapV map, String key) throws RecordException {
        CborValue value = map.entries().get(key);
        if (!(value instanceof CborValue.UInt uint)) {
            throw new RecordException(RecordException.Code.SCHEMA);
        }
        return Instant.ofEpochSecond(uint.value()); // DateTimeException mapped by caller
    }

    private static String readText(CborValue.MapV map, String key) throws RecordException {
        return readTextValue(map.entries().get(key));
    }

    private static String readTextValue(CborValue value) throws RecordException {
        if (!(value instanceof CborValue.Text text)) {
            throw new RecordException(RecordException.Code.SCHEMA);
        }
        return text.value();
    }

    private static boolean readBool(CborValue.MapV map, String key) throws RecordException {
        CborValue value = map.entries().get(key);
        if (!(value instanceof CborValue.Bool bool)) {
            throw new RecordException(RecordException.Code.SCHEMA);
        }
        return bool.value();
    }

    private static byte[] readBytes(CborValue.MapV map, String key) throws RecordException {
        return readBytesFromValue(map.entries().get(key));
    }

    /** Returns a fresh copy; {@code CborValue.Bytes#value} never exposes its own array. */
    private static byte[] readBytesFromValue(CborValue value) throws RecordException {
        if (!(value instanceof CborValue.Bytes bytes)) {
            throw new RecordException(RecordException.Code.SCHEMA);
        }
        return bytes.value();
    }

    private static List<String> readStrings(CborValue.MapV map, String key) throws RecordException {
        CborValue value = map.entries().get(key);
        if (!(value instanceof CborValue.Array array)) {
            throw new RecordException(RecordException.Code.SCHEMA);
        }
        List<String> strings = new ArrayList<>(array.items().size());
        for (CborValue item : array.items()) {
            strings.add(readTextValue(item));
        }
        return List.copyOf(strings);
    }

    private static CborValue.MapV requireMap(CborValue.MapV map, String key) throws RecordException {
        CborValue value = map.entries().get(key);
        if (!(value instanceof CborValue.MapV nested)) {
            throw new RecordException(RecordException.Code.SCHEMA);
        }
        return nested;
    }
}
