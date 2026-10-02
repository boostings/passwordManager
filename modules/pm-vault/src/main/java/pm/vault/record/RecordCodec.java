package pm.vault.record;

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

public final class RecordCodec {
    public static final int SCHEMA_VERSION = 1;

    private RecordCodec() {}

    public static SecretBytes encodePayload(List<VaultRecord> records) {
        Objects.requireNonNull(records, "records");
        List<CborValue> recordValues = new ArrayList<>();
        for (VaultRecord record : records) {
            recordValues.add(encodeRecord(record));
        }
        CborValue root = new CborValue.MapV(Map.of(
            "schema_version", new CborValue.UInt(SCHEMA_VERSION),
            "records", new CborValue.Array(recordValues)
        ));
        byte[] bytes = CborWriter.encode(root);
        return SecretBytes.takeOwnership(bytes);
    }

    public static List<VaultRecord> decodePayload(SecretBytes plaintext) throws RecordException {
        Objects.requireNonNull(plaintext, "plaintext");
        try {
            return plaintext.apply(bytes -> {
                try {
                    return decodePayloadBytes(bytes);
                } catch (RecordException ex) {
                    throw new IllegalStateException(ex);
                }
            });
        } catch (IllegalStateException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof RecordException re) {
                throw re;
            }
            throw ex;
        }
    }

    private static List<VaultRecord> decodePayloadBytes(byte[] in) throws RecordException {
        List<VaultRecord> decoded = new ArrayList<>();
        try {
            CborValue root = CborReader.decode(in, CborLimits.PAYLOAD);
            if (!(root instanceof CborValue.MapV map)) {
                throw new RecordException(RecordException.Code.SCHEMA, "root must be a map");
            }
            CborValue schemaValue = map.entries().get("schema_version");
            if (!(schemaValue instanceof CborValue.UInt schema) || schema.value() != SCHEMA_VERSION) {
                throw new RecordException(RecordException.Code.SCHEMA, "schema_version missing or invalid");
            }
            CborValue recordsValue = map.entries().get("records");
            if (!(recordsValue instanceof CborValue.Array recordsArray)) {
                throw new RecordException(RecordException.Code.SCHEMA, "records must be an array");
            }
            for (CborValue recordValue : recordsArray.items()) {
                decoded.add(decodeRecord(recordValue));
            }
            return List.copyOf(decoded);
        } catch (RecordException | CborException ex) {
            for (VaultRecord record : decoded) {
                record.close();
            }
            if (ex instanceof RecordException re) {
                throw re;
            }
            throw new RecordException(RecordException.Code.MALFORMED, "payload could not be decoded", ex);
        }
    }

    private static CborValue encodeRecord(VaultRecord record) {
        if (record instanceof LoginRecord login) {
            LinkedHashMap<String, CborValue> map = new LinkedHashMap<>();
            map.put("type", new CborValue.Text("login"));
            map.put("id", new CborValue.Text(login.id().toString()));
            map.put("title", new CborValue.Text(login.title()));
            map.put("username", new CborValue.Text(login.username()));
            map.put("password", new CborValue.Bytes(login.password().apply(bytes -> java.util.Arrays.copyOf(bytes, bytes.length))));
            map.put("urls", encodeStrings(login.urls()));
            map.put("notes", new CborValue.Text(login.notes()));
            map.put("tags", encodeStrings(login.tags()));
            map.put("created", new CborValue.UInt(login.created().getEpochSecond()));
            map.put("updated", new CborValue.UInt(login.updated().getEpochSecond()));
            map.put("last_used", new CborValue.UInt(login.lastUsed().getEpochSecond()));
            return new CborValue.MapV(map);
        }
        if (record instanceof WifiRecord wifi) {
            LinkedHashMap<String, CborValue> map = new LinkedHashMap<>();
            map.put("type", new CborValue.Text("wifi"));
            map.put("id", new CborValue.Text(wifi.id().toString()));
            map.put("title", new CborValue.Text(wifi.title()));
            map.put("ssid", new CborValue.Text(wifi.ssid()));
            map.put("security", new CborValue.Text(wifi.security()));
            map.put("password", new CborValue.Bytes(wifi.password().apply(bytes -> java.util.Arrays.copyOf(bytes, bytes.length))));
            map.put("hidden", new CborValue.Bool(wifi.hidden()));
            map.put("notes", new CborValue.Text(wifi.notes()));
            map.put("created", new CborValue.UInt(wifi.created().getEpochSecond()));
            map.put("updated", new CborValue.UInt(wifi.updated().getEpochSecond()));
            return new CborValue.MapV(map);
        }
        if (record instanceof SshKeyRecord ssh) {
            LinkedHashMap<String, CborValue> map = new LinkedHashMap<>();
            map.put("type", new CborValue.Text("ssh_key"));
            map.put("id", new CborValue.Text(ssh.id().toString()));
            map.put("title", new CborValue.Text(ssh.title()));
            map.put("key_type", new CborValue.Text(ssh.keyType()));
            map.put("private_key", new CborValue.Bytes(ssh.privateKey().apply(bytes -> java.util.Arrays.copyOf(bytes, bytes.length))));
            map.put("public_key", new CborValue.Text(ssh.publicKey()));
            map.put("fingerprint", new CborValue.Text(ssh.fingerprint()));
            map.put("comment", new CborValue.Text(ssh.comment()));
            map.put("hosts", encodeStrings(ssh.hosts()));
            map.put("created", new CborValue.UInt(ssh.created().getEpochSecond()));
            map.put("updated", new CborValue.UInt(ssh.updated().getEpochSecond()));
            return new CborValue.MapV(map);
        }
        if (record instanceof ProjectRecord project) {
            LinkedHashMap<String, CborValue> entries = new LinkedHashMap<>();
            entries.put("type", new CborValue.Text("project"));
            entries.put("id", new CborValue.Text(project.id().toString()));
            entries.put("title", new CborValue.Text(project.title()));
            entries.put("canonical_path", new CborValue.Text(project.canonicalPath()));
            entries.put("git_remote", new CborValue.Text(project.gitRemote()));
            LinkedHashMap<String, CborValue> variables = new LinkedHashMap<>();
            for (Map.Entry<String, SecretBytes> variable : project.variables().entrySet()) {
                variables.put(variable.getKey(), new CborValue.Bytes(variable.getValue().apply(bytes -> java.util.Arrays.copyOf(bytes, bytes.length))));
            }
            entries.put("variables", new CborValue.MapV(variables));
            LinkedHashMap<String, CborValue> config = new LinkedHashMap<>();
            for (Map.Entry<String, String> entry : project.config().entrySet()) {
                config.put(entry.getKey(), new CborValue.Text(entry.getValue()));
            }
            entries.put("config", new CborValue.MapV(config));
            entries.put("created", new CborValue.UInt(project.created().getEpochSecond()));
            entries.put("updated", new CborValue.UInt(project.updated().getEpochSecond()));
            return new CborValue.MapV(entries);
        }
        throw new IllegalArgumentException("Unsupported record type: " + record.getClass());
    }

    private static CborValue encodeStrings(List<String> values) {
        List<CborValue> items = new ArrayList<>();
        for (String value : values) {
            items.add(new CborValue.Text(value));
        }
        return new CborValue.Array(items);
    }

    private static VaultRecord decodeRecord(CborValue value) throws RecordException, CborException {
        if (!(value instanceof CborValue.MapV map)) {
            throw new RecordException(RecordException.Code.MALFORMED, "record is not a map");
        }
        String type = readText(map, "type");
        UUID id = UUID.fromString(readText(map, "id"));
        String title = readText(map, "title");
        long createdEpoch = readLong(map, "created");
        long updatedEpoch = readLong(map, "updated");
        if ("login".equals(type)) {
            String username = readText(map, "username");
            SecretBytes password = SecretBytes.takeOwnership(readBytes(map, "password"));
            List<String> urls = readStrings(map, "urls");
            String notes = readText(map, "notes");
            List<String> tags = readStrings(map, "tags");
            long lastUsedEpoch = readLong(map, "last_used");
            return new LoginRecord(id, title, username, password, urls, notes, tags,
                java.time.Instant.ofEpochSecond(createdEpoch), java.time.Instant.ofEpochSecond(updatedEpoch),
                java.time.Instant.ofEpochSecond(lastUsedEpoch));
        }
        if ("wifi".equals(type)) {
            String ssid = readText(map, "ssid");
            String security = readText(map, "security");
            SecretBytes password = SecretBytes.takeOwnership(readBytes(map, "password"));
            boolean hidden = readBool(map, "hidden");
            String notes = readText(map, "notes");
            return new WifiRecord(id, title, ssid, security, password, hidden, notes,
                java.time.Instant.ofEpochSecond(createdEpoch), java.time.Instant.ofEpochSecond(updatedEpoch));
        }
        if ("ssh_key".equals(type)) {
            String keyType = readText(map, "key_type");
            String publicKey = readText(map, "public_key");
            String fingerprint = readText(map, "fingerprint");
            String comment = readText(map, "comment");
            List<String> hosts = readStrings(map, "hosts");
            SecretBytes privateKey = SecretBytes.takeOwnership(readBytes(map, "private_key"));
            return new SshKeyRecord(id, title, keyType, privateKey, publicKey, fingerprint, comment, hosts,
                java.time.Instant.ofEpochSecond(createdEpoch), java.time.Instant.ofEpochSecond(updatedEpoch));
        }
        if ("project".equals(type)) {
            String canonicalPath = readText(map, "canonical_path");
            String gitRemote = readText(map, "git_remote");
            Map<String, SecretBytes> variables = new LinkedHashMap<>();
            CborValue.MapV variableMap = requireMap(map, "variables");
            for (Map.Entry<String, CborValue> entry : variableMap.entries().entrySet()) {
                variables.put(entry.getKey(), SecretBytes.takeOwnership(readBytesFromValue(entry.getValue())));
            }
            Map<String, String> config = new LinkedHashMap<>();
            CborValue.MapV configMap = requireMap(map, "config");
            for (Map.Entry<String, CborValue> entry : configMap.entries().entrySet()) {
                config.put(entry.getKey(), readTextValue(entry.getValue()));
            }
            return new ProjectRecord(id, title, canonicalPath, gitRemote, variables, config,
                java.time.Instant.ofEpochSecond(createdEpoch), java.time.Instant.ofEpochSecond(updatedEpoch));
        }
        throw new RecordException(RecordException.Code.SCHEMA, "unsupported record type: " + type);
    }

    private static String readText(CborValue.MapV map, String key) throws RecordException {
        CborValue value = map.entries().get(key);
        if (!(value instanceof CborValue.Text text)) {
            throw new RecordException(RecordException.Code.SCHEMA, "expected text for " + key);
        }
        return text.value();
    }

    private static String readTextValue(CborValue value) throws RecordException {
        if (!(value instanceof CborValue.Text text)) {
            throw new RecordException(RecordException.Code.SCHEMA, "expected text");
        }
        return text.value();
    }

    private static long readLong(CborValue.MapV map, String key) throws RecordException {
        CborValue value = map.entries().get(key);
        if (!(value instanceof CborValue.UInt uint)) {
            throw new RecordException(RecordException.Code.SCHEMA, "expected uint for " + key);
        }
        return uint.value();
    }

    private static boolean readBool(CborValue.MapV map, String key) throws RecordException {
        CborValue value = map.entries().get(key);
        if (!(value instanceof CborValue.Bool bool)) {
            throw new RecordException(RecordException.Code.SCHEMA, "expected bool for " + key);
        }
        return bool.value();
    }

    private static byte[] readBytes(CborValue.MapV map, String key) throws RecordException {
        CborValue value = map.entries().get(key);
        if (!(value instanceof CborValue.Bytes bytes)) {
            throw new RecordException(RecordException.Code.SCHEMA, "expected bytes for " + key);
        }
        return java.util.Arrays.copyOf(bytes.value(), bytes.value().length);
    }

    private static byte[] readBytesFromValue(CborValue value) throws RecordException {
        if (!(value instanceof CborValue.Bytes bytes)) {
            throw new RecordException(RecordException.Code.SCHEMA, "expected bytes");
        }
        return java.util.Arrays.copyOf(bytes.value(), bytes.value().length);
    }

    private static List<String> readStrings(CborValue.MapV map, String key) throws RecordException {
        CborValue value = map.entries().get(key);
        if (!(value instanceof CborValue.Array array)) {
            throw new RecordException(RecordException.Code.SCHEMA, "expected array for " + key);
        }
        List<String> strings = new ArrayList<>();
        for (CborValue item : array.items()) {
            strings.add(readTextValue(item));
        }
        return List.copyOf(strings);
    }

    private static CborValue.MapV requireMap(CborValue.MapV map, String key) throws RecordException {
        CborValue value = map.entries().get(key);
        if (!(value instanceof CborValue.MapV nested)) {
            throw new RecordException(RecordException.Code.SCHEMA, "expected map for " + key);
        }
        return nested;
    }
}
