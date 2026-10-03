package pm.vault.record;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import pm.crypto.SecretBytes;

/**
 * Shared fixtures for the record tests: fixed sample records, jqwik generators for all four record
 * types, and test-only access to payload bytes. Every factory returns a new record that the caller
 * owns and closes.
 */
final class RecordFixtures {
    static final Instant T0 = Instant.parse("2026-10-02T12:00:00Z");
    static final String ID_A = "11111111-1111-4111-8111-111111111111";
    static final String ID_B = "22222222-2222-4222-8222-222222222222";
    static final String ID_C = "33333333-3333-4333-8333-333333333333";
    static final String ID_D = "44444444-4444-4444-8444-444444444444";

    private static final int FIRST_SURROGATE = 0xD800;
    private static final int LAST_SURROGATE = 0xDFFF;
    private static final int MAX_TEXT_CODE_POINTS = 24;
    private static final int MAX_LIST = 3;
    private static final int MAX_SECRET = 48;

    private RecordFixtures() {
    }

    // ---- fixed samples -------------------------------------------------------------------------

    static SecretBytes secretOf(String text) {
        return SecretBytes.copyOf(text.getBytes(StandardCharsets.UTF_8));
    }

    static LoginRecord login(String id, String title) {
        return new LoginRecord(UUID.fromString(id), title, "alice", secretOf("hunter2"),
                List.of("https://example.com/login"), "recovery codes in the safe", List.of("work"),
                T0, T0.plusSeconds(5), T0.plusSeconds(10));
    }

    static WifiRecord wifi(String id, String title) {
        return new WifiRecord(UUID.fromString(id), title, "HomeNet", "WPA3", secretOf("wifi-hunter2"),
                true, "router in the hall", T0, T0);
    }

    static SshKeyRecord sshKey(String id, String title) {
        return new SshKeyRecord(UUID.fromString(id), title, "ed25519", secretOf("ssh-hunter2-private"),
                "ssh-ed25519 AAAAC3Nz", "SHA256:abcdef", "deploy comment", List.of("build.example.org"), T0, T0);
    }

    static ProjectRecord project(String id, String title) {
        return new ProjectRecord(UUID.fromString(id), title, "/home/alice/work/app", "git@example.org:alice/app.git",
                Map.of("API_TOKEN", secretOf("env-hunter2"), "DB_URL", secretOf("postgres://db")),
                Map.of("profile", "dev"), T0, T0);
    }

    /** One record of each of the four types. */
    static List<VaultRecord> oneOfEach() {
        return List.of(login(ID_A, "Bank"), wifi(ID_B, "Home"), sshKey(ID_C, "Deploy"), project(ID_D, "App"));
    }

    /**
     * Closes a record that a try-with-resources block will close again; javac's {@code try} lint
     * refuses a direct {@code close()} call on such a variable.
     */
    static void closeNow(VaultRecord record) {
        record.close();
    }

    /** Same as {@link #closeNow(VaultRecord)}, for a secret. */
    static void closeNow(SecretBytes secret) {
        secret.close();
    }

    // ---- payload bytes (test only: production code never copies a payload out) ------------------

    /** Encodes {@code records} and returns a copy of the payload bytes. */
    static byte[] encode(List<VaultRecord> records) {
        try (SecretBytes payload = RecordCodec.encodePayload(records)) {
            return payload.apply(bytes -> Arrays.copyOf(bytes, bytes.length));
        }
    }

    /** Decodes {@code payload}, closes the records and returns how many there were. */
    static int decodedCount(byte[] payload) throws RecordException {
        try (SecretBytes plaintext = SecretBytes.copyOf(payload)) {
            List<VaultRecord> decoded = RecordCodec.decodePayload(plaintext);
            decoded.forEach(VaultRecord::close);
            return decoded.size();
        }
    }

    // ---- generators ----------------------------------------------------------------------------

    /** Lists of up to {@code maxSize} records of all four types with distinct ids. */
    static Arbitrary<List<VaultRecord>> recordLists(int maxSize) {
        Arbitrary<VaultRecord> any = Arbitraries.oneOf(List.of(logins(), wifis(), sshKeys(), projects()));
        return any.list().ofMaxSize(maxSize).uniqueElements(VaultRecord::id);
    }

    static Arbitrary<VaultRecord> logins() {
        return Combinators.combine(ids(), texts(), texts(), secrets(), texts().list().ofMaxSize(MAX_LIST), texts(),
                        texts().list().ofMaxSize(MAX_LIST), instants())
                .as((id, title, username, raw, urls, notes, tags, at) -> new LoginRecord(
                        id, title, username, SecretBytes.copyOf(raw), urls, notes, tags, at, at, at));
    }

    static Arbitrary<VaultRecord> wifis() {
        return Combinators.combine(ids(), texts(), texts(), Arbitraries.of("WPA2", "WPA3", "WEP", "OPEN"),
                        secrets(), Arbitraries.of(true, false), texts(), instants())
                .as((id, title, ssid, security, raw, hidden, notes, at) -> new WifiRecord(
                        id, title, ssid, security, SecretBytes.copyOf(raw), hidden, notes, at, at));
    }

    static Arbitrary<VaultRecord> sshKeys() {
        return Combinators.combine(ids(), texts(), texts(), secrets(), texts(), texts(),
                        texts().list().ofMaxSize(MAX_LIST), instants())
                .as((id, title, keyType, raw, publicKey, comment, hosts, at) -> new SshKeyRecord(
                        id, title, keyType, SecretBytes.copyOf(raw), publicKey, "SHA256:" + keyType, comment,
                        hosts, at, at));
    }

    static Arbitrary<VaultRecord> projects() {
        return Combinators.combine(ids(), texts(), texts(), texts(),
                        Arbitraries.maps(texts(), secrets()).ofMaxSize(MAX_LIST),
                        Arbitraries.maps(texts(), texts()).ofMaxSize(MAX_LIST), instants())
                .as((id, title, path, remote, variables, config, at) -> new ProjectRecord(
                        id, title, path, remote, wrap(variables), config, at, at));
    }

    static Arbitrary<UUID> ids() {
        return Combinators.combine(Arbitraries.longs(), Arbitraries.longs()).as(UUID::new);
    }

    /** Any instant the model accepts, in whole seconds. */
    static Arbitrary<Instant> instants() {
        return Arbitraries.longs().between(0, FieldRules.MAX_EPOCH_SECOND).map(Instant::ofEpochSecond);
    }

    static Arbitrary<byte[]> secrets() {
        return Arbitraries.bytes().array(byte[].class).ofMaxSize(MAX_SECRET);
    }

    /** Well-formed strings over all of Unicode, including supplementary characters. */
    static Arbitrary<String> texts() {
        return Arbitraries.integers().between(0, Character.MAX_CODE_POINT)
                .filter(codePoint -> codePoint < FIRST_SURROGATE || codePoint > LAST_SURROGATE)
                .list().ofMaxSize(MAX_TEXT_CODE_POINTS)
                .map(codePoints -> {
                    StringBuilder text = new StringBuilder();
                    codePoints.forEach(text::appendCodePoint);
                    return text.toString();
                });
    }

    private static Map<String, SecretBytes> wrap(Map<String, byte[]> raw) {
        Map<String, SecretBytes> wrapped = new HashMap<>();
        raw.forEach((name, bytes) -> wrapped.put(name, SecretBytes.copyOf(bytes)));
        return wrapped;
    }
}
