package pm.vault.record;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/**
 * Payload codec (ADR 0006, SR-021): round trips for all four record types, the all-or-nothing rule
 * under truncation and corruption, and one test per schema rejection.
 */
class RecordCodecTest {
    private static final HexFormat HEX = HexFormat.of();
    private static final int MAX_RECORDS = 4;
    private static final int ONE_MIB = 1 << 20;

    // ---- round trips ---------------------------------------------------------------------------

    @Test
    void roundTripsOneRecordOfEachType() throws RecordException {
        List<VaultRecord> records = RecordFixtures.oneOfEach();
        try (SecretBytes payload = RecordCodec.encodePayload(records)) {
            List<VaultRecord> decoded = RecordCodec.decodePayload(payload);
            assertEquals(records, decoded);
            assertEquals(List.of(LoginRecord.class, WifiRecord.class, SshKeyRecord.class, ProjectRecord.class),
                    decoded.stream().map(Object::getClass).toList());
            decoded.forEach(VaultRecord::close);
        }
        records.forEach(VaultRecord::close);
    }

    @Property(tries = 200)
    void decodeInvertsEncodeForAllRecordTypes(@ForAll("recordLists") List<VaultRecord> records)
            throws RecordException {
        try (SecretBytes payload = RecordCodec.encodePayload(records)) {
            List<VaultRecord> decoded = RecordCodec.decodePayload(payload);
            assertEquals(records, decoded);
            try (SecretBytes again = RecordCodec.encodePayload(decoded)) {
                assertEquals(payload, again);
            }
            decoded.forEach(VaultRecord::close);
        }
    }

    @Test
    void encodesTheDocumentedPayloadShape() {
        // {"records": [], "schema_version": 1}: keys in deterministic order.
        byte[] expected = CborWriter.encode(new CborValue.MapV(Map.of(
                "schema_version", new CborValue.UInt(1), "records", new CborValue.Array(List.of()))));
        assertEquals("a2677265636f726473806e736368656d615f76657273696f6e01",
                HEX.formatHex(RecordFixtures.encode(List.of())));
        assertEquals(HEX.formatHex(expected),
                HEX.formatHex(RecordFixtures.encode(List.of())));
    }

    @Test
    void timestampsWithNanosecondsSurviveARoundTrip() throws RecordException {
        Instant precise = RecordFixtures.T0.plusNanos(123_456_789);
        try (LoginRecord login = new LoginRecord(UUID.fromString(RecordFixtures.ID_A), "t", "u",
                RecordFixtures.secretOf("pw-value"), List.of(), "", List.of(), precise, precise, precise);
             SecretBytes payload = RecordCodec.encodePayload(List.of(login))) {
            List<VaultRecord> decoded = RecordCodec.decodePayload(payload);
            assertEquals(List.of(login), decoded);
            assertEquals(RecordFixtures.T0, decoded.get(0).created());
            decoded.forEach(VaultRecord::close);
        }
    }

    // ---- all or nothing (M1 exit criterion: corrupted input never yields a partial record) -------

    /**
     * Cutting the payload at every offset throws {@link RecordException}. It never returns a
     * shorter list, and never throws anything else.
     */
    @Property(tries = 40)
    void truncationNeverPartial(@ForAll("recordLists") List<VaultRecord> records) throws RecordException {
        byte[] full = RecordFixtures.encode(records);
        assertEquals(records.size(), RecordFixtures.decodedCount(full));
        for (int length = 0; length < full.length; length++) {
            byte[] prefix = Arrays.copyOf(full, length);
            assertThrows(RecordException.class, () -> RecordFixtures.decodedCount(prefix));
        }
    }

    /** Flipping any single bit gives every record or a {@link RecordException}, never fewer records. */
    @Property(tries = 15)
    void singleBitFlipNeverYieldsAShorterList(@ForAll("recordLists") List<VaultRecord> records) {
        byte[] full = RecordFixtures.encode(records);
        for (int bit = 0; bit < full.length * Byte.SIZE; bit++) {
            byte[] flipped = full.clone();
            flipped[bit / Byte.SIZE] ^= (byte) (1 << (bit % Byte.SIZE));
            try {
                assertEquals(records.size(), RecordFixtures.decodedCount(flipped));
            } catch (RecordException expected) {
                assertNotNull(expected.code());
            }
        }
    }

    @Test
    void aBadRecordAfterGoodOnesRejectsTheWholePayload() {
        Map<String, CborValue> bad = loginFields(RecordFixtures.ID_C);
        bad.remove("urls");
        byte[] payload = payload(1, List.of(loginFields(RecordFixtures.ID_A), loginFields(RecordFixtures.ID_B), bad));
        assertEquals(RecordException.Code.SCHEMA, rejected(payload).code());
    }

    // ---- schema rejections ---------------------------------------------------------------------

    @Test
    void rejectsWrongSchemaVersion() {
        assertEquals(RecordException.Code.SCHEMA, rejected(payload(2, List.of())).code());
        assertEquals(RecordException.Code.SCHEMA, rejected(payload(0, List.of())).code());
    }

    @Test
    void rejectsMissingOrMistypedTopLevelKeys() {
        CborValue noVersion = new CborValue.MapV(Map.of("records", new CborValue.Array(List.of())));
        CborValue textVersion = new CborValue.MapV(Map.of(
                "schema_version", new CborValue.Text("1"), "records", new CborValue.Array(List.of())));
        CborValue noRecords = new CborValue.MapV(Map.of("schema_version", new CborValue.UInt(1)));
        CborValue mapRecords = new CborValue.MapV(Map.of(
                "schema_version", new CborValue.UInt(1), "records", new CborValue.MapV(Map.of())));
        CborValue arrayRoot = new CborValue.Array(List.of());
        CborValue recordNotAMap = new CborValue.MapV(Map.of(
                "schema_version", new CborValue.UInt(1),
                "records", new CborValue.Array(List.of(new CborValue.Text("login")))));
        for (CborValue root : List.of(noVersion, textVersion, noRecords, mapRecords, arrayRoot, recordNotAMap)) {
            assertEquals(RecordException.Code.SCHEMA, rejected(CborWriter.encode(root)).code());
        }
    }

    @Test
    void rejectsDuplicateRecordIds() {
        byte[] payload = payload(1, List.of(loginFields(RecordFixtures.ID_A), loginFields(RecordFixtures.ID_A)));
        assertEquals(RecordException.Code.SCHEMA, rejected(payload).code());
    }

    @Test
    void encodeRefusesDuplicateRecordIds() {
        try (LoginRecord first = RecordFixtures.login(RecordFixtures.ID_A, "one");
             LoginRecord second = RecordFixtures.login(RecordFixtures.ID_A, "two")) {
            assertThrows(IllegalArgumentException.class, () -> RecordFixtures.encode(List.of(first, second)));
        }
    }

    @Test
    void rejectsUnknownRecordTypeWithoutEchoingIt() {
        Map<String, CborValue> fields = loginFields(RecordFixtures.ID_A);
        fields.put("type", new CborValue.Text("credit_card"));
        RecordException e = rejected(payload(1, List.of(fields)));
        assertEquals(RecordException.Code.SCHEMA, e.code());
        assertFalse(e.getMessage().contains("credit_card"));
    }

    @Test
    void rejectsEveryMissingLoginField() {
        for (String key : loginFields(RecordFixtures.ID_A).keySet()) {
            Map<String, CborValue> fields = loginFields(RecordFixtures.ID_A);
            fields.remove(key);
            assertEquals(RecordException.Code.SCHEMA, rejected(payload(1, List.of(fields))).code(), key);
        }
    }

    @Test
    void rejectsFieldsOfTheWrongType() {
        Map<String, CborValue> wrong = new HashMap<>();
        wrong.put("password", new CborValue.Text("hunter2"));
        wrong.put("title", new CborValue.Bytes(new byte[] {1}));
        wrong.put("created", new CborValue.Text("yesterday"));
        wrong.put("urls", new CborValue.Text("https://example.com"));
        wrong.put("tags", new CborValue.Array(List.of(new CborValue.UInt(1))));
        wrong.put("id", new CborValue.Bytes(new byte[16]));
        for (Map.Entry<String, CborValue> entry : wrong.entrySet()) {
            Map<String, CborValue> fields = loginFields(RecordFixtures.ID_A);
            fields.put(entry.getKey(), entry.getValue());
            assertEquals(RecordException.Code.SCHEMA, rejected(payload(1, List.of(fields))).code(), entry.getKey());
        }
    }

    @Test
    void rejectsIdsThatAreNotCanonicalUuids() {
        for (String id : List.of("not-a-uuid", "1-1-1-1-1", "11111111-1111-4111-8111-11111111111",
                "11111111-1111-4111-8111-1111111111111", "AAAAAAAA-1111-4111-8111-111111111111",
                "11111111x1111-4111-8111-111111111111", "")) {
            RecordException e = rejected(payload(1, List.of(loginFields(id))));
            assertEquals(RecordException.Code.SCHEMA, e.code(), id);
        }
    }

    @Test
    void rejectsTimestampsBeyondTheSupportedRange() {
        for (long seconds : new long[] {FieldRules.MAX_EPOCH_SECOND + 1, Long.MAX_VALUE}) {
            Map<String, CborValue> fields = loginFields(RecordFixtures.ID_A);
            fields.put("created", new CborValue.UInt(seconds));
            assertEquals(RecordException.Code.LIMIT, rejected(payload(1, List.of(fields))).code());
        }
    }

    @Test
    void rejectsFieldsTheModelRefuses() {
        Map<String, CborValue> longTitle = loginFields(RecordFixtures.ID_A);
        longTitle.put("title", new CborValue.Text("t".repeat(FieldRules.MAX_TITLE_CHARS + 1)));
        Map<String, CborValue> manyUrls = loginFields(RecordFixtures.ID_A);
        List<CborValue> urls = new ArrayList<>();
        for (int i = 0; i <= FieldRules.MAX_LIST_ITEMS; i++) {
            urls.add(new CborValue.Text("https://example.com/" + i));
        }
        manyUrls.put("urls", new CborValue.Array(urls));
        Map<String, CborValue> badSecurity = wifiFields(RecordFixtures.ID_A);
        badSecurity.put("security", new CborValue.Text("WPA"));
        for (Map<String, CborValue> fields : List.of(longTitle, manyUrls, badSecurity)) {
            RecordException e = rejected(payload(1, List.of(loginFields(RecordFixtures.ID_B), fields)));
            assertEquals(RecordException.Code.SCHEMA, e.code());
        }
    }

    @Test
    void rejectsProjectVariablesThatAreNotByteStrings() {
        Map<String, CborValue> fields = new HashMap<>();
        fields.put("type", new CborValue.Text("project"));
        fields.put("id", new CborValue.Text(RecordFixtures.ID_A));
        fields.put("title", new CborValue.Text("t"));
        fields.put("canonical_path", new CborValue.Text("/p"));
        fields.put("git_remote", new CborValue.Text(""));
        fields.put("created", new CborValue.UInt(1));
        fields.put("updated", new CborValue.UInt(1));
        fields.put("config", new CborValue.MapV(Map.of()));
        fields.put("variables", new CborValue.MapV(Map.of(
                "A", new CborValue.Bytes(new byte[] {1}), "B", new CborValue.Text("not bytes"))));
        assertEquals(RecordException.Code.SCHEMA, rejected(payload(1, List.of(fields))).code());
    }

    @Test
    void ignoresUnknownKeysAndDoesNotWriteThemBack() throws RecordException {
        Map<String, CborValue> fields = loginFields(RecordFixtures.ID_A);
        fields.put("future_field", new CborValue.Bytes(new byte[] {9, 9, 9}));
        CborValue root = new CborValue.MapV(Map.of(
                "schema_version", new CborValue.UInt(1),
                "records", new CborValue.Array(List.of(new CborValue.MapV(fields))),
                "future_top_level", new CborValue.Text("ignored")));
        byte[] expected = payload(1, List.of(loginFields(RecordFixtures.ID_A)));
        try (SecretBytes plaintext = SecretBytes.copyOf(CborWriter.encode(root))) {
            List<VaultRecord> decoded = RecordCodec.decodePayload(plaintext);
            assertEquals(1, decoded.size());
            assertEquals(HEX.formatHex(expected),
                    HEX.formatHex(RecordFixtures.encode(decoded)));
            decoded.forEach(VaultRecord::close);
        }
    }

    @Test
    void rejectsBytesThatAreNotDeterministicCbor() {
        assertEquals(RecordException.Code.MALFORMED, rejected(new byte[0]).code());
        assertEquals(RecordException.Code.MALFORMED, rejected(new byte[] {(byte) 0xFF}).code());
        // {"schema_version": 1, "records": []} with the keys in the wrong order.
        byte[] unsorted = HEX.parseHex("a26e736368656d615f76657273696f6e01677265636f72647380");
        assertEquals(RecordException.Code.MALFORMED, rejected(unsorted).code());
        byte[] trailing = Arrays.copyOf(payload(1, List.of()), payload(1, List.of()).length + 1);
        assertEquals(RecordException.Code.MALFORMED, rejected(trailing).code());
    }

    @Test
    void rejectsStringsAboveThePayloadLimit() {
        Map<String, CborValue> fields = loginFields(RecordFixtures.ID_A);
        fields.put("notes", new CborValue.Text("n".repeat(ONE_MIB + 1)));
        assertEquals(RecordException.Code.LIMIT, rejected(payload(1, List.of(fields))).code());
    }

    @Test
    void decodeRejectsNullAndClosedInput() {
        assertThrows(NullPointerException.class, () -> RecordCodec.decodePayload(null));
        assertThrows(NullPointerException.class, () -> RecordFixtures.encode(null));
        try (SecretBytes closed = SecretBytes.copyOf(payload(1, List.of()))) {
            RecordFixtures.closeNow(closed);
            assertThrows(IllegalStateException.class, () -> RecordCodec.decodePayload(closed));
        }
    }

    @Test
    void encodeRefusesARecordWhoseSecretIsClosed() {
        try (LoginRecord login = RecordFixtures.login(RecordFixtures.ID_A, "closed")) {
            RecordFixtures.closeNow(login);
            assertThrows(IllegalStateException.class, () -> RecordFixtures.encode(List.of(login)));
        }
        try (ProjectRecord project = RecordFixtures.project(RecordFixtures.ID_D, "closed")) {
            RecordFixtures.closeNow(project);
            assertThrows(IllegalStateException.class, () -> RecordFixtures.encode(List.of(project)));
        }
    }

    @Test
    void encodeLeavesTheCallersRecordsOpen() throws RecordException {
        List<VaultRecord> records = RecordFixtures.oneOfEach();
        assertEquals(records.size(), RecordFixtures.decodedCount(RecordFixtures.encode(records)));
        try (SecretBytes expected = RecordFixtures.secretOf("hunter2")) {
            assertEquals(expected, LoginRecord.class.cast(records.get(0)).password());
        }
        records.forEach(VaultRecord::close);
    }

    @Provide
    Arbitrary<List<VaultRecord>> recordLists() {
        return RecordFixtures.recordLists(MAX_RECORDS);
    }

    // ---- hand-built payloads -------------------------------------------------------------------

    private static RecordException rejected(byte[] payload) {
        return assertThrows(RecordException.class, () -> RecordFixtures.decodedCount(payload));
    }

    private static byte[] payload(long schemaVersion, List<Map<String, CborValue>> records) {
        List<CborValue> items = new ArrayList<>();
        for (Map<String, CborValue> fields : records) {
            items.add(new CborValue.MapV(fields));
        }
        return CborWriter.encode(new CborValue.MapV(Map.of(
                "schema_version", new CborValue.UInt(schemaVersion), "records", new CborValue.Array(items))));
    }

    private static Map<String, CborValue> loginFields(String id) {
        Map<String, CborValue> fields = new HashMap<>();
        fields.put("type", new CborValue.Text("login"));
        fields.put("id", new CborValue.Text(id));
        fields.put("title", new CborValue.Text("Bank"));
        fields.put("username", new CborValue.Text("alice"));
        fields.put("password", new CborValue.Bytes("hunter2".getBytes(StandardCharsets.UTF_8)));
        fields.put("urls", new CborValue.Array(List.of(new CborValue.Text("https://example.com"))));
        fields.put("notes", new CborValue.Text(""));
        fields.put("tags", new CborValue.Array(List.of()));
        fields.put("created", new CborValue.UInt(1));
        fields.put("updated", new CborValue.UInt(2));
        fields.put("last_used", new CborValue.UInt(3));
        return fields;
    }

    private static Map<String, CborValue> wifiFields(String id) {
        Map<String, CborValue> fields = new HashMap<>();
        fields.put("type", new CborValue.Text("wifi"));
        fields.put("id", new CborValue.Text(id));
        fields.put("title", new CborValue.Text("Home"));
        fields.put("ssid", new CborValue.Text("HomeNet"));
        fields.put("security", new CborValue.Text("WPA2"));
        fields.put("password", new CborValue.Bytes("wifi-value".getBytes(StandardCharsets.UTF_8)));
        fields.put("hidden", new CborValue.Bool(false));
        fields.put("notes", new CborValue.Text(""));
        fields.put("created", new CborValue.UInt(1));
        fields.put("updated", new CborValue.UInt(2));
        return fields;
    }
}
