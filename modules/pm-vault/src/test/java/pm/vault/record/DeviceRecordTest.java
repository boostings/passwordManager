package pm.vault.record;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import pm.crypto.DeviceIdentity;
import pm.crypto.SecretBytes;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/**
 * The two LAN sharing records (M3.6, lan-share.md §1, §5, §8): model validation, codec round trip
 * with the documented byte-string encoding, schema rejections, and that they are internal (never
 * searched).
 */
class DeviceRecordTest {
    private static final Instant T0 = RecordFixtures.T0;
    private static final byte[] KEY = filled(32, 7);
    private static final byte[] CERT = filled(40, 3);
    private static final String SHARE_A = "0a".repeat(16);
    private static final String SHARE_B = "0b".repeat(16);

    @Test
    void identityAndTrustedDeviceRoundTripThroughThePayload() throws RecordException {
        List<VaultRecord> records = List.of(identity("laptop"), trusted("phone", KEY), RecordFixtures.login(
                RecordFixtures.ID_C, "Bank"));
        try (SecretBytes payload = RecordCodec.encodePayload(records)) {
            List<VaultRecord> decoded = RecordCodec.decodePayload(payload);
            assertEquals(records, decoded);
            assertArrayEquals(CERT, DeviceIdentityRecord.class.cast(decoded.get(0)).certificateDer());
            assertArrayEquals(KEY, TrustedDeviceRecord.class.cast(decoded.get(1)).rawPublicKey());
            assertEquals(DeviceIdentity.fingerprint(KEY), TrustedDeviceRecord.class.cast(decoded.get(1)).fingerprint());
            assertEquals(T0, TrustedDeviceRecord.class.cast(decoded.get(1)).pairedAt());
            decoded.forEach(VaultRecord::close);
        }
        records.forEach(VaultRecord::close);
    }

    @Test
    void keysAndCertificatesAreStoredAsByteStrings() throws RecordException {
        Map<String, CborValue> device = trustedFields();
        device.put("public_key", new CborValue.Text("00".repeat(32)));
        assertEquals(RecordException.Code.SCHEMA, rejected(payload(device)).code());

        Map<String, CborValue> shortKey = trustedFields();
        shortKey.put("public_key", new CborValue.Bytes(new byte[31]));
        assertEquals(RecordException.Code.SCHEMA, rejected(payload(shortKey)).code());

        Map<String, CborValue> identity = identityFields();
        identity.put("certificate", new CborValue.Text("AAAA"));
        assertEquals(RecordException.Code.SCHEMA, rejected(payload(identity)).code());
        assertEquals(1, RecordFixtures.decodedCount(payload(identityFields())));
        assertEquals(1, RecordFixtures.decodedCount(payload(trustedFields())));
    }

    @Test
    void decodeRejectsAFingerprintThatIsNotTheKeys() {
        Map<String, CborValue> device = trustedFields();
        device.put("fingerprint", new CborValue.Text(DeviceIdentity.fingerprint(filled(32, 8))));
        assertEquals(RecordException.Code.SCHEMA, rejected(payload(device)).code());
    }

    @Test
    void decodeRejectsMissingFields() {
        for (String key : List.of("private_key", "certificate", "title", "created")) {
            Map<String, CborValue> identity = identityFields();
            identity.remove(key);
            assertEquals(RecordException.Code.SCHEMA, rejected(payload(identity)).code(), key);
        }
        for (String key : List.of("public_key", "fingerprint", "shared", "received", "updated")) {
            Map<String, CborValue> device = trustedFields();
            device.remove(key);
            assertEquals(RecordException.Code.SCHEMA, rejected(payload(device)).code(), key);
        }
    }

    @Test
    void sharedItemsAreKeptInOrderWithoutRepeatsAndBounded() throws RecordException {
        UUID a = UUID.fromString(RecordFixtures.ID_C);
        UUID b = UUID.fromString(RecordFixtures.ID_D);
        try (TrustedDeviceRecord device = trusted("phone", KEY).withShared(a, T0.plusSeconds(1)).withShared(b, T0)
                .withShared(a, T0.plusSeconds(2));
                TrustedDeviceRecord renamed = device.renamed("tablet", T0.plusSeconds(9))) {
            assertEquals(List.of(b, a), device.shared());
            assertEquals(T0.plusSeconds(2), device.updated());
            assertEquals(T0, device.pairedAt());
            assertEquals(List.of(device), decode(RecordFixtures.encode(List.of(device))));
            assertEquals("tablet", renamed.title());
            assertEquals(device.shared(), renamed.shared());
            assertEquals(T0.plusSeconds(9), renamed.pairedAt());
        }
        List<UUID> kept = sharedOneMoreThanTheBound();
        assertEquals(TrustedDeviceRecord.MAX_SHARED, kept.size());
        assertEquals(new UUID(0, 1), kept.get(0), "the oldest is dropped");

        Map<String, CborValue> bad = trustedFields();
        bad.put("shared", new CborValue.Array(List.of(new CborValue.Text("not-a-uuid"))));
        assertEquals(RecordException.Code.SCHEMA, rejected(payload(bad)).code());
    }

    @Test
    void receivedSharesAreKeptUntilTheyExpireWithoutRepeatsAndBounded() throws RecordException {
        try (TrustedDeviceRecord device = trusted("phone", KEY)
                .withReceived(SHARE_A, T0.plusSeconds(60), T0)
                .withReceived(SHARE_B, T0.plusSeconds(600), T0.plusSeconds(1))) {
            assertTrue(device.hasReceived(SHARE_A, T0.plusSeconds(59)));
            assertFalse(device.hasReceived(SHARE_A, T0.plusSeconds(60)), "an expired entry no longer counts");
            assertEquals(List.of(device), decode(RecordFixtures.encode(List.of(device))), "stored in the vault");
            try (TrustedDeviceRecord later = device.withReceived(SHARE_B, T0.plusSeconds(900), T0.plusSeconds(61));
                    TrustedDeviceRecord renamed = later.renamed("tablet", T0.plusSeconds(62))) {
                assertEquals(List.of(new TrustedDeviceRecord.Received(SHARE_B, T0.plusSeconds(900))), later.received(),
                        "expired entries are dropped and an id is listed once");
                assertEquals(later.received(), renamed.received());
            }
        }
        List<TrustedDeviceRecord.Received> kept = receivedOneMoreThanTheBound();
        assertEquals(TrustedDeviceRecord.MAX_RECEIVED, kept.size());
        assertEquals(shareId(1), kept.get(0).shareId(), "the oldest is dropped");
        assertThrows(IllegalArgumentException.class, () -> new TrustedDeviceRecord.Received("AB".repeat(16), T0));
        assertThrows(IllegalArgumentException.class, () -> new TrustedDeviceRecord(UUID.randomUUID(), "p",
                "07".repeat(32), DeviceIdentity.fingerprint(KEY), List.of(),
                List.of(new TrustedDeviceRecord.Received(SHARE_A, T0), new TrustedDeviceRecord.Received(SHARE_A, T0)),
                T0, T0));

        for (String entry : List.of(SHARE_A, SHARE_A + "@", SHARE_A + "@-1", SHARE_A + "@01", "zz" + SHARE_A + "@1")) {
            Map<String, CborValue> bad = trustedFields();
            bad.put("received", new CborValue.Array(List.of(new CborValue.Text(entry))));
            assertEquals(RecordException.Code.SCHEMA, rejected(payload(bad)).code(), entry);
        }
    }

    private static List<TrustedDeviceRecord.Received> receivedOneMoreThanTheBound() {
        return java.util.stream.IntStream.rangeClosed(0, TrustedDeviceRecord.MAX_RECEIVED)
                .mapToObj(DeviceRecordTest::shareId)
                .reduce(trusted("phone", KEY), (d, id) -> d.withReceived(id, T0.plusSeconds(60), T0), (x, y) -> y)
                .received();
    }

    private static String shareId(int n) {
        return "0".repeat(16) + java.util.HexFormat.of().toHexDigits((long) n);
    }

    private static List<UUID> sharedOneMoreThanTheBound() {
        return java.util.stream.IntStream.rangeClosed(0, TrustedDeviceRecord.MAX_SHARED)
                .mapToObj(i -> new UUID(0, i))
                .reduce(trusted("phone", KEY), (d, id) -> d.withShared(id, T0), (x, y) -> y).shared();
    }

    private static List<VaultRecord> decode(byte[] payload) throws RecordException {
        try (SecretBytes plaintext = SecretBytes.copyOf(payload)) {
            return RecordCodec.decodePayload(plaintext);
        }
    }

    @Test
    void namesAreShortPrintableText() {
        UUID id = UUID.randomUUID();
        for (String bad : List.of("", "x".repeat(33), around(0x07), around(0x202E), around(0x2028),
                around(0x2029), around(0x0A), around(0x200B))) {
            assertThrows(IllegalArgumentException.class, () -> TrustedDeviceRecord.of(id, bad, KEY, T0), bad);
        }
        assertThrows(NullPointerException.class, () -> TrustedDeviceRecord.of(id, null, KEY, T0));
        assertEquals("x".repeat(32), TrustedDeviceRecord.of(id, "x".repeat(32), KEY, T0).title());
        assertEquals("Büro-Laptop ☕", TrustedDeviceRecord.of(id, "Büro-Laptop ☕", KEY, T0).title());
    }

    @Test
    void trustedDeviceValidatesKeyAndFingerprint() {
        UUID id = UUID.randomUUID();
        String fp = DeviceIdentity.fingerprint(KEY);
        assertThrows(IllegalArgumentException.class,
                () -> new TrustedDeviceRecord(id, "p", "AB".repeat(32), fp, List.of(), List.of(), T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new TrustedDeviceRecord(id, "p", "ab".repeat(31), fp, List.of(), List.of(), T0, T0));
        assertThrows(IllegalArgumentException.class, () -> new TrustedDeviceRecord(id, "p", "07".repeat(32),
                DeviceIdentity.fingerprint(filled(32, 9)), List.of(), List.of(), T0, T0));
        assertThrows(NullPointerException.class, () -> new TrustedDeviceRecord(id, "p", null, fp, List.of(), List.of(), T0, T0));
        assertThrows(NullPointerException.class,
                () -> new TrustedDeviceRecord(id, "p", "07".repeat(32), null, List.of(), List.of(), T0, T0));
        assertThrows(NullPointerException.class,
                () -> new TrustedDeviceRecord(null, "p", "07".repeat(32), fp, List.of(), List.of(), T0, T0));
        assertThrows(IllegalArgumentException.class, () -> new TrustedDeviceRecord(id, "p", "07".repeat(32), fp,
                List.of(id, id), List.of(), T0, T0));
        assertThrows(NullPointerException.class,
                () -> new TrustedDeviceRecord(id, "p", "07".repeat(32), fp, null, List.of(), T0, T0));
        try (TrustedDeviceRecord ok = new TrustedDeviceRecord(id, "p", "07".repeat(32), fp, List.of(), List.of(), T0, T0)) {
            byte[] raw = ok.rawPublicKey();
            raw[0] = 0;
            assertArrayEquals(KEY, ok.rawPublicKey(), "a copy, not the record's state");
        }
    }

    @Test
    void identityValidatesCertificateAndOwnsItsKey() {
        UUID id = UUID.randomUUID();
        try (SecretBytes key = SecretBytes.copyOf(filled(48, 1))) {
            assertThrows(IllegalArgumentException.class, () -> new DeviceIdentityRecord(id, "me", key, "", T0, T0));
            assertThrows(IllegalArgumentException.class,
                    () -> new DeviceIdentityRecord(id, "me", key, "not base64!", T0, T0));
            assertThrows(IllegalArgumentException.class,
                    () -> new DeviceIdentityRecord(id, "me", key, "A".repeat(16_388), T0, T0));
            assertThrows(NullPointerException.class, () -> new DeviceIdentityRecord(null, "me", key, "AAAA", T0, T0));
        }
        try (DeviceIdentityRecord identity = identity("me")) {
            RecordFixtures.closeNow(identity);
            assertTrue(identity.privateKey().isClosed());
        }
    }

    @Test
    void deviceRecordsAreInternalAndNeverSearched() {
        try (TrustedDeviceRecord device = trusted("phone", KEY);
                DeviceIdentityRecord identity = identity("laptop");
                LoginRecord login = RecordFixtures.login(RecordFixtures.ID_A, "phone bill")) {
            assertTrue(DeviceRecord.isInternal(device));
            assertTrue(DeviceRecord.isInternal(identity));
            assertFalse(DeviceRecord.isInternal(login));
            assertFalse(RecordSearch.matches(device, "phone"));
            assertFalse(RecordSearch.matches(identity, ""));
            assertTrue(RecordSearch.matches(login, "phone"));
        }
    }

    // ---- helpers -------------------------------------------------------------------------------

    private static DeviceIdentityRecord identity(String name) {
        return DeviceIdentityRecord.of(UUID.fromString(RecordFixtures.ID_A), name, SecretBytes.copyOf(filled(48, 1)),
                CERT, T0);
    }

    private static TrustedDeviceRecord trusted(String name, byte[] key) {
        return TrustedDeviceRecord.of(UUID.fromString(RecordFixtures.ID_B), name, key, T0);
    }

    private static String around(int codePoint) {
        return "a" + Character.toString(codePoint) + "b";
    }

    private static byte[] filled(int length, int value) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) value);
        return out;
    }

    private static RecordException rejected(byte[] payload) {
        return assertThrows(RecordException.class, () -> RecordFixtures.decodedCount(payload));
    }

    private static byte[] payload(Map<String, CborValue> fields) {
        List<CborValue> items = new ArrayList<>();
        items.add(new CborValue.MapV(fields));
        return CborWriter.encode(new CborValue.MapV(Map.of(
                "schema_version", new CborValue.UInt(1), "records", new CborValue.Array(items))));
    }

    private static Map<String, CborValue> identityFields() {
        Map<String, CborValue> fields = new HashMap<>();
        fields.put("type", new CborValue.Text("device_identity"));
        fields.put("id", new CborValue.Text(RecordFixtures.ID_A));
        fields.put("title", new CborValue.Text("laptop"));
        fields.put("private_key", new CborValue.Bytes("pkcs8".getBytes(StandardCharsets.UTF_8)));
        fields.put("certificate", new CborValue.Bytes(CERT));
        fields.put("created", new CborValue.UInt(1));
        fields.put("updated", new CborValue.UInt(2));
        return fields;
    }

    private static Map<String, CborValue> trustedFields() {
        Map<String, CborValue> fields = new HashMap<>();
        fields.put("type", new CborValue.Text("trusted_device"));
        fields.put("id", new CborValue.Text(RecordFixtures.ID_B));
        fields.put("title", new CborValue.Text("phone"));
        fields.put("public_key", new CborValue.Bytes(KEY.clone()));
        fields.put("fingerprint", new CborValue.Text(DeviceIdentity.fingerprint(KEY)));
        fields.put("shared", new CborValue.Array(List.of(new CborValue.Text(RecordFixtures.ID_C))));
        fields.put("received", new CborValue.Array(List.of(new CborValue.Text(SHARE_A + "@5"))));
        fields.put("created", new CborValue.UInt(1));
        fields.put("updated", new CborValue.UInt(1));
        return fields;
    }
}
