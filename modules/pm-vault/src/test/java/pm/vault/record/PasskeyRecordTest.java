package pm.vault.record;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import pm.crypto.SecretBytes;
import pm.crypto.passkey.PasskeyKey;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/**
 * Passkey record model and codec (M6.2, ADR 0016 addendum, SR-085, SR-086): field bounds, display
 * safety and at least one visible character in names, no secret in {@code toString}, no public
 * accessor or constructor, the public codec refusing passkeys ({@code VAULT_ONLY}), the key checked
 * at decode, exact key set, u32 counter, and the CDDL matching what the codec writes.
 */
class PasskeyRecordTest {
    private static final HexFormat HEX = HexFormat.of();
    private static final UUID ID = UUID.fromString(RecordFixtures.ID_A);
    private static final Instant T0 = PasskeyFixtures.T0;
    private static final Path CDDL = Path.of("../../docs/schemas/records.cddl");
    private static final byte[] VALID_KEY = validKey();

    // ---- model ---------------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"example.com", "login.example.co.uk", "localhost", "xn--fa-hia.de", "a-b.c9",
            "a.b.c.d.e", "0.example"})
    void acceptsCanonicalRpIds(String rpId) {
        try (PasskeyRecord r = withRpId(rpId)) {
            assertEquals(rpId, r.rpId());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "Example.com", "example.com.", ".example.com", "exa mple.com", "-a.com", "a-.com",
            "a..com", "127.1", "0x7f.1", "1.2.3", "10", "faß.de", "例え.jp", "example.com:443", "https://example.com",
            "user@example.com", "[::1]", "a_b.com"})
    void refusesRpIdsThatAreNotCanonicalHostNames(String rpId) {
        assertThrows(IllegalArgumentException.class, () -> withRpId(rpId).close());
    }

    @Test
    void refusesOverlongRpIdsAndLabels() {
        String label63 = "a".repeat(63);
        String host253 = String.join(".", label63, label63, label63, "a".repeat(61));
        assertEquals(PasskeyRecord.MAX_RP_ID_CHARS, host253.length());
        withRpId(host253).close();
        assertThrows(IllegalArgumentException.class, () -> withRpId(host253 + "a").close());
        assertThrows(IllegalArgumentException.class, () -> withRpId("a".repeat(64) + ".com").close());
        assertThrows(IllegalArgumentException.class, () -> withRpId(String.join(".", "127", "0", "0", "1")).close());
    }

    @Test
    void boundsCredentialIdAndUserHandle() {
        for (int ok : new int[] {PasskeyRecord.MIN_CREDENTIAL_ID_BYTES, PasskeyRecord.MAX_CREDENTIAL_ID_BYTES}) {
            withBytes(new byte[ok], new byte[1]).close();
        }
        for (int bad : new int[] {0, PasskeyRecord.MIN_CREDENTIAL_ID_BYTES - 1, PasskeyRecord.MAX_CREDENTIAL_ID_BYTES + 1}) {
            assertThrows(IllegalArgumentException.class, () -> withBytes(new byte[bad], new byte[1]).close());
        }
        withBytes(new byte[16], new byte[PasskeyRecord.MAX_USER_HANDLE_BYTES]).close();
        for (int bad : new int[] {0, PasskeyRecord.MAX_USER_HANDLE_BYTES + 1}) {
            assertThrows(IllegalArgumentException.class, () -> withBytes(new byte[16], new byte[bad]).close());
        }
    }

    @Test
    void boundsTheSignCountToU32() {
        for (long ok : new long[] {0, 1, PasskeyRecord.MAX_SIGN_COUNT}) {
            try (PasskeyRecord r = withCount(ok)) {
                assertEquals(ok, r.signCount());
            }
        }
        for (long bad : new long[] {-1, PasskeyRecord.MAX_SIGN_COUNT + 1, Long.MAX_VALUE, Long.MIN_VALUE}) {
            assertThrows(IllegalArgumentException.class, () -> withCount(bad).close());
        }
        assertEquals(4_294_967_295L, PasskeyRecord.MAX_SIGN_COUNT);
    }

    @Test
    void privateKeyMustBeTheStorageFormLength() {
        for (int bad : new int[] {0, PasskeyRecord.PRIVATE_KEY_BYTES - 1, PasskeyRecord.PRIVATE_KEY_BYTES + 1}) {
            try (SecretBytes key = SecretBytes.takeOwnership(new byte[bad])) {
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> withKey(key).close());
                assertEquals("privateKey has the wrong length", e.getMessage());
            }
        }
        try (SecretBytes closed = SecretBytes.takeOwnership(new byte[1])) {
            RecordFixtures.closeNow(closed);
            withKey(closed).close();
        }
    }

    @ParameterizedTest
    @MethodSource("unsafeNames")
    void refusesNamesThatAreUnsafeToDisplay(String name) {
        assertThrows(IllegalArgumentException.class, () -> withNames(name, "ok").close());
        assertThrows(IllegalArgumentException.class, () -> withNames("ok", name).close());
        String safe = PasskeyRecord.displaySafe(name);
        withNames("x" + safe, safe).close();
    }

    @ParameterizedTest
    @MethodSource("invisibleNames")
    void refusesNamesWithNoVisibleCharacter(String name) {
        assertThrows(IllegalArgumentException.class, () -> withNames(name, "ok").close());
        assertThrows(IllegalArgumentException.class, () -> withNames("ok", name).close());
        Map<String, CborValue> fields = passkeyFields();
        fields.put("user_name", new CborValue.Text(name));
        assertEquals(RecordException.Code.SCHEMA, rejected(fields).code());
    }

    static List<String> invisibleNames() {
        return List.of(" ", "   ", u(0x3164, 0x3164), u(0x115F), u(0x1160), u(0xFFA0), u(0x2800), u(0x3000),
                u(0x00A0), u(0x0301), u(0x20DD), " " + u(0x3164) + " ", u(0xE000), u(0x0378),
                // M6.2 re-verification: blank symbols and spacing marks the blocklist let through.
                u(0x1D159), u(0x1D15A), u(0x1D159, 0x1D15A), u(0x0903), u(0x034F), u(0x17B4), u(0xFE0F),
                u(0xFE00), u(0xE0100), u(0x0E47), u(0x16FE4), u(0x2007), u(0x202F), u(0x0020, 0x0301));
    }

    @ParameterizedTest
    @MethodSource("visibleNames")
    void acceptsNamesWithALetterNumberPunctuationOrSymbol(String name) {
        try (PasskeyRecord r = withNames(name, name)) {
            assertEquals(name, r.accountName());
        }
    }

    static List<String> visibleNames() {
        return List.of("a", "7", "-", "@", u(0x20AC), u(0x1F600), u(0x4E2D), u(0x0661), u(0xFFFC),
                u(0x3164, 0x0041), u(0x1D15E));
    }

    @Test
    void anEmptyAccountNameIsRefusedButAnEmptyDisplayNameIsNot() {
        assertThrows(IllegalArgumentException.class, () -> withNames("", "ok").close());
        try (PasskeyRecord r = withNames("a" + u(0x3164), "")) {
            assertEquals("", r.displayName());
        }
        withNames("x", u(0x0041, 0x0301)).close();
    }

    static List<String> unsafeNames() {
        return List.of(u(0x202E) + "evil", "a" + u(0) + "b", "a\nb", "a\tb", "zero" + u(0x200B) + "width",
                u(0x2028), u(0x2029), u(0x1B) + "[31m", u(0x85), "lone" + u(0xD800), u(0xDC00),
                u(0x2066) + "x" + u(0x2069), u(0x061C), u(0x200E), u(0xFEFF));
    }

    @Test
    void displaySafeStripsAndTruncatesWithoutSplittingAPair() {
        assertEquals("evil", PasskeyRecord.displaySafe(u(0x202E) + "ev" + u(0x200B) + "il" + u(0) + "\n"));
        assertEquals("Ålice 😀", PasskeyRecord.displaySafe("Ålice 😀"));
        String nearlyFull = "a".repeat(PasskeyRecord.MAX_NAME_CHARS - 1);
        assertEquals(nearlyFull, PasskeyRecord.displaySafe(nearlyFull + "😀"));
        assertEquals(nearlyFull + "b", PasskeyRecord.displaySafe(nearlyFull + "😀b"));
        assertEquals(PasskeyRecord.MAX_NAME_CHARS,
                PasskeyRecord.displaySafe("x".repeat(PasskeyRecord.MAX_NAME_CHARS * 2)).length());
        withNames(nearlyFull + "b", "Ålice 😀").close();
        assertThrows(IllegalArgumentException.class,
                () -> withNames("x".repeat(PasskeyRecord.MAX_NAME_CHARS + 1), "ok").close());
    }

    @Test
    void accessorsReturnCopies() {
        byte[] credentialId = PasskeyFixtures.credentialId();
        try (PasskeyRecord r = new PasskeyRecord(ID, "t", "example.com", credentialId, PasskeyFixtures.userHandle(),
                "u", "d", key(), 0, T0, T0, T0)) {
            credentialId[0] ^= 1;
            assertArrayEquals(PasskeyFixtures.credentialId(), r.credentialId());
            r.credentialId()[0] ^= 1;
            r.userHandle()[0] ^= 1;
            assertArrayEquals(PasskeyFixtures.credentialId(), r.credentialId());
            assertArrayEquals(PasskeyFixtures.userHandle(), r.userHandle());
        }
    }

    @Test
    void toStringShowsNoSecretOrIdentifyingBytes() {
        try (PasskeyRecord r = PasskeyFixtures.passkey(RecordFixtures.ID_A)) {
            String text = r.toString();
            byte[] stored = PasskeyFixtures.storedKey(r);
            assertFalse(text.contains(HEX.formatHex(stored).substring(2, 66)));
            assertFalse(text.toLowerCase(java.util.Locale.ROOT).contains(HEX.formatHex(PasskeyFixtures.credentialId())));
            assertFalse(text.contains(HEX.formatHex(PasskeyFixtures.userHandle())));
            assertFalse(text.contains("alice"));
            assertTrue(text.contains("example.com"));
        }
    }

    @Test
    void noPublicMethodHandsOutTheKeyOrAdvancesTheCounter() {
        assertEquals(0, PasskeyRecord.class.getConstructors().length, "no public constructor");
        for (Method m : PasskeyRecord.class.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers())) {
                assertNotEquals(SecretBytes.class, m.getReturnType(), m.getName());
                assertNotEquals(PasskeyKey.class, m.getReturnType(), m.getName());
                assertFalse(!Modifier.isStatic(m.getModifiers()) && m.getReturnType() == PasskeyRecord.class,
                        m.getName());
            }
        }
    }

    @Test
    void closeZeroFillsTheKey() {
        try (PasskeyRecord r = PasskeyFixtures.passkey(RecordFixtures.ID_A)) {
            assertFalse(r.privateKey().isClosed());
            RecordFixtures.closeNow(r);
            RecordFixtures.closeNow(r);
            assertTrue(r.privateKey().isClosed());
        }
    }

    @Test
    void searchCoversRpIdAndNamesButNotIdentifiers() {
        try (PasskeyRecord r = PasskeyFixtures.passkey(RecordFixtures.ID_A)) {
            assertTrue(RecordSearch.matches(r, "EXAMPLE.COM"));
            assertTrue(RecordSearch.matches(r, "alice@"));
            assertTrue(RecordSearch.matches(r, "Alice"));
            assertTrue(RecordSearch.matches(r, "examp"));
            assertFalse(RecordSearch.matches(r, HEX.formatHex(PasskeyFixtures.credentialId())));
            assertFalse(RecordSearch.matches(r, "3333"));
            assertFalse(RecordSearch.matches(r, "nothing-like-it"));
        }
        try (PasskeyRecord other = withNames("bob", "Robert")) {
            assertTrue(RecordSearch.matches(other, "robert"));
            assertFalse(RecordSearch.matches(other, "alice"));
        }
    }

    // ---- codec ---------------------------------------------------------------------------------

    @Test
    void roundTripsThroughThePayloadWithEveryField() throws RecordException {
        try (PasskeyRecord original = new PasskeyRecord(ID, "Example", "example.com", PasskeyFixtures.credentialId(),
                     PasskeyFixtures.userHandle(), "alice@example.com", "Ålice 😀", key(),
                     PasskeyRecord.MAX_SIGN_COUNT, T0, T0.plusSeconds(5), T0.plusSeconds(10).plusNanos(7));
             LoginRecord login = RecordFixtures.login(RecordFixtures.ID_B, "Bank")) {
            byte[] payload = RecordFixtures.encodeVault(List.of(original, login));
            try (SecretBytes plaintext = SecretBytes.copyOf(payload)) {
                List<VaultRecord> decoded = RecordCodec.decodeVaultPayload(plaintext);
                try {
                    assertEquals(2, decoded.size());
                    assertSamePasskey(original, decoded.get(0));
                    assertEquals(HEX.formatHex(payload), HEX.formatHex(RecordFixtures.encodeVault(decoded)));
                } finally {
                    decoded.forEach(VaultRecord::close);
                }
            }
        }
    }

    private static void assertSamePasskey(PasskeyRecord original, VaultRecord decoded) {
        assertInstanceOf(PasskeyRecord.class, decoded);
        assertSamePasskeyFields(original, PasskeyRecord.class.cast(decoded));
    }

    private static void assertSamePasskeyFields(PasskeyRecord original, PasskeyRecord back) {
        assertEquals(original.id(), back.id());
        assertEquals(original.title(), back.title());
        assertEquals(original.rpId(), back.rpId());
        assertArrayEquals(original.credentialId(), back.credentialId());
        assertArrayEquals(original.userHandle(), back.userHandle());
        assertEquals(original.accountName(), back.accountName());
        assertEquals(original.displayName(), back.displayName());
        assertArrayEquals(PasskeyFixtures.storedKey(original), PasskeyFixtures.storedKey(back));
        assertEquals(PasskeyRecord.MAX_SIGN_COUNT, back.signCount());
        assertEquals(original.created(), back.created());
        assertEquals(original.updated(), back.updated());
        assertEquals(T0.plusSeconds(10), back.lastUsed());
    }

    @Test
    void thePublicCodecRefusesPasskeysBothWays() throws RecordException {
        try (PasskeyRecord passkey = PasskeyFixtures.passkey(RecordFixtures.ID_A);
             LoginRecord login = RecordFixtures.login(RecordFixtures.ID_B, "Bank")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> RecordCodec.encodePayload(List.of(login, passkey)).close());
            assertTrue(e.getMessage().startsWith("VAULT_ONLY"), e.getMessage());
            assertFalse(passkey.privateKey().isClosed());
            byte[] payload = RecordFixtures.encodeVault(List.of(login, passkey));
            RecordException refused = assertThrows(RecordException.class, () -> RecordFixtures.decodedCount(payload));
            assertEquals(RecordException.Code.VAULT_ONLY, refused.code());
            assertEquals(2, RecordFixtures.decodedVaultCount(payload));
            assertEquals(1, RecordFixtures.decodedCount(RecordFixtures.encode(List.of(login))));
        }
    }

    @Test
    void aKeyThatDoesNotLoadIsRefusedAtDecode() {
        byte[] flipped = VALID_KEY.clone();
        flipped[PasskeyRecord.PRIVATE_KEY_BYTES - 1] ^= 1;
        byte[] scalarZero = VALID_KEY.clone();
        java.util.Arrays.fill(scalarZero, 1, 33, (byte) 0);
        for (byte[] bad : List.of(new byte[PasskeyRecord.PRIVATE_KEY_BYTES], flipped, scalarZero)) {
            Map<String, CborValue> fields = passkeyFields();
            fields.put("private_key", new CborValue.Bytes(bad));
            RecordException e = rejected(fields);
            assertEquals(RecordException.Code.SCHEMA, e.code());
            assertFalse(e.getMessage().contains(HEX.formatHex(bad, 1, 9)));
        }
    }

    @Test
    void theKeySetIsExact() {
        Map<String, CborValue> fields = passkeyFields();
        assertEquals(1, decode(fields));
        for (String key : fields.keySet()) {
            Map<String, CborValue> missing = passkeyFields();
            missing.remove(key);
            assertEquals(RecordException.Code.SCHEMA, rejected(missing).code(), key);
        }
        Map<String, CborValue> extra = passkeyFields();
        extra.put("future_field", new CborValue.UInt(1));
        assertEquals(RecordException.Code.SCHEMA, rejected(extra).code());
    }

    @Test
    void signCountAboveU32IsALimitRejection() {
        for (long bad : new long[] {PasskeyRecord.MAX_SIGN_COUNT + 1, Long.MAX_VALUE}) {
            Map<String, CborValue> fields = passkeyFields();
            fields.put("sign_count", new CborValue.UInt(bad));
            assertEquals(RecordException.Code.LIMIT, rejected(fields).code());
        }
    }

    @Test
    void fieldsTheModelRefusesRejectThePayload() {
        Map<String, CborValue> wrong = new HashMap<>();
        wrong.put("private_key", new CborValue.Bytes(new byte[PasskeyRecord.PRIVATE_KEY_BYTES - 1]));
        wrong.put("credential_id", new CborValue.Bytes(new byte[PasskeyRecord.MIN_CREDENTIAL_ID_BYTES - 1]));
        wrong.put("user_handle", new CborValue.Bytes(new byte[0]));
        wrong.put("rp_id", new CborValue.Text("Example.COM"));
        wrong.put("user_name", new CborValue.Text(u(0x202E) + "evil"));
        wrong.put("display_name", new CborValue.Text("x".repeat(PasskeyRecord.MAX_NAME_CHARS + 1)));
        for (Map.Entry<String, CborValue> entry : wrong.entrySet()) {
            Map<String, CborValue> fields = passkeyFields();
            fields.put(entry.getKey(), entry.getValue());
            assertEquals(RecordException.Code.SCHEMA, rejected(fields).code(), entry.getKey());
        }
        Map<String, CborValue> textKey = passkeyFields();
        textKey.put("private_key", new CborValue.Text("not bytes"));
        assertEquals(RecordException.Code.SCHEMA, rejected(textKey).code());
        Map<String, CborValue> textCount = passkeyFields();
        textCount.put("sign_count", new CborValue.Text("1"));
        assertEquals(RecordException.Code.SCHEMA, rejected(textCount).code());
    }

    @Test
    void theCddlListsExactlyTheKeysTheCodecWrites() throws IOException, CborException {
        String cddl = Files.readString(CDDL, StandardCharsets.UTF_8);
        int start = cddl.indexOf("passkey-record = {");
        assertTrue(start >= 0, "passkey-record rule");
        String rule = cddl.substring(start, cddl.indexOf('}', start));
        Set<String> documented = new TreeSet<>();
        Matcher m = Pattern.compile("\"([a-z_]+)\"\\s*=>").matcher(rule);
        while (m.find()) {
            documented.add(m.group(1));
        }
        assertTrue(Pattern.compile("\"type\"\\s*=>\\s*\"passkey\"").matcher(rule).find());
        assertTrue(rule.contains("bstr .size 98"));
        assertTrue(rule.contains("0..4294967295"));
        assertTrue(cddl.contains("record //= passkey-record"));
        try (PasskeyRecord r = PasskeyFixtures.passkey(RecordFixtures.ID_A)) {
            CborValue root = CborReader.decode(RecordFixtures.encodeVault(List.of(r)), CborLimits.PAYLOAD);
            CborValue.Array records = assertInstanceOf(CborValue.Array.class,
                    assertInstanceOf(CborValue.MapV.class, root).entries().get("records"));
            Map<String, CborValue> written = assertInstanceOf(CborValue.MapV.class, records.items().get(0)).entries();
            assertEquals(documented, new TreeSet<>(written.keySet()));
            assertEquals(new TreeSet<>(passkeyFields().keySet()), documented);
            root.wipe();
        }
    }

    // ---- helpers -------------------------------------------------------------------------------

    /** The string of the given code points; lone surrogates included. */
    private static String u(int... codePoints) {
        StringBuilder out = new StringBuilder();
        for (int cp : codePoints) {
            out.appendCodePoint(cp);
        }
        return out.toString();
    }

    private static byte[] validKey() {
        try (SecretBytes stored = key()) {
            return stored.apply(bytes -> java.util.Arrays.copyOf(bytes, bytes.length));
        }
    }

    private static SecretBytes key() {
        try (PasskeyKey k = PasskeyKey.generate()) {
            return pm.crypto.passkey.storage.PasskeyStorage.toStorage(k);
        }
    }

    private static PasskeyRecord withRpId(String rpId) {
        return new PasskeyRecord(ID, "t", rpId, new byte[16], new byte[1], "u", "d", key(), 0, T0, T0, T0);
    }

    private static PasskeyRecord withBytes(byte[] credentialId, byte[] userHandle) {
        return new PasskeyRecord(ID, "t", "example.com", credentialId, userHandle, "u", "d", key(), 0, T0, T0, T0);
    }

    private static PasskeyRecord withCount(long count) {
        return new PasskeyRecord(ID, "t", "example.com", new byte[16], new byte[1], "u", "d", key(), count, T0, T0, T0);
    }

    private static PasskeyRecord withKey(SecretBytes key) {
        return new PasskeyRecord(ID, "t", "example.com", new byte[16], new byte[1], "u", "d", key, 0, T0, T0, T0);
    }

    private static PasskeyRecord withNames(String userName, String displayName) {
        return new PasskeyRecord(ID, "t", "example.com", new byte[16], new byte[1], userName, displayName, key(), 0,
                T0, T0, T0);
    }

    private static Map<String, CborValue> passkeyFields() {
        Map<String, CborValue> fields = new HashMap<>();
        fields.put("type", new CborValue.Text("passkey"));
        fields.put("id", new CborValue.Text(RecordFixtures.ID_A));
        fields.put("title", new CborValue.Text("Example"));
        fields.put("rp_id", new CborValue.Text("example.com"));
        fields.put("credential_id", new CborValue.Bytes(PasskeyFixtures.credentialId()));
        fields.put("user_handle", new CborValue.Bytes(PasskeyFixtures.userHandle()));
        fields.put("user_name", new CborValue.Text("alice"));
        fields.put("display_name", new CborValue.Text("Alice"));
        fields.put("private_key", new CborValue.Bytes(VALID_KEY.clone()));
        fields.put("sign_count", new CborValue.UInt(7));
        fields.put("created", new CborValue.UInt(1));
        fields.put("updated", new CborValue.UInt(2));
        fields.put("last_used", new CborValue.UInt(3));
        return fields;
    }

    private static byte[] payload(Map<String, CborValue> fields) {
        return CborWriter.encode(new CborValue.MapV(Map.of(
                "schema_version", new CborValue.UInt(1),
                "records", new CborValue.Array(List.of(new CborValue.MapV(fields))))));
    }

    private static int decode(Map<String, CborValue> fields) {
        try {
            return RecordFixtures.decodedVaultCount(payload(fields));
        } catch (RecordException e) {
            throw new AssertionError(e);
        }
    }

    private static RecordException rejected(Map<String, CborValue> fields) {
        return assertThrows(RecordException.class, () -> RecordFixtures.decodedVaultCount(payload(fields)));
    }
}
