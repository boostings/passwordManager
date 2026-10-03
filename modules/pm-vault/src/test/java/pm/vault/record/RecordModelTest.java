package pm.vault.record;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import pm.crypto.SecretBytes;

/**
 * Compact-constructor validation, defensive copies, secret ownership and equality of the four
 * record types (sprint plan section 2 D, MET00-J, OBJ06-J, ADR 0008).
 */
class RecordModelTest {
    private static final UUID ID = UUID.fromString(RecordFixtures.ID_A);
    private static final Instant T0 = RecordFixtures.T0;
    private static final Instant LAST_INSTANT = Instant.parse("9999-12-31T23:59:59Z");

    // ---- bounds --------------------------------------------------------------------------------

    @Test
    void titleIsBoundedAt256Characters() {
        try (LoginRecord atLimit = loginTitled("t".repeat(FieldRules.MAX_TITLE_CHARS))) {
            assertEquals(FieldRules.MAX_TITLE_CHARS, atLimit.title().length());
        }
        String tooLong = "t".repeat(FieldRules.MAX_TITLE_CHARS + 1);
        assertThrows(IllegalArgumentException.class, () -> loginTitled(tooLong));
        assertThrows(IllegalArgumentException.class,
                () -> new WifiRecord(ID, tooLong, "ssid", "WPA2", secret(), false, "", T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new SshKeyRecord(ID, tooLong, "ed25519", secret(), "", "", "", List.of(), T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new ProjectRecord(ID, tooLong, "", "", Map.of(), Map.of(), T0, T0));
    }

    @Test
    void notesAndCommentAreBoundedAt64KiBCharacters() {
        String atLimit = "n".repeat(FieldRules.MAX_NOTES_CHARS);
        String tooLong = atLimit + "n";
        try (LoginRecord login = new LoginRecord(ID, "t", "u", secret(), List.of(), atLimit, List.of(), T0, T0, T0);
             SshKeyRecord ssh = new SshKeyRecord(ID, "t", "ed25519", secret(), "", "", atLimit, List.of(), T0, T0)) {
            assertEquals(login.notes(), ssh.comment());
        }
        assertThrows(IllegalArgumentException.class,
                () -> new LoginRecord(ID, "t", "u", secret(), List.of(), tooLong, List.of(), T0, T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new WifiRecord(ID, "t", "ssid", "WPA2", secret(), false, tooLong, T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new SshKeyRecord(ID, "t", "ed25519", secret(), "", "", tooLong, List.of(), T0, T0));
    }

    @Test
    void urlsTagsAndHostsAreBoundedAt64Entries() {
        List<String> atLimit = Collections.nCopies(FieldRules.MAX_LIST_ITEMS, "x");
        List<String> tooMany = Collections.nCopies(FieldRules.MAX_LIST_ITEMS + 1, "x");
        try (LoginRecord login = new LoginRecord(ID, "t", "u", secret(), atLimit, "", atLimit, T0, T0, T0);
             SshKeyRecord ssh = new SshKeyRecord(ID, "t", "ed25519", secret(), "", "", "", atLimit, T0, T0)) {
            assertEquals(login.urls(), ssh.hosts());
        }
        assertThrows(IllegalArgumentException.class,
                () -> new LoginRecord(ID, "t", "u", secret(), tooMany, "", List.of(), T0, T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new LoginRecord(ID, "t", "u", secret(), List.of(), "", tooMany, T0, T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new SshKeyRecord(ID, "t", "ed25519", secret(), "", "", "", tooMany, T0, T0));
    }

    @Test
    void everyTextFieldAndListElementIsBounded() {
        String shortOver = "x".repeat(FieldRules.MAX_SHORT_TEXT_CHARS + 1);
        String urlOver = "x".repeat(FieldRules.MAX_URL_CHARS + 1);
        String keyOver = "x".repeat(FieldRules.MAX_PUBLIC_KEY_CHARS + 1);
        String pathOver = "x".repeat(FieldRules.MAX_PATH_CHARS + 1);
        assertThrows(IllegalArgumentException.class,
                () -> new LoginRecord(ID, "t", shortOver, secret(), List.of(), "", List.of(), T0, T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new LoginRecord(ID, "t", "u", secret(), List.of(urlOver), "", List.of(), T0, T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new LoginRecord(ID, "t", "u", secret(), List.of(), "", List.of(shortOver), T0, T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new WifiRecord(ID, "t", shortOver, "WPA2", secret(), false, "", T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new SshKeyRecord(ID, "t", shortOver, secret(), "", "", "", List.of(), T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new SshKeyRecord(ID, "t", "ed25519", secret(), keyOver, "", "", List.of(), T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new SshKeyRecord(ID, "t", "ed25519", secret(), "", shortOver, "", List.of(), T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new SshKeyRecord(ID, "t", "ed25519", secret(), "", "", "", List.of(shortOver), T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new ProjectRecord(ID, "t", pathOver, "", Map.of(), Map.of(), T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new ProjectRecord(ID, "t", "", urlOver, Map.of(), Map.of(), T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new ProjectRecord(ID, "t", "", "", Map.of(shortOver, secret()), Map.of(), T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new ProjectRecord(ID, "t", "", "", Map.of(), Map.of(shortOver, "v"), T0, T0));
        assertThrows(IllegalArgumentException.class, () -> new ProjectRecord(ID, "t", "", "", Map.of(),
                Map.of("k", "v".repeat(FieldRules.MAX_NOTES_CHARS + 1)), T0, T0));
    }

    @Test
    void secretsAreBoundedAt64KiB() {
        try (LoginRecord atLimit = new LoginRecord(ID, "t", "u",
                SecretBytes.copyOf(new byte[FieldRules.MAX_SECRET_BYTES]), List.of(), "", List.of(), T0, T0, T0)) {
            assertEquals(FieldRules.MAX_SECRET_BYTES, atLimit.password().length());
        }
        byte[] tooLarge = new byte[FieldRules.MAX_SECRET_BYTES + 1];
        assertThrows(IllegalArgumentException.class, () -> new LoginRecord(ID, "t", "u",
                SecretBytes.copyOf(tooLarge), List.of(), "", List.of(), T0, T0, T0));
        assertThrows(IllegalArgumentException.class, () -> new WifiRecord(ID, "t", "ssid", "WPA2",
                SecretBytes.copyOf(tooLarge), false, "", T0, T0));
        assertThrows(IllegalArgumentException.class, () -> new SshKeyRecord(ID, "t", "ed25519",
                SecretBytes.copyOf(tooLarge), "", "", "", List.of(), T0, T0));
        assertThrows(IllegalArgumentException.class, () -> new ProjectRecord(ID, "t", "", "",
                Map.of("BIG", SecretBytes.copyOf(tooLarge)), Map.of(), T0, T0));
    }

    @Test
    void projectMapsAreBoundedAt1024Entries() {
        Map<String, String> config = new HashMap<>();
        Map<String, SecretBytes> variables = new HashMap<>();
        for (int i = 0; i <= FieldRules.MAX_MAP_ENTRIES; i++) {
            config.put("k" + i, "v");
            variables.put("V" + i, secret());
        }
        assertThrows(IllegalArgumentException.class,
                () -> new ProjectRecord(ID, "t", "", "", Map.of(), config, T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new ProjectRecord(ID, "t", "", "", variables, Map.of(), T0, T0));
    }

    @Test
    void textWithAnUnpairedSurrogateIsRefused() {
        String broken = "a\uD800b";
        assertThrows(IllegalArgumentException.class, () -> loginTitled(broken));
        assertThrows(IllegalArgumentException.class,
                () -> new LoginRecord(ID, "t", "u", secret(), List.of(broken), "", List.of(), T0, T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new ProjectRecord(ID, "t", "", "", Map.of(broken, secret()), Map.of(), T0, T0));
        assertThrows(IllegalArgumentException.class,
                () -> new ProjectRecord(ID, "t", "", "", Map.of(), Map.of("k", broken), T0, T0));
        try (LoginRecord paired = loginTitled("key 🔑")) {
            assertEquals("key 🔑", paired.title());
        }
    }

    // ---- wifi security -------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"WPA2", "WPA3", "WEP", "OPEN"})
    void wifiAcceptsTheFourSecurityTypes(String security) {
        try (WifiRecord wifi = new WifiRecord(ID, "t", "ssid", security, secret(), false, "", T0, T0)) {
            assertEquals(security, wifi.security());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "wpa2", "WPA", "WPA2 ", "WPA4", "NONE"})
    void wifiRefusesAnyOtherSecurityType(String security) {
        assertThrows(IllegalArgumentException.class,
                () -> new WifiRecord(ID, "t", "ssid", security, secret(), false, "", T0, T0));
    }

    @Test
    void openWifiMayHaveAnEmptyPassword() {
        try (WifiRecord open = new WifiRecord(ID, "cafe", "Cafe", "OPEN", SecretBytes.copyOf(new byte[0]),
                false, "", T0, T0)) {
            assertEquals(0, open.password().length());
        }
    }

    // ---- instants ------------------------------------------------------------------------------

    @Test
    void instantsAreTruncatedToWholeSeconds() {
        Instant precise = T0.plusNanos(999_999_999);
        try (LoginRecord login = new LoginRecord(ID, "t", "u", secret(), List.of(), "", List.of(),
                precise, precise, precise);
             WifiRecord wifi = new WifiRecord(ID, "t", "ssid", "WPA2", secret(), false, "", precise, precise);
             SshKeyRecord ssh = new SshKeyRecord(ID, "t", "ed25519", secret(), "", "", "", List.of(), precise, precise);
             ProjectRecord project = new ProjectRecord(ID, "t", "", "", Map.of(), Map.of(), precise, precise)) {
            assertEquals(List.of(T0, T0, T0), List.of(login.created(), login.updated(), login.lastUsed()));
            assertEquals(List.of(T0, T0), List.of(wifi.created(), wifi.updated()));
            assertEquals(List.of(T0, T0), List.of(ssh.created(), ssh.updated()));
            assertEquals(List.of(T0, T0), List.of(project.created(), project.updated()));
        }
    }

    @Test
    void instantsBeforeTheEpochAreRefused() {
        for (Instant early : List.of(Instant.EPOCH.minusNanos(1), Instant.EPOCH.minusSeconds(86_400), Instant.MIN)) {
            assertThrows(IllegalArgumentException.class,
                    () -> new LoginRecord(ID, "t", "u", secret(), List.of(), "", List.of(), early, T0, T0));
            assertThrows(IllegalArgumentException.class,
                    () -> new LoginRecord(ID, "t", "u", secret(), List.of(), "", List.of(), T0, early, T0));
            assertThrows(IllegalArgumentException.class,
                    () -> new LoginRecord(ID, "t", "u", secret(), List.of(), "", List.of(), T0, T0, early));
            assertThrows(IllegalArgumentException.class,
                    () -> new WifiRecord(ID, "t", "ssid", "WPA2", secret(), false, "", early, T0));
            assertThrows(IllegalArgumentException.class,
                    () -> new SshKeyRecord(ID, "t", "ed25519", secret(), "", "", "", List.of(), T0, early));
            assertThrows(IllegalArgumentException.class,
                    () -> new ProjectRecord(ID, "t", "", "", Map.of(), Map.of(), early, T0));
        }
    }

    @Test
    void instantsAfterTheYear9999AreRefused() {
        try (LoginRecord first = new LoginRecord(ID, "t", "u", secret(), List.of(), "", List.of(),
                Instant.EPOCH, Instant.EPOCH, LAST_INSTANT.plusNanos(999_999_999))) {
            assertEquals(Instant.EPOCH, first.created());
            assertEquals(LAST_INSTANT, first.lastUsed());
            assertEquals(FieldRules.MAX_EPOCH_SECOND, first.lastUsed().getEpochSecond());
        }
        for (Instant late : List.of(LAST_INSTANT.plusSeconds(1), Instant.MAX)) {
            assertThrows(IllegalArgumentException.class,
                    () -> new LoginRecord(ID, "t", "u", secret(), List.of(), "", List.of(), late, T0, T0));
        }
    }

    // ---- nulls and copies ----------------------------------------------------------------------

    @Test
    void nullComponentsAreRefused() {
        assertThrows(NullPointerException.class,
                () -> new LoginRecord(null, "t", "u", secret(), List.of(), "", List.of(), T0, T0, T0));
        assertThrows(NullPointerException.class,
                () -> new LoginRecord(ID, null, "u", secret(), List.of(), "", List.of(), T0, T0, T0));
        assertThrows(NullPointerException.class,
                () -> new LoginRecord(ID, "t", "u", null, List.of(), "", List.of(), T0, T0, T0));
        assertThrows(NullPointerException.class,
                () -> new LoginRecord(ID, "t", "u", secret(), null, "", List.of(), T0, T0, T0));
        assertThrows(NullPointerException.class,
                () -> new LoginRecord(ID, "t", "u", secret(), Arrays.asList("a", null), "", List.of(), T0, T0, T0));
        assertThrows(NullPointerException.class,
                () -> new LoginRecord(ID, "t", "u", secret(), List.of(), "", List.of(), T0, T0, null));
        assertThrows(NullPointerException.class,
                () -> new WifiRecord(ID, "t", "ssid", null, secret(), false, "", T0, T0));
        assertThrows(NullPointerException.class,
                () -> new SshKeyRecord(ID, "t", "ed25519", null, "", "", "", List.of(), T0, T0));
        assertThrows(NullPointerException.class,
                () -> new ProjectRecord(ID, "t", "", "", null, Map.of(), T0, T0));
        assertThrows(NullPointerException.class,
                () -> new ProjectRecord(ID, "t", "", "", Map.of(), null, T0, T0));
    }

    @Test
    void listsAndMapsAreDefensiveUnmodifiableCopies() {
        List<String> urls = new ArrayList<>(List.of("https://a.example"));
        Map<String, String> config = new HashMap<>(Map.of("k", "v"));
        Map<String, SecretBytes> variables = new HashMap<>(Map.of("A", secret()));
        try (LoginRecord login = new LoginRecord(ID, "t", "u", secret(), urls, "", urls, T0, T0, T0);
             ProjectRecord project = new ProjectRecord(ID, "t", "", "", variables, config, T0, T0)) {
            urls.add("https://b.example");
            config.put("k2", "v2");
            variables.clear();

            assertEquals(List.of("https://a.example"), login.urls());
            assertEquals(List.of("https://a.example"), login.tags());
            assertEquals(Map.of("k", "v"), project.config());
            assertEquals(1, project.variables().size());
            assertThrows(UnsupportedOperationException.class, () -> login.urls().add("x"));
            assertThrows(UnsupportedOperationException.class, () -> project.config().put("x", "y"));
            assertThrows(UnsupportedOperationException.class, () -> project.variables().clear());
        }
    }

    // ---- secrets -------------------------------------------------------------------------------

    @Test
    void closeZeroesEverySecretAndIsIdempotent() {
        List<VaultRecord> records = RecordFixtures.oneOfEach();
        records.forEach(VaultRecord::close);
        records.forEach(VaultRecord::close);

        assertTrue(LoginRecord.class.cast(records.get(0)).password().isClosed());
        assertTrue(WifiRecord.class.cast(records.get(1)).password().isClosed());
        assertTrue(SshKeyRecord.class.cast(records.get(2)).privateKey().isClosed());
        Map<String, SecretBytes> variables = ProjectRecord.class.cast(records.get(3)).variables();
        assertEquals(2, variables.size());
        assertTrue(variables.values().stream().allMatch(SecretBytes::isClosed));
    }

    @Test
    void aClosedSecretIsAcceptedByTheConstructor() {
        try (LoginRecord source = RecordFixtures.login(RecordFixtures.ID_A, "t")) {
            RecordFixtures.closeNow(source);
            try (LoginRecord around = new LoginRecord(ID, "t", "u", source.password(), List.of(), "", List.of(),
                    T0, T0, T0)) {
                assertTrue(around.password().isClosed());
            }
        }
    }

    @Test
    void equalityComparesSecretsByContent() {
        try (LoginRecord left = RecordFixtures.login(RecordFixtures.ID_A, "Bank");
             LoginRecord same = RecordFixtures.login(RecordFixtures.ID_A, "Bank");
             LoginRecord otherSecret = new LoginRecord(left.id(), left.title(), left.username(),
                     RecordFixtures.secretOf("different"), left.urls(), left.notes(), left.tags(),
                     left.created(), left.updated(), left.lastUsed())) {
            assertEquals(left, same);
            assertEquals(left.hashCode(), same.hashCode());
            assertNotEquals(left, otherSecret);
            assertEquals(left.hashCode(), otherSecret.hashCode());

            RecordFixtures.closeNow(same);
            assertNotEquals(left, same);
            // A closed record still equals itself (List.contains calls equals).
            assertTrue(List.of(same).contains(same));
        }
    }

    @Test
    void toStringNeverShowsASecret() {
        List<VaultRecord> records = RecordFixtures.oneOfEach();
        for (String shown : records.stream().map(Object::toString).toList()) {
            assertFalse(shown.contains("hunter2"), shown);
            assertTrue(shown.contains("SecretBytes[redacted]"), shown);
        }
        records.forEach(VaultRecord::close);
    }

    private static LoginRecord loginTitled(String title) {
        return new LoginRecord(ID, title, "u", secret(), List.of(), "", List.of(), T0, T0, T0);
    }

    private static SecretBytes secret() {
        return RecordFixtures.secretOf("value");
    }
}
