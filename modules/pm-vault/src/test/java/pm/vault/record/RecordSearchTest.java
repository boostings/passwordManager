package pm.vault.record;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Search covers title, username, urls, tags, ssid and hosts, case-insensitively, and never a
 * secret (sprint plan section 2 D and section 5 D).
 */
class RecordSearchTest {

    /** The plan's example: a record whose password is "hunter2" is not found by "hunter". */
    @ParameterizedTest
    @ValueSource(strings = {"hunter", "hunter2", "HUNTER2", "2"})
    void neverMatchesOnSecretContents(String query) {
        try (LoginRecord login = RecordFixtures.login(RecordFixtures.ID_A, "Bank");
             WifiRecord wifi = RecordFixtures.wifi(RecordFixtures.ID_B, "Home");
             SshKeyRecord ssh = RecordFixtures.sshKey(RecordFixtures.ID_C, "Deploy");
             ProjectRecord project = RecordFixtures.project(RecordFixtures.ID_D, "App")) {
            assertFalse(RecordSearch.matches(login, query));
            assertFalse(RecordSearch.matches(wifi, query));
            assertFalse(RecordSearch.matches(ssh, query));
            assertFalse(RecordSearch.matches(project, query));
        }
    }

    @Test
    void matchesTheContractFieldsIgnoringCase() {
        try (LoginRecord login = RecordFixtures.login(RecordFixtures.ID_A, "My Bank");
             WifiRecord wifi = RecordFixtures.wifi(RecordFixtures.ID_B, "Home WiFi");
             SshKeyRecord ssh = RecordFixtures.sshKey(RecordFixtures.ID_C, "Deploy key");
             ProjectRecord project = RecordFixtures.project(RecordFixtures.ID_D, "Shop App")) {
            assertTrue(RecordSearch.matches(login, "BANK"));
            assertTrue(RecordSearch.matches(login, "Alice"));
            assertTrue(RecordSearch.matches(login, "EXAMPLE.com/log"));
            assertTrue(RecordSearch.matches(login, "wOrK"));
            assertTrue(RecordSearch.matches(wifi, "wifi"));
            assertTrue(RecordSearch.matches(wifi, "homenet"));
            assertTrue(RecordSearch.matches(ssh, "deploy"));
            assertTrue(RecordSearch.matches(ssh, "BUILD.example"));
            assertTrue(RecordSearch.matches(project, "shop"));
        }
    }

    @Test
    void doesNotSearchFieldsOutsideTheContract() {
        try (LoginRecord login = RecordFixtures.login(RecordFixtures.ID_A, "Bank");
             WifiRecord wifi = RecordFixtures.wifi(RecordFixtures.ID_B, "Home");
             SshKeyRecord ssh = RecordFixtures.sshKey(RecordFixtures.ID_C, "Deploy");
             ProjectRecord project = RecordFixtures.project(RecordFixtures.ID_D, "App")) {
            assertFalse(RecordSearch.matches(login, "recovery codes"));
            assertFalse(RecordSearch.matches(wifi, "wpa3"));
            assertFalse(RecordSearch.matches(wifi, "router"));
            assertFalse(RecordSearch.matches(ssh, "ed25519"));
            assertFalse(RecordSearch.matches(ssh, "AAAAC3"));
            assertFalse(RecordSearch.matches(ssh, "sha256"));
            assertFalse(RecordSearch.matches(ssh, "comment"));
            assertFalse(RecordSearch.matches(project, "/home/alice"));
            assertFalse(RecordSearch.matches(project, "git@example"));
            assertFalse(RecordSearch.matches(project, "api_token"));
            assertFalse(RecordSearch.matches(project, "profile"));
        }
    }

    @Test
    void anEmptyQueryMatchesEveryRecord() {
        List<VaultRecord> records = RecordFixtures.oneOfEach();
        assertTrue(IntStream.range(0, records.size()).allMatch(i -> RecordSearch.matches(records.get(i), "")));
        assertTrue(IntStream.range(0, records.size())
                .noneMatch(i -> RecordSearch.matches(records.get(i), "no such text")));
        records.forEach(VaultRecord::close);
    }

    @Test
    void lowerCasingUsesTheRootLocale() {
        // In a Turkish default locale "TITLE".toLowerCase() is "tıtle"; Locale.ROOT keeps the ASCII i.
        try (LoginRecord login = RecordFixtures.login(RecordFixtures.ID_A, "TITLE WITH I")) {
            assertTrue(RecordSearch.matches(login, "title with i"));
            assertTrue(RecordSearch.matches(login, "TITLE WITH I"));
        }
    }

    @Test
    void nullArgumentsAreRefused() {
        try (LoginRecord login = RecordFixtures.login(RecordFixtures.ID_A, "Bank")) {
            assertThrows(NullPointerException.class, () -> RecordSearch.matches(login, null));
            assertThrows(NullPointerException.class, () -> RecordSearch.matches(null, "bank"));
        }
    }
}
