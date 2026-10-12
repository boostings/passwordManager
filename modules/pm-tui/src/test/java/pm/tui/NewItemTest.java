package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.googlecode.lanterna.input.KeyType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.vault.record.LoginRecord;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/** Ctrl+N's New item menu, Enter in a form's last field, and the SSH key import form (M7.15). */
class NewItemTest {
    private static final String CANARY =
            Objects.requireNonNull(System.getProperty("pm.canary.secret"), "pm.canary.secret");

    private static FakeVaultPort newPort() {
        return new FakeVaultPort(CANARY, "RK-0000-1111-2222");
    }

    /** Imports answer from a queue; every path asked for is recorded. */
    static final class FakeImports implements SshActions {
        final List<SshActions.Imported> answers = new ArrayList<>();
        final List<String> paths = new ArrayList<>();
        final List<String> titles = new ArrayList<>();

        @Override
        public Outcome add(SecretBytes privateKey, Duration lifetime, boolean confirm) {
            return Outcome.UNAVAILABLE;
        }

        @Override
        public Outcome remove(SecretBytes privateKey) {
            return Outcome.UNAVAILABLE;
        }

        @Override
        public Imported importKey(String path, String title) {
            paths.add(path);
            titles.add(title);
            return answers.remove(0);
        }
    }

    private static SshKeyRecord key(String title, String fingerprint) {
        return new SshKeyRecord(UUID.randomUUID(), title, "ssh-ed25519",
                SecretBytes.copyOf("k".getBytes(StandardCharsets.US_ASCII)), "ssh-ed25519 AAAA", fingerprint, "",
                List.of(), FakeVaultPort.T0, FakeVaultPort.T0);
    }

    private static List<VaultRecord> ofType(TuiHarness h, Class<?> type) {
        return h.port.last().records().stream().filter(type::isInstance).toList();
    }

    @Test
    void menuOffersEveryTypeAndCtrlNTypesNothing() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.ctrl('n');
            String screen = h.screenText();
            for (String choice : List.of(NewItemMenu.LOGIN, NewItemMenu.WIFI, NewItemMenu.SSH, NewItemMenu.PASSKEY,
                    NewItemMenu.PROJECT)) {
                assertTrue(screen.contains(choice), screen);
            }
            h.press(KeyType.ArrowDown, KeyType.ArrowDown, KeyType.ArrowDown, KeyType.Enter); // Passkey
            assertTrue(h.screenText().contains("Not in this version"), h.screenText());
            h.press(KeyType.Escape);
            assertFalse(h.screenText().contains(NewItemMenu.TITLE));
        }
    }

    @Test
    void enterInTheLastFieldSavesAndCtrlLettersAreNotTyped() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.ctrl('n');
            h.press(KeyType.Enter); // Login
            h.type("Gitea");
            h.ctrl('n'); // a shortcut, never text
            h.press(KeyType.Tab);
            h.type("alice");
            h.press(KeyType.Tab);
            h.type("pw");
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Tab); // Generate, Show, website, tags
            h.type("dev");
            h.press(KeyType.Enter); // last field: saves

            assertEquals(1, h.port.last().saveCount(), h.screenText());
            assertEquals("Gitea", h.port.last().records().get(3).title());
            assertEquals(List.of("dev"), LoginRecord.class.cast(h.port.last().records().get(3)).tags());
        }
    }

    @Test
    void generateFillsAndShowsThePassword() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.ctrl('n');
            h.press(KeyType.Enter);
            h.type("Gitea");
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Enter); // username, password, Generate
            assertTrue(h.screenText().contains(LoginDialog.HIDE), h.screenText());
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Enter); // Show, website, tags, OK

            assertEquals(20, LoginRecord.class.cast(h.port.last().records().get(3)).password().length());
        }
    }

    @Test
    void wifiIsAddedFromTheMenu() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            int before = ofType(h, WifiRecord.class).size();
            h.ctrl('n');
            h.press(KeyType.ArrowDown, KeyType.Enter);
            h.type("CafeNet");
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab); // security, hidden, password
            h.type("wifi-pw-123");
            h.press(KeyType.Enter);
            assertEquals(before + 1, ofType(h, WifiRecord.class).size(), h.screenText());
        }
    }

    @Test
    void sshKeyIsImportedOnceAndProblemsAreShown() throws IOException {
        FakeImports ssh = new FakeImports();
        ssh.answers.add(SshActions.Imported.failed(SshActions.ImportProblem.ENCRYPTED));
        ssh.answers.add(new SshActions.Imported(Optional.of(key("Laptop", "SHA256:new")), Optional.empty(), false));
        ssh.answers.add(new SshActions.Imported(Optional.of(key("Again", "SHA256:new")), Optional.empty(), false));
        try (TuiHarness h = new TuiHarness(newPort(), ssh)) {
            h.unlockWith(CANARY);
            int before = ofType(h, SshKeyRecord.class).size();
            h.ctrl('n');
            h.press(KeyType.ArrowDown, KeyType.ArrowDown, KeyType.Enter);
            assertTrue(h.screenText().contains(SshImportDialog.DEFAULT_PATH), h.screenText());
            h.press(KeyType.Tab, KeyType.Enter); // title (last field)
            assertTrue(h.screenText().contains(Messages.of(SshActions.ImportProblem.ENCRYPTED)), h.screenText());
            assertEquals(List.of(SshImportDialog.DEFAULT_PATH), ssh.paths);

            h.press(KeyType.Tab);
            h.type("Laptop");
            h.press(KeyType.Enter);
            assertEquals(before + 1, ofType(h, SshKeyRecord.class).size(), h.screenText());
            assertEquals("Laptop", ssh.titles.get(1));
            assertFalse(h.screenText().contains(SshImportDialog.TITLE));

            h.ctrl('n');
            h.press(KeyType.ArrowDown, KeyType.ArrowDown, KeyType.Enter);
            h.press(KeyType.Tab, KeyType.Enter);
            assertTrue(h.screenText().contains(Messages.SSH_KEY_EXISTS), h.screenText());
            assertEquals(before + 1, ofType(h, SshKeyRecord.class).size());
        }
    }

    @Test
    void wrapBreaksAtSpaces() {
        assertEquals("one two\nthree", Padded.wrap("one two three", 8));
        assertEquals("averyveryverylongword\nx", Padded.wrap("averyveryverylongword x", 8));
        assertEquals("a\nb", Padded.wrap("a\nb", 8));
    }
}
