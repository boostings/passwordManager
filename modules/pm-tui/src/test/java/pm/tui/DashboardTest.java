package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import com.googlecode.lanterna.terminal.virtual.DefaultVirtualTerminal;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.Test;
import pm.vault.VaultException;
import pm.vault.record.LoginRecord;
import pm.vault.record.VaultRecord;

/**
 * M1 exit criterion "TUI dashboard and search" (plan.md §13 M1): drives the real Lanterna windows
 * on a {@link DefaultVirtualTerminal} with an in-memory vault, and reads the rendered screen.
 * Also covers masked secrets (SR-503), catalogue errors (SR-501), the canary (SR-500) and the
 * idle-lock wiring (SR-504).
 */
class DashboardTest {
    private static final String CANARY =
            Objects.requireNonNull(System.getProperty("pm.canary.secret"), "pm.canary.secret");
    private static final String RECOVERY = "RK-0000-1111-2222";

    private static FakeVaultPort newPort() {
        return new FakeVaultPort(CANARY, RECOVERY);
    }

    @Test
    void rightPassphraseShowsDashboard() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            assertTrue(h.screenText().contains(UnlockWindow.TITLE));
            h.unlockWith(CANARY);

            assertTrue(h.controller.isUnlocked());
            String screen = h.screenText();
            assertTrue(screen.contains(DashboardWindow.TITLE));
            assertTrue(screen.contains("Username/SSID"));
            assertTrue(screen.contains("Locked in 5:00"), screen);
            assertFalse(screen.contains(UnlockWindow.TITLE));
            assertEquals(1, h.timers.started());
        }
    }

    @Test
    void recoveryKeyButtonUnlocksThroughRecoverySlot() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.type(RECOVERY);
            h.press(KeyType.Enter, KeyType.Tab, KeyType.Enter); // box -> Unlock -> Use recovery key
            assertTrue(h.controller.isUnlocked());
            assertTrue(h.screenText().contains("GitHub"));
        }
    }

    @Test
    void tableListsRecordsWithoutSecrets() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            String screen = h.screenText();
            for (String cell : List.of("Type", "Title", "Updated", "Login", "GitHub", "octocat",
                    "Wi-Fi", "Home WiFi", "HomeNet", "SSH key", "Deploy key", "2026-10-01 12:00")) {
                assertTrue(screen.contains(cell), cell);
            }
            assertFalse(screen.contains(FakeVaultPort.LOGIN_SECRET));
            assertFalse(screen.contains(FakeVaultPort.WIFI_SECRET));
        }
    }

    @Test
    void typingInSearchFiltersRows() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.type("git");

            String screen = h.screenText();
            assertTrue(screen.contains("GitHub"));
            assertFalse(screen.contains("HomeNet"));
            assertFalse(screen.contains("Deploy key"));
            assertEquals(List.of("g", "gi", "git"), h.port.last().searchQueries());

            h.press(KeyType.Backspace, KeyType.Backspace, KeyType.Backspace);
            assertTrue(h.screenText().contains("HomeNet")); // blank query lists everything again
        }
    }

    @Test
    void searchWithNoMatchShowsEmptyTable() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.type("zzz");
            String screen = h.screenText();
            assertFalse(screen.contains("GitHub"));
            h.press(KeyType.Tab, KeyType.Enter); // select on an empty table opens nothing
            assertFalse(h.screenText().contains(RecordDetailWindow.CLOSE));
        }
    }

    @Test
    void wrongPassphraseShowsCatalogueErrorAndStaysLocked() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith("not-the-passphrase");

            assertFalse(h.controller.isUnlocked());
            assertTrue(h.port.openedSessions().isEmpty());
            String screen = h.screenText();
            assertTrue(screen.contains(Messages.of(VaultException.Code.WRONG_CREDENTIAL)), screen);
            assertTrue(screen.contains(UnlockWindow.TITLE));
            assertFalse(screen.contains("WRONG_CREDENTIAL")); // no exception text (SR-501)
            assertEquals(0, h.timers.started());

            h.unlockWith(CANARY); // the box was cleared, so a retry works
            assertTrue(h.controller.isUnlocked());
        }
    }

    @Test
    void emptyPassphraseIsRejectedWithoutCallingTheVault() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.press(KeyType.Enter, KeyType.Enter);
            assertTrue(h.screenText().contains(Messages.EMPTY_CREDENTIAL));
            assertEquals(0, h.port.attemptCount());
        }
    }

    @Test
    void addLoginAddsRowAndSavesOnce() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            openAddLogin(h);
            assertTrue(h.screenText().contains(AddLoginDialog.TAGS_LABEL));

            fillAddLogin(h, "Gitea", "alice", CANARY);
            h.press(KeyType.Tab, KeyType.Enter); // tags -> OK

            assertEquals(1, h.port.last().saveCount());
            List<VaultRecord> records = h.port.last().records();
            assertEquals(4, records.size());
            assertEquals(List.of("Login", "Gitea", "alice"),
                    DashboardWindow.row(records.get(3)).subList(0, 3));
            assertEquals(List.of("https://gitea.example", "https://git.example"),
                    LoginRecord.class.cast(records.get(3)).urls());
            assertEquals(List.of("dev", "work"), LoginRecord.class.cast(records.get(3)).tags());
            String screen = h.screenText();
            assertTrue(screen.contains("Gitea"));
            assertTrue(screen.contains("alice"));
            assertFalse(screen.contains(AddLoginDialog.TAGS_LABEL)); // dialog closed
            assertFalse(screen.contains(CANARY));
        }
    }

    @Test
    void addLoginSaveFailureShowsCatalogueMessageAndRollsBack() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.port.last().failSaves(VaultException.Code.STORAGE);
            openAddLogin(h);
            fillAddLogin(h, "Gitea", "alice", "pw");
            h.press(KeyType.Tab, KeyType.Enter);

            assertEquals(1, h.port.last().saveCount());
            assertEquals(3, h.port.last().records().size());
            String screen = h.screenText();
            assertTrue(screen.contains(Messages.of(VaultException.Code.STORAGE)), screen);
            assertTrue(screen.contains(AddLoginDialog.TAGS_LABEL)); // still open for a retry
        }
    }

    @Test
    void addLoginWithoutTitleIsRejected() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            openAddLogin(h);
            fillAddLogin(h, "", "alice", "pw");
            h.press(KeyType.Tab, KeyType.Enter);

            assertTrue(h.screenText().contains(Messages.TITLE_REQUIRED));
            assertEquals(0, h.port.last().saveCount());
        }
    }

    @Test
    void addLoginCancelClosesWithoutSaving() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            openAddLogin(h);
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Tab,
                    KeyType.Enter); // five fields, OK, Cancel
            assertFalse(h.screenText().contains(AddLoginDialog.TAGS_LABEL));
            assertEquals(0, h.port.last().saveCount());
        }
    }

    @Test
    void detailViewMasksSecrets() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.press(KeyType.Tab, KeyType.Enter); // search -> table, open first row (GitHub)

            String screen = h.screenText();
            assertTrue(screen.contains("Password:"), screen);
            assertTrue(screen.contains(Messages.SECRET_MASK));
            assertTrue(screen.contains("https://github.com"));
            assertFalse(screen.contains(FakeVaultPort.LOGIN_SECRET));

            h.press(KeyType.Enter); // Close
            assertFalse(h.screenText().contains(Messages.SECRET_MASK));
        }
    }

    @Test
    void detailFieldsNeverIncludeSecrets() {
        try (FakeVaultPort.FakeSession session = new FakeVaultPort.FakeSession()) {
            session.records().stream().map(r -> RecordDetailWindow.fields(r).toString())
                    .forEach(all -> {
                        assertTrue(all.contains(Messages.SECRET_MASK), all);
                        assertFalse(all.contains("SECRET"), all);
                    });
        }
    }

    @Test
    void canaryNeverReachesAnyScreenBuffer() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.type(CANARY);
            assertTrue(h.screenText().contains("*".repeat(CANARY.length())));
            h.press(KeyType.Enter, KeyType.Enter);
            openAddLogin(h);
            fillAddLogin(h, "Canary", "user", CANARY);
            h.press(KeyType.Tab, KeyType.Enter);
            h.press(KeyType.Tab, KeyType.Enter); // open a detail view too
            h.timers.fireLatest();
            h.pump();

            for (String frame : h.renderedFrames()) {
                assertFalse(frame.contains(CANARY));
                assertFalse(frame.contains(FakeVaultPort.LOGIN_SECRET));
            }
            assertFalse(h.bufferText().contains(CANARY));
        }
    }

    @Test
    void lockCallbackReturnsToUnlockAndClosesSession() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            openAddLogin(h); // a dialog open on top must go too

            h.timers.fireLatest(); // IdleLock expiry: only posts to the GUI thread
            assertFalse(h.port.last().isLocked());
            h.pump();

            assertTrue(h.port.last().isLocked());
            assertFalse(h.controller.isUnlocked());
            assertEquals(1, h.timers.closes());
            String screen = h.screenText();
            assertTrue(screen.contains(UnlockWindow.TITLE));
            assertFalse(screen.contains("Username/SSID"));
            assertFalse(screen.contains("GitHub"));
            assertFalse(screen.contains(AddLoginDialog.TAGS_LABEL));

            h.unlockWith(CANARY);
            assertTrue(h.controller.isUnlocked());
            h.timers.fire(0); // a stale expiry from the first session does nothing
            h.pump();
            assertTrue(h.controller.isUnlocked());
        }
    }

    @Test
    void lockButtonLocks() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Enter); // table, Add, Lock
            assertTrue(h.port.last().isLocked());
            assertTrue(h.screenText().contains(UnlockWindow.TITLE));
        }
    }

    @Test
    void everyKeyTouchesIdleTimerAndStatusCountsDown() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            int before = h.timers.touches();
            h.clock.advance(Duration.ofSeconds(61));
            h.tick();
            assertTrue(h.screenText().contains("Locked in 3:59"), h.screenText());

            h.type("a");
            assertEquals(before + 1, h.timers.touches());
            h.tick();
            assertTrue(h.screenText().contains("Locked in 5:00"));

            h.clock.advance(Duration.ofMinutes(9));
            h.tick();
            assertTrue(h.screenText().contains("Locked in 0:00"));
        }
    }

    @Test
    void quitButtonLocksAndStops() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Enter);
            assertTrue(h.controller.isQuit());
            assertTrue(h.port.last().isLocked());
        }
    }

    @Test
    void lockedInFormatsMinutesAndSeconds() {
        assertEquals("Locked in 5:00", Messages.lockedIn(Duration.ofMinutes(5)));
        assertEquals("Locked in 0:09", Messages.lockedIn(Duration.ofSeconds(9)));
        assertEquals("Locked in 0:00", Messages.lockedIn(Duration.ofSeconds(-3)));
    }

    @Test
    void everyVaultCodeHasACatalogueMessage() {
        for (VaultException.Code code : VaultException.Code.values()) {
            assertFalse(Messages.of(code).contains(code.name()));
        }
    }

    @Test
    void runUnlocksAndEndsOnEndOfInput() throws IOException {
        FakeVaultPort port = newPort();
        try (DefaultVirtualTerminal terminal = new DefaultVirtualTerminal(new TerminalSize(100, 30))) {
            CANARY.chars().forEach(c -> terminal.addInput(new KeyStroke((char) c, false, false)));
            terminal.addInput(new KeyStroke(KeyType.Enter));
            terminal.addInput(new KeyStroke(KeyType.Enter));
            terminal.addInput(new KeyStroke(KeyType.EOF));

            new TuiApp(port, TuiApp.DEFAULT_IDLE_LOCK).run(terminal); // real IdleLock + scheduler
        }

        assertEquals(1, port.openedSessions().size());
        assertTrue(port.last().isLocked()); // end of input locks the vault
    }

    private static void openAddLogin(TuiHarness h) {
        h.press(KeyType.Tab, KeyType.Tab, KeyType.Enter); // search -> table -> Add login
    }

    private static void fillAddLogin(TuiHarness h, String title, String user, String pw) {
        h.type(title);
        h.press(KeyType.Tab);
        h.type(user);
        h.press(KeyType.Tab);
        h.type(pw);
        h.press(KeyType.Tab);
        h.type("https://gitea.example, https://git.example");
        h.press(KeyType.Tab);
        h.type("dev, work");
    }
}
