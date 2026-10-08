package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import com.googlecode.lanterna.terminal.virtual.DefaultVirtualTerminal;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.vault.VaultException;
import pm.vault.record.LoginRecord;
import pm.vault.record.VaultRecord;

/**
 * M1 exit criterion "TUI dashboard and search" (plan.md §13 M1): drives the real Lanterna windows
 * on a {@link DefaultVirtualTerminal} with an in-memory vault, and reads the rendered screen.
 * Also covers masked secrets (SR-503), catalogue errors (SR-501), terminal-safe rendering of
 * record text (SR-501), the canary (SR-500), wiping typed input on cancel, lock and quit (ADR 0008)
 * and the idle-lock wiring (SR-504).
 */
class DashboardTest {
    private static final String CANARY =
            Objects.requireNonNull(System.getProperty("pm.canary.secret"), "pm.canary.secret");
    private static final String RECOVERY = "RK-0000-1111-2222";
    private static final String TYPED_PW = "TYPEDPW-adv-999";
    private static final String ESC_TITLE = "Evil\u001b]0;PWNED\u0007x";
    private static final String CSI_TITLE = "Bank\u009b2J\u009d0;OWNED\u009c";
    private static final String BIDI_TITLE = "Mail\u202Egnp.exe";

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
            assertTrue(h.screenText().contains(LoginDialog.TAGS_LABEL));

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
            assertFalse(screen.contains(LoginDialog.TAGS_LABEL)); // dialog closed
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
            assertTrue(screen.contains(LoginDialog.TAGS_LABEL)); // still open for a retry
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
            assertFalse(h.screenText().contains(LoginDialog.TAGS_LABEL));
            assertEquals(0, h.port.last().saveCount());
        }
    }

    @Test
    void addLoginCancelEmptiesEveryBox() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            openAddLogin(h);
            Window dialog = h.activeWindow();
            typeIntoAddLogin(h);
            assertTrue(TuiHarness.boxTexts(dialog).contains(TYPED_PW));

            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Enter); // urls, tags, OK, Cancel

            assertFalse(h.screenText().contains(LoginDialog.TAGS_LABEL));
            assertAllEmpty(dialog);
            assertEquals(0, h.port.last().saveCount());
        }
    }

    @Test
    void quitEmptiesOpenFormsIncludingUnlockBox() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            Window unlock = h.activeWindow();
            h.type(CANARY); // typed, never submitted
            h.controller.quit();
            h.pump();
            assertAllEmpty(unlock);
        }
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            openAddLogin(h);
            Window dialog = h.activeWindow();
            typeIntoAddLogin(h);
            h.controller.quit();
            h.pump();
            assertAllEmpty(dialog);
            assertTrue(h.port.last().isLocked());
        }
    }

    @Test
    void addLoginPutFailureZeroesThePassword() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.port.last().failPuts();
            openAddLogin(h);
            fillAddLogin(h, "Gitea", "alice", TYPED_PW);

            assertThrows(IllegalStateException.class, () -> h.press(KeyType.Tab, KeyType.Enter));

            assertTrue(LoginRecord.class.cast(h.port.last().rejectedPut()).password().isClosed());
            assertEquals(0, h.port.last().saveCount());
        }
    }

    @Test
    void controlAndBidiCharactersInStoredRecordsRenderAsReplacement() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            for (String title : List.of(ESC_TITLE, CSI_TITLE, BIDI_TITLE)) {
                h.port.last().put(login(title, "u\u0085\u2028\u200Bser"));
            }
            h.type("e"); // refresh through search, then back to the full list
            h.press(KeyType.Backspace);

            String screen = h.screenText();
            assertTrue(screen.contains("Evil\uFFFD]0;PWNED\uFFFDx"), screen);
            assertTrue(screen.contains("Bank\uFFFD2J\uFFFD0;OWNED\uFFFD"), screen);
            assertTrue(screen.contains("Mail\uFFFDgnp.exe"), screen);
            assertTrue(screen.contains("u\uFFFD\uFFFD\uFFFDser"), screen);
            assertTerminalSafe(h);

            h.press(KeyType.Tab, KeyType.ArrowDown, KeyType.ArrowDown, KeyType.ArrowDown,
                    KeyType.Enter); // detail view of the ESC record: window title and labels
            assertTrue(h.screenText().contains(RecordDetailWindow.CLOSE));
            assertTrue(h.screenText().contains("Evil\uFFFD]0;PWNED"), h.screenText());
            assertTerminalSafe(h);
            assertTrue(h.controller.isUnlocked());
        }
    }

    @Test
    void typedControlOrFormatCharacterIsRejected() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            openAddLogin(h);
            Window dialog = h.activeWindow();
            h.type("A\u009bB\u001bC\u202ED");
            assertTrue(h.screenText().contains(Messages.UNSAFE_CHARACTER), h.screenText());
            assertEquals("ABCD", TuiHarness.boxTexts(dialog).get(0));
            assertTerminalSafe(h);

            h.press(KeyType.Tab);
            h.type("user\u0085");
            h.press(KeyType.Tab);
            h.type("pw");
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Enter); // urls, tags, OK

            assertEquals(List.of("Login", "ABCD", "user"),
                    DashboardWindow.row(h.port.last().records().get(3)).subList(0, 3));
        }
    }

    @Test
    void displaySafeReplacesEveryUnsafeClass() {
        assertEquals("a\uFFFDb\uFFFDc\uFFFDd\uFFFDe\uFFFDf\uFFFDg\uFFFDh",
                DisplaySafe.text("a\u001bb\u009bc\u0085d\u202Ee\u200Bf\u2028g\u2029h"));
        assertEquals("\uFFFD", DisplaySafe.text("\uD800")); // lone surrogate
        assertEquals("ok \uD83D\uDD11 \u00E9", DisplaySafe.text("ok \uD83D\uDD11 \u00E9"));
        assertTrue(DisplaySafe.isSafe("plain title"));
        assertFalse(DisplaySafe.isSafe("tab\there"));
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
            Window dialog = h.activeWindow();
            typeIntoAddLogin(h);
            assertTrue(TuiHarness.boxTexts(dialog).contains(TYPED_PW));

            h.timers.fireLatest(); // IdleLock expiry: only posts to the GUI thread
            assertFalse(h.port.last().isLocked());
            h.pump();

            assertAllEmpty(dialog); // ADR 0008: the typed password is not left in the masked box
            assertTrue(h.port.last().isLocked());
            assertFalse(h.controller.isUnlocked());
            assertEquals(1, h.timers.closes());
            String screen = h.screenText();
            assertTrue(screen.contains(UnlockWindow.TITLE));
            assertFalse(screen.contains("Username/SSID"));
            assertFalse(screen.contains("GitHub"));
            assertFalse(screen.contains(LoginDialog.TAGS_LABEL));

            h.unlockWith(CANARY);
            assertTrue(h.controller.isUnlocked());
            h.timers.fire(0); // a stale expiry from the first session does nothing
            h.pump();
            assertTrue(h.controller.isUnlocked());
        }
    }

    @Test
    void ctrlLLocks() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.ctrl('l');
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
    void ctrlXLocksAndStops() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.ctrl('x');
            assertTrue(h.controller.isQuit());
            assertTrue(h.port.last().isLocked());
        }
        try (TuiHarness h = new TuiHarness(newPort())) {
            Window unlock = h.activeWindow();
            h.type(CANARY);
            h.ctrl('x'); // works on the unlock screen too, and wipes the box
            assertTrue(h.controller.isQuit());
            assertAllEmpty(unlock);
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
    void exceptionEscapingRunStillLocksTheSession() throws IOException {
        FakeVaultPort port = newPort();
        port.failSearches();
        try (DefaultVirtualTerminal terminal = new DefaultVirtualTerminal(new TerminalSize(100, 30))) {
            CANARY.chars().forEach(c -> terminal.addInput(new KeyStroke((char) c, false, false)));
            terminal.addInput(new KeyStroke(KeyType.Enter));
            terminal.addInput(new KeyStroke(KeyType.Enter));
            terminal.addInput(new KeyStroke('x', false, false)); // search throws on the GUI thread

            TuiApp app = new TuiApp(port, TuiApp.DEFAULT_IDLE_LOCK);
            assertThrows(IllegalStateException.class, () -> app.run(terminal));
        }

        assertEquals(1, port.openedSessions().size());
        assertTrue(port.last().isLocked()); // run's finally locked the vault on the way out
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
        h.ctrl('n');
    }

    private static void typeIntoAddLogin(TuiHarness h) {
        h.type("Title");
        h.press(KeyType.Tab);
        h.type("user");
        h.press(KeyType.Tab);
        h.type(TYPED_PW);
    }

    private static void assertAllEmpty(Window form) {
        List<String> texts = TuiHarness.boxTexts(form);
        assertFalse(texts.isEmpty());
        texts.forEach(t -> assertEquals("", t, texts::toString));
    }

    /** No control, format or separator character reached the virtual terminal (SR-501). */
    private static void assertTerminalSafe(TuiHarness h) {
        for (String text : List.of(h.screenText(), h.bufferText())) {
            text.lines().forEach(line -> assertTrue(DisplaySafe.isSafe(line), line));
        }
    }

    private static LoginRecord login(String title, String username) {
        return new LoginRecord(UUID.randomUUID(), title, username,
                SecretBytes.copyOf("pw".getBytes(StandardCharsets.UTF_8)), List.of(), "", List.of(),
                FakeVaultPort.T0, FakeVaultPort.T0, FakeVaultPort.T0);
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
