package pm.tui;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.input.KeyType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.vault.VaultException;
import pm.vault.record.LoginRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/**
 * M7.8: a card's Reveal (re-masked after 15 s, on Hide and on lock) and Copy (cleared after 30 s,
 * on lock, and only while the clipboard still holds the copy; SR-503), Edit, Delete, a new Wi-Fi
 * network, the passphrase change and the dashboard's answer to a key that has nothing to act on.
 * Driven through the real Lanterna windows like {@link DashboardTest}.
 */
@Tag("T-UI-05")
@SuppressWarnings("PMD.CloseResource") // CE-088: records are the fake session's
class RecordActionsTest {
    private static final String CANARY =
            Objects.requireNonNull(System.getProperty("pm.canary.secret"), "pm.canary.secret");
    private static final String RECOVERY = "RK-0000-1111-2222";
    private static final String NEW_PASSPHRASE = "a fresh passphrase 42";

    private static FakeVaultPort newPort() {
        return new FakeVaultPort(CANARY, RECOVERY);
    }

    /** An in-memory clipboard that records what it was given. */
    static final class FakeClipboard implements Clipboard {
        byte[] content = new byte[0];
        boolean readable = true;
        boolean copyFails;
        int clears;

        @Override
        public boolean available() {
            return true;
        }

        @Override
        public boolean copy(byte[] utf8) {
            if (copyFails) {
                return false;
            }
            content = utf8.clone();
            return true;
        }

        @Override
        public Optional<byte[]> read() {
            return readable ? Optional.of(content.clone()) : Optional.empty();
        }

        @Override
        public boolean clear() {
            clears++;
            content = new byte[0];
            return true;
        }

        String text() {
            return new String(content, StandardCharsets.UTF_8);
        }
    }

    /** Unlocks and opens the first row's card (the GitHub login); Close has the focus. */
    private static void openGitHub(TuiHarness h) {
        h.unlockWith(CANARY);
        h.press(KeyType.Tab, KeyType.Enter);
        assertTrue(h.screenText().contains(RecordDetailWindow.REVEAL), h.screenText());
    }

    /** From Close: Tab wraps to Reveal, then Copy, then Edit; Shift+Tab goes to Delete. */
    private static void pressCardButton(TuiHarness h, String button) {
        switch (button) {
            case RecordDetailWindow.REVEAL -> h.press(KeyType.Tab, KeyType.Enter);
            case RecordDetailWindow.COPY -> h.press(KeyType.Tab, KeyType.Tab, KeyType.Enter);
            case RecordDetailWindow.EDIT -> h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Enter);
            case RecordDetailWindow.DELETE -> h.press(KeyType.ReverseTab, KeyType.Enter);
            default -> throw new IllegalArgumentException(button);
        }
    }

    private static LoginRecord login(TuiHarness h, String title) {
        return h.port.last().records().stream().filter(r -> r.title().equals(title))
                .map(LoginRecord.class::cast).findFirst().orElseThrow();
    }

    /** The idle lock fires: Ctrl+L is a dashboard key, and a card is modal. */
    private static void idleLock(TuiHarness h) {
        h.timers.fireLatest();
        h.pump();
    }

    /** The dashboard footer shows {@code message}; it is drawn on the next tick. */
    private static void assertToast(TuiHarness h, String message) {
        h.tick();
        assertTrue(h.screenText().contains(message), h.screenText());
    }

    private static String utf8(SecretBytes s) {
        return s.apply(b -> new String(b, StandardCharsets.UTF_8));
    }

    @Test
    void revealShowsThePasswordAndMasksItAgainAfterFifteenSeconds() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            openGitHub(h);
            assertFalse(h.screenText().contains(FakeVaultPort.LOGIN_SECRET));
            pressCardButton(h, RecordDetailWindow.REVEAL);
            assertTrue(h.screenText().contains(FakeVaultPort.LOGIN_SECRET), h.screenText());
            assertTrue(h.screenText().contains(RecordDetailWindow.HIDE));

            h.clock.advance(RecordDetailWindow.REVEAL_FOR.minusMillis(1));
            h.tick();
            assertTrue(h.screenText().contains(FakeVaultPort.LOGIN_SECRET));
            h.clock.advance(Duration.ofMillis(1));
            h.tick();
            String screen = h.screenText();
            assertFalse(screen.contains(FakeVaultPort.LOGIN_SECRET), screen);
            assertTrue(screen.contains(Messages.SECRET_MASK));
            assertTrue(screen.contains(RecordDetailWindow.REVEAL));
        }
    }

    @Test
    void hideAndLockMaskARevealedPassword() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            openGitHub(h);
            pressCardButton(h, RecordDetailWindow.REVEAL);
            h.press(KeyType.Enter); // the focus stays on the button, now Hide
            assertFalse(h.screenText().contains(FakeVaultPort.LOGIN_SECRET));

            h.press(KeyType.Enter);
            assertTrue(h.screenText().contains(FakeVaultPort.LOGIN_SECRET));
            idleLock(h);
            assertFalse(h.controller.isUnlocked());
            assertFalse(h.screenText().contains(FakeVaultPort.LOGIN_SECRET));
        }
    }

    @Test
    void aPasswordWithControlCharactersIsNeverRevealed() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.port.last().put(new LoginRecord(UUID.randomUUID(), "Zeta", "z",
                    SecretBytes.copyOf("pw\u001b]0;OWNED\u0007".getBytes(StandardCharsets.UTF_8)), List.of(), "",
                    List.of(), FakeVaultPort.T0, FakeVaultPort.T0, FakeVaultPort.T0));
            h.controller.refreshDashboard();
            h.type("Zeta");
            h.press(KeyType.Tab, KeyType.Enter);
            pressCardButton(h, RecordDetailWindow.REVEAL);
            String screen = h.screenText();
            assertTrue(screen.contains(Messages.REVEAL_UNPRINTABLE), screen);
            assertFalse(screen.contains("OWNED"));
            assertTrue(screen.contains(Messages.SECRET_MASK));
        }
    }

    @Test
    void revealableRefusesWhatTheTerminalWouldActOn() {
        for (String bad : List.of("a\u001bb", "a\u0007", "\u202Eabc", "a\u200Bb", "a\u0085")) {
            try (SecretBytes s = SecretBytes.copyOf(bad.getBytes(StandardCharsets.UTF_8))) {
                assertTrue(DisplaySafe.revealable(s).isEmpty(), bad);
            }
        }
        try (SecretBytes s = SecretBytes.copyOf(new byte[] {(byte) 0xC3})) {
            assertTrue(DisplaySafe.revealable(s).isEmpty(), "malformed UTF-8");
        }
        try (SecretBytes s = SecretBytes.copyOf("pässwörd ✓ 42".getBytes(StandardCharsets.UTF_8))) {
            assertArrayEquals("pässwörd ✓ 42".toCharArray(), DisplaySafe.revealable(s).orElseThrow());
        }
    }

    @Test
    void copyPutsThePasswordOnTheClipboardAndClearsItAfterThirtySeconds() throws IOException {
        FakeClipboard clipboard = new FakeClipboard();
        try (TuiHarness h = new TuiHarness(newPort(), clipboard)) {
            openGitHub(h);
            pressCardButton(h, RecordDetailWindow.COPY);
            assertEquals(FakeVaultPort.LOGIN_SECRET, clipboard.text());
            String screen = h.screenText();
            assertTrue(screen.contains(Messages.copied(ClipboardGuard.DEFAULT_CLEAR_AFTER)), screen);
            assertFalse(screen.contains(FakeVaultPort.LOGIN_SECRET), "Copy does not reveal");

            h.clock.advance(ClipboardGuard.DEFAULT_CLEAR_AFTER.minusMillis(1));
            h.tick();
            assertEquals(FakeVaultPort.LOGIN_SECRET, clipboard.text());
            h.clock.advance(Duration.ofMillis(1));
            h.tick();
            assertEquals("", clipboard.text());
            assertEquals(1, clipboard.clears);
            h.clock.advance(ClipboardGuard.DEFAULT_CLEAR_AFTER);
            h.tick();
            assertEquals(1, clipboard.clears, "cleared once");
        }
    }

    @Test
    void lockClearsTheCopyButLeavesTextCopiedLater() throws IOException {
        FakeClipboard clipboard = new FakeClipboard();
        try (TuiHarness h = new TuiHarness(newPort(), clipboard)) {
            openGitHub(h);
            pressCardButton(h, RecordDetailWindow.COPY);
            idleLock(h);
            assertEquals("", clipboard.text(), "lock clears the copy");

            h.unlockWith(CANARY);
            h.press(KeyType.Tab, KeyType.Enter);
            pressCardButton(h, RecordDetailWindow.COPY);
            clipboard.content = "something the user copied".getBytes(StandardCharsets.UTF_8);
            h.clock.advance(ClipboardGuard.DEFAULT_CLEAR_AFTER);
            h.tick();
            assertEquals("something the user copied", clipboard.text());
            idleLock(h);
            assertEquals("something the user copied", clipboard.text());
        }
    }

    @Test
    void aClipboardThatCannotBeReadIsClearedAnyway() {
        FakeClipboard clipboard = new FakeClipboard();
        ClipboardGuard guard = new ClipboardGuard(clipboard, Duration.ofSeconds(5));
        try (SecretBytes s = SecretBytes.copyOf(new byte[] {'x'})) {
            assertEquals(ClipboardGuard.Copied.COPIED, guard.copy(s, FakeVaultPort.T0));
        }
        assertTrue(guard.pending());
        clipboard.readable = false;
        assertTrue(guard.clearNow());
        assertEquals(1, clipboard.clears);
        assertFalse(guard.pending());
        assertTrue(guard.clearNow());
        assertEquals(1, clipboard.clears);
        assertThrows(IllegalArgumentException.class, () -> new ClipboardGuard(clipboard, Duration.ZERO));
    }

    @Test
    void copyWithoutAClipboardOrWhenTheToolFailsSaysSo() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            openGitHub(h);
            pressCardButton(h, RecordDetailWindow.COPY);
            assertTrue(h.screenText().contains(Messages.COPY_UNAVAILABLE), h.screenText());
        }
        FakeClipboard failing = new FakeClipboard();
        failing.copyFails = true;
        try (TuiHarness h = new TuiHarness(newPort(), failing)) {
            openGitHub(h);
            pressCardButton(h, RecordDetailWindow.COPY);
            assertTrue(h.screenText().contains(Messages.COPY_FAILED), h.screenText());
            assertFalse(h.controller.clipboard().pending());
        }
    }

    @Test
    void editChangesTheUsernameAndKeepsThePassword() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            openGitHub(h);
            UUID id = login(h, "GitHub").id();
            pressCardButton(h, RecordDetailWindow.EDIT);
            assertTrue(h.screenText().contains(LoginDialog.EDIT_TITLE), h.screenText());
            assertTrue(h.screenText().contains(LoginDialog.KEEP_PASSWORD));

            h.press(KeyType.Tab); // title -> username
            h.press(KeyType.End);
            h.type("-renamed");
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Enter); // password, urls, tags, OK

            LoginRecord edited = login(h, "GitHub");
            assertEquals(id, edited.id());
            assertEquals("octocat-renamed", edited.username());
            assertEquals(FakeVaultPort.LOGIN_SECRET, utf8(edited.password()));
            assertEquals(List.of("https://github.com"), edited.urls());
            assertEquals(List.of("dev"), edited.tags());
            assertEquals(1, h.port.last().saveCount());
            String screen = h.screenText();
            assertToast(h, Messages.CHANGES_SAVED);
            assertTrue(screen.contains("octocat-renamed"));
        }
    }

    @Test
    void editWithANewPasswordAndAFailedSavePutsTheOldRecordBack() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            openGitHub(h);
            h.port.last().failSaves(VaultException.Code.STORAGE);
            pressCardButton(h, RecordDetailWindow.EDIT);
            h.press(KeyType.Tab, KeyType.Tab);
            h.type("brand-new-pw");
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Enter);

            assertTrue(h.screenText().contains(Messages.of(VaultException.Code.STORAGE)), h.screenText());
            assertEquals(FakeVaultPort.LOGIN_SECRET, utf8(login(h, "GitHub").password()));

            h.port.last().failSaves(null);
            h.type("brand-new-pw"); // the focus is back on the emptied password box
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Enter);
            assertEquals("brand-new-pw", utf8(login(h, "GitHub").password()));
            assertFalse(h.screenText().contains(LoginDialog.EDIT_TITLE));
        }
    }

    @Test
    void deleteAsksFirstWithCancelFocusedThenRemovesAndSaves() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            openGitHub(h);
            pressCardButton(h, RecordDetailWindow.DELETE);
            assertTrue(h.screenText().contains("Delete Login “GitHub”?"), h.screenText());
            h.press(KeyType.Enter); // Cancel
            assertEquals(3, h.port.last().records().size());
            assertEquals(0, h.port.last().saveCount());

            h.press(KeyType.Enter); // the card's Delete still has the focus
            h.press(KeyType.ReverseTab, KeyType.Enter); // Delete
            assertEquals(2, h.port.last().records().size());
            assertEquals(1, h.port.last().saveCount());
            String screen = h.screenText();
            assertToast(h, Messages.DELETED);
            assertFalse(screen.contains("GitHub"), "the card closed and the row is gone");
        }
    }

    @Test
    void deletingAnSshKeyWarnsAboutTheAgentAndAFailedSaveCanBeRetried() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.type("deploy");
            h.press(KeyType.Tab, KeyType.Enter);
            h.press(KeyType.ReverseTab, KeyType.Enter); // Close -> Delete (no Reveal/Copy/Edit for a key)
            assertTrue(h.screenText().contains(Messages.DELETE_SSH_AGENT), h.screenText());

            h.port.last().failSaves(VaultException.Code.STORAGE);
            h.press(KeyType.ReverseTab, KeyType.Enter);
            assertTrue(h.screenText().contains(Messages.DELETE_NOT_SAVED), h.screenText());
            assertEquals(2, h.port.last().records().size());

            h.port.last().failSaves(null);
            h.press(KeyType.Enter);
            assertEquals(2, h.port.last().saveCount());
            assertToast(h, Messages.DELETED);
        }
    }

    /** Ctrl+T, then the {@code downs}-th entry. */
    private static void tool(TuiHarness h, int downs) {
        h.ctrl('t');
        for (int i = 0; i < downs; i++) {
            h.press(KeyType.ArrowDown);
        }
        h.press(KeyType.Enter);
    }

    @Test
    void aNewWifiNetworkIsNamedAfterItsSsidAndNeedsAPassword() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            tool(h, 3);
            assertTrue(h.screenText().contains(WifiDialog.TITLE), h.screenText());
            h.type("CafeNet");
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Enter); // security, hidden, pw, OK
            assertTrue(h.screenText().contains(Messages.WIFI_NEEDS_PASSWORD), h.screenText());

            h.type("cafe-psk-123");
            h.press(KeyType.Tab, KeyType.Enter);
            WifiRecord added = h.port.last().records().stream().filter(WifiRecord.class::isInstance)
                    .map(WifiRecord.class::cast).filter(w -> w.ssid().equals("CafeNet")).findFirst().orElseThrow();
            assertEquals("CafeNet", added.title());
            assertEquals("WPA2", added.security());
            assertEquals("cafe-psk-123", utf8(added.password()));
            assertToast(h, Messages.WIFI_SAVED);
        }
    }

    @Test
    void anOpenNetworkRefusesAPassword() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            tool(h, 3);
            h.type("Library");
            h.press(KeyType.Tab, KeyType.Enter); // security: the list opens on WPA2
            h.press(KeyType.ArrowDown, KeyType.ArrowDown, KeyType.ArrowDown, KeyType.Enter); // OPEN
            assertTrue(h.screenText().contains("OPEN"), h.screenText());
            h.press(KeyType.Tab, KeyType.Tab);
            h.type("nope");
            h.press(KeyType.Tab, KeyType.Enter);
            assertTrue(h.screenText().contains(Messages.OPEN_HAS_NO_PASSWORD), h.screenText());
            h.press(KeyType.Tab, KeyType.Enter); // the password box was emptied on submit
            WifiRecord open = h.port.last().records().stream().filter(WifiRecord.class::isInstance)
                    .map(WifiRecord.class::cast).filter(w -> w.ssid().equals("Library")).findFirst().orElseThrow();
            assertEquals(0, open.password().length());
        }
    }

    /** Ctrl+T, Change passphrase, then the three boxes and OK. */
    private static void changePassphrase(TuiHarness h, String current, String fresh, String repeat) {
        tool(h, 4);
        assertTrue(h.screenText().contains(PassphraseDialog.TITLE), h.screenText());
        h.type(current);
        h.press(KeyType.Tab);
        h.type(fresh);
        h.press(KeyType.Tab);
        h.type(repeat);
        h.press(KeyType.Tab, KeyType.Enter);
    }

    @Test
    void thePassphraseChangeNeedsTheCurrentOneAndAMatchingRepeat() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            changePassphrase(h, "not it", NEW_PASSPHRASE, NEW_PASSPHRASE);
            assertTrue(h.screenText().contains(Messages.CURRENT_WRONG), h.screenText());
            assertEquals(0, h.port.last().passphraseChangeCount());
            h.press(KeyType.Escape);

            changePassphrase(h, CANARY, NEW_PASSPHRASE, NEW_PASSPHRASE + "x");
            assertTrue(h.screenText().contains(Messages.PASSPHRASE_MISMATCH), h.screenText());
            h.press(KeyType.Escape);

            changePassphrase(h, "", NEW_PASSPHRASE, NEW_PASSPHRASE);
            assertTrue(h.screenText().contains(Messages.CURRENT_REQUIRED), h.screenText());
            assertEquals(0, h.port.last().passphraseChangeCount());
        }
    }

    @Test
    void thePassphraseChangesWithTheRecoveryKeyAndTheNewOneUnlocks() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            changePassphrase(h, RECOVERY, NEW_PASSPHRASE, NEW_PASSPHRASE);
            assertEquals(1, h.port.last().passphraseChangeCount());
            String screen = h.screenText();
            assertToast(h, Messages.PASSPHRASE_CHANGED);
            assertFalse(screen.contains(PassphraseDialog.TITLE));

            h.ctrl('l');
            h.unlockWith(NEW_PASSPHRASE);
            assertTrue(h.controller.isUnlocked());
        }
    }

    @Test
    void aFailedPassphraseChangeSaysWhichPassphraseOpensTheFile() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.port.last().failPassphraseChanges(VaultException.Code.PASSPHRASE_CHANGED_UNCONFIRMED);
            changePassphrase(h, CANARY, NEW_PASSPHRASE, NEW_PASSPHRASE);
            assertTrue(h.screenText().contains(Messages.CHANGE_UNCONFIRMED), h.screenText());
        }
    }

    @Test
    void shareWithNothingSelectedSaysSo() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.type("no such item");
            h.ctrl('s');
            assertToast(h, Messages.SELECT_ITEM);
        }
    }

    @Test
    void cardFieldsKeepPasswordsMaskedForEveryType() {
        for (VaultRecord r : new FakeVaultPort.FakeSession().records()) {
            String all = RecordDetailWindow.fields(r).toString();
            assertFalse(all.contains("SECRET"), all);
        }
    }

    @Test
    void theNewDialogsFitTheMinimumTerminal() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort(), ApprovalHost.none(), new TuiHarness.ManualClock(FakeVaultPort.T0),
                new TerminalSize(80, 24))) {
            h.unlockWith(CANARY);
            tool(h, 4);
            for (String label : List.of(PassphraseDialog.TITLE, "Current or recovery key:", "Repeat new passphrase:",
                    Messages.OLD_BACKUPS.substring(0, 20), "esc cancel")) {
                assertTrue(h.screenText().contains(label), label + "\n" + h.screenText());
            }
            h.press(KeyType.Escape);
            tool(h, 3);
            for (String label : List.of(WifiDialog.TITLE, "SSID:", "Security:", WifiDialog.HIDDEN, "Password:",
                    FormLayout.OK, "esc cancel")) {
                assertTrue(h.screenText().contains(label), label + "\n" + h.screenText());
            }
            h.press(KeyType.Escape);
            h.press(KeyType.Tab, KeyType.Enter);
            pressCardButton(h, RecordDetailWindow.EDIT);
            for (String label : List.of(LoginDialog.EDIT_TITLE, LoginDialog.TAGS_LABEL, LoginDialog.KEEP_PASSWORD,
                    FormLayout.CANCEL, "esc cancel")) {
                assertTrue(h.screenText().contains(label), label + "\n" + h.screenText());
            }
        }
    }
}
