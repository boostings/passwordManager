package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.googlecode.lanterna.input.KeyType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.domain.generate.PasswordPolicy;
import pm.vault.record.LoginRecord;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;

/**
 * plan.md §13 M4.4 in the TUI: Ctrl+T opens the tools menu; the generator shows a secret with its
 * entropy and empties it on close and lock (ADR 0008); the health view lists weak, reused and old
 * items by title only and never runs the breach check; ssh-agent actions go through the
 * {@link SshActions} port with the chosen constraints and show catalogue text.
 */
@SuppressWarnings("PMD.CloseResource") // CE-045: the test closes each record it builds
class ToolsTest {
    private static final String CANARY =
            Objects.requireNonNull(System.getProperty("pm.canary.secret"), "pm.canary.secret");
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");

    /** Records every call with the key text it was given; answers with {@link #next}. */
    private static class RecordingSsh implements SshActions {
        final List<String> calls = new ArrayList<>();
        final List<SecretBytes> given = new ArrayList<>();
        Outcome next = Outcome.ADDED;

        @Override
        public Outcome add(SecretBytes privateKey, Duration lifetime, boolean confirm) {
            given.add(privateKey);
            calls.add("add " + text(privateKey) + " " + lifetime.toSeconds() + " " + confirm);
            return next;
        }

        @Override
        public Outcome remove(SecretBytes privateKey) {
            given.add(privateKey);
            calls.add("remove " + text(privateKey));
            return next;
        }

        private static String text(SecretBytes key) {
            return key.apply(b -> new String(b, StandardCharsets.US_ASCII));
        }
    }

    /** Holds each agent call until the test runs it, as a stalled agent would. */
    private static final class HeldSsh extends RecordingSsh {
        final List<Runnable> held = new ArrayList<>();

        @Override
        public Executor executor() {
            return held::add;
        }
    }

    private static FakeVaultPort newPort() {
        return new FakeVaultPort(CANARY, "RK-0000-1111-2222");
    }

    @Test
    void ctrlTOpensTheToolsMenuAndTheGenerator() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.ctrl('t');
            assertEquals(ToolsMenu.TITLE, h.activeWindow().getTitle());
            h.press(KeyType.Enter);
            assertEquals(GenerateDialog.TITLE, h.activeWindow().getTitle());
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Enter); // -> Generate
            assertTrue(h.screenText().contains("bits of entropy"), h.screenText());
            h.press(KeyType.Escape);
            assertEquals(DashboardWindow.TITLE, h.activeWindow().getTitle());
            assertFalse(h.screenText().contains("bits of entropy"));
        }
    }

    @Test
    void generatorHonoursThePolicyAndClearsItsResult() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            GenerateDialog dialog = new GenerateDialog(h.theme, h.clock);
            h.controller.showForm(dialog);
            dialog.generate();
            assertEquals(PasswordPolicy.DEFAULT_LENGTH, dialog.shown().length());
            String first = dialog.shown();
            dialog.generate();
            assertFalse(first.equals(dialog.shown()), "each press draws a new secret");

            h.controller.lock();
            h.pump();
            assertEquals("", dialog.shown(), "lock empties the shown secret");
            assertFalse(h.controller.isUnlocked());
        }
    }

    @Test
    void passphraseModeAndBadSizes() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.ctrl('t');
            h.press(KeyType.Enter);
            h.press(KeyType.Tab);
            h.type(" "); // tick "Passphrase (words)": the size box switches to 6 words
            h.press(KeyType.Tab, KeyType.Enter); // the password-only boxes are disabled and skipped
            String screen = h.screenText();
            assertTrue(screen.contains("bits of entropy"), screen);
            assertTrue(screen.lines().anyMatch(l -> l.chars().filter(c -> c == '-').count() >= 5), screen);

            GenerateDialog dialog = new GenerateDialog(h.theme, h.clock);
            h.controller.showForm(dialog);
            h.press(KeyType.Backspace, KeyType.Backspace); // empty the size box
            dialog.generate();
            h.pump();
            assertEquals("", dialog.shown());
            assertTrue(h.screenText().contains(Messages.BAD_POLICY), h.screenText());
        }
    }

    @Test
    void healthViewListsTitlesOnlyAndPointsToTheCliForBreaches() {
        List<VaultRecord> records = List.of(
                login("Mail", "password", NOW), login("Bank", "vH7#qR2!mZ9$wK4&tL6^pN", NOW),
                login("Shop", "vH7#qR2!mZ9$wK4&tL6^pN", NOW),
                login("Forum", "Zq8#vT3!kL7$nB5&", NOW.minus(Duration.ofDays(400))));
        HealthWindow view = new HealthWindow(records, Clock.fixed(NOW, ZoneOffset.UTC), PmTheme.standard());
        String text = String.join("\n", view.lines());
        assertTrue(text.contains("4 passwords checked"), text);
        assertTrue(text.contains("Weak (1)") && text.contains("Mail"), text);
        assertTrue(text.contains("Reused (1)") && (text.contains("Bank, Shop") || text.contains("Shop, Bank")), text);
        assertTrue(text.contains("Not changed in a year (1)") && text.contains("Forum  400 days"), text);
        assertFalse(text.contains("password") && text.contains("vH7#"), "never a password");
        records.forEach(r -> ((LoginRecord) r).close());

        HealthWindow clean = new HealthWindow(List.of(), Clock.fixed(NOW, ZoneOffset.UTC), PmTheme.standard());
        assertTrue(clean.lines().contains(Messages.HEALTH_CLEAN));
    }

    @Test
    void healthOpensFromTheMenuWithTheBreachHint() throws IOException {
        try (TuiHarness h = new TuiHarness(newPort())) {
            h.unlockWith(CANARY);
            h.ctrl('t');
            h.press(KeyType.ArrowDown, KeyType.Enter);
            assertEquals(HealthWindow.TITLE, h.activeWindow().getTitle());
            assertTrue(h.screenText().contains("pm health --breach"), h.screenText());
            assertFalse(h.screenText().contains(FakeVaultPort.LOGIN_SECRET));
        }
    }

    @Test
    void sshActionsUseTheSelectedKeyAndShowTheOutcome() throws IOException {
        RecordingSsh ssh = new RecordingSsh();
        try (TuiHarness h = new TuiHarness(newPort(), ssh)) {
            h.unlockWith(CANARY);
            h.ctrl('t');
            h.press(KeyType.ArrowDown, KeyType.ArrowDown, KeyType.Enter);
            assertEquals(ToolsMenu.TITLE, h.activeWindow().getTitle(), "no SSH row selected yet");
            assertTrue(h.screenText().contains(Messages.SELECT_SSH_KEY), h.screenText());
            h.press(KeyType.Escape);

            h.press(KeyType.Tab, KeyType.ArrowDown, KeyType.ArrowDown); // table rows: GitHub, Home WiFi, Deploy key
            h.ctrl('t');
            h.press(KeyType.ArrowDown, KeyType.ArrowDown, KeyType.Enter);
            assertEquals(SshAgentDialog.TITLE, h.activeWindow().getTitle());
            assertTrue(h.screenText().contains("SHA256:abc"), h.screenText());
            assertFalse(h.screenText().contains("ssh-SECRET"));
            h.press(KeyType.Enter); // Add to agent, no constraints
            assertEquals(List.of("add ssh-SECRET 0 false"), ssh.calls);
            assertTrue(ssh.given.get(0).isClosed(), "the call's copy of the key is closed after it");
            assertTrue(h.screenText().contains(Messages.of(SshActions.Outcome.ADDED)), h.screenText());
        }
    }

    @Test
    void sshDialogPassesConstraintsAndShowsFailures() throws IOException {
        RecordingSsh ssh = new RecordingSsh();
        SshKeyRecord key = sshKey();
        try (TuiHarness h = new TuiHarness(newPort())) {
            SshAgentDialog dialog = new SshAgentDialog(key, ssh, PmTheme.standard());
            dialog.add();
            assertTrue(ssh.calls.isEmpty(), "nothing runs before the dialog is shown");
            h.controller.show(dialog.window());
            dialog.add();
            h.pump();
            ssh.next = SshActions.Outcome.NO_AGENT;
            dialog.remove();
            h.pump();
            assertEquals(List.of("add k 0 false", "remove k"), ssh.calls);
            assertEquals(Messages.of(SshActions.Outcome.NO_AGENT), dialog.status());
            assertFalse(dialog.busy());
        }
        for (SshActions.Outcome o : SshActions.Outcome.values()) {
            assertFalse(Messages.of(o).isEmpty());
        }
        assertEquals(SshActions.Outcome.UNAVAILABLE, SshActions.none().add(key.privateKey(), Duration.ZERO, false));
        assertEquals(SshActions.Outcome.UNAVAILABLE, SshActions.none().remove(key.privateKey()));
        key.close();
    }

    @Test
    void aPendingAgentCallKeepsTheUiLiveAndLockTearsTheDialogDown() throws IOException {
        HeldSsh ssh = new HeldSsh();
        SshKeyRecord key = sshKey();
        try (TuiHarness h = new TuiHarness(newPort(), ssh)) {
            h.unlockWith(CANARY);
            SshAgentDialog dialog = new SshAgentDialog(key, ssh, PmTheme.standard());
            h.controller.show(dialog.window());
            dialog.add();
            h.pump();
            assertTrue(dialog.busy());
            assertEquals(Messages.SSH_WORKING, dialog.status());
            assertEquals(1, ssh.held.size(), "the call waits off the GUI thread");
            dialog.remove();
            assertEquals(1, ssh.held.size(), "one call at a time");

            h.controller.lock(); // the GUI thread is free, so lock runs while the call is pending
            h.pump();
            assertFalse(h.controller.isUnlocked());
            assertEquals(UnlockWindow.TITLE, h.activeWindow().getTitle());
            key.close(); // as the session does on lock: the call has its own copy

            ssh.held.get(0).run(); // the agent answers late
            h.pump();
            assertEquals(List.of("add k 0 false"), ssh.calls);
            assertTrue(ssh.given.get(0).isClosed());
            assertFalse(h.screenText().contains(Messages.of(SshActions.Outcome.ADDED)), "a late result is dropped");
            assertEquals(UnlockWindow.TITLE, h.activeWindow().getTitle());
            assertFalse(dialog.busy());
        }
    }

    @Test
    void aRefusedOrFailingCallIsReportedAsAFailure() throws IOException {
        SshKeyRecord key = sshKey();
        SshActions throwing = new RecordingSsh() {
            @Override
            public Executor executor() {
                return r -> {
                    throw new RejectedExecutionException("shut down");
                };
            }
        };
        RecordingSsh failing = new RecordingSsh() {
            @Override
            public Outcome add(SecretBytes privateKey, Duration lifetime, boolean confirm) {
                throw new IllegalStateException("agent adapter bug");
            }
        };
        try (TuiHarness h = new TuiHarness(newPort())) {
            SshAgentDialog rejected = new SshAgentDialog(key, throwing, PmTheme.standard());
            h.controller.show(rejected.window());
            rejected.add();
            h.pump();
            assertEquals(Messages.of(SshActions.Outcome.AGENT_FAILED), rejected.status());
            h.press(KeyType.Escape);

            SshAgentDialog broken = new SshAgentDialog(key, failing, PmTheme.standard());
            h.controller.show(broken.window());
            broken.add();
            h.pump();
            assertEquals(Messages.of(SshActions.Outcome.AGENT_FAILED), broken.status());
        }
        key.close();
    }

    private static SshKeyRecord sshKey() {
        return new SshKeyRecord(UUID.randomUUID(), "Deploy key", "ssh-ed25519",
                SecretBytes.copyOf("k".getBytes(StandardCharsets.US_ASCII)), "ssh-ed25519 AAAA", "SHA256:abc", "",
                List.of(), NOW, NOW);
    }

    private static LoginRecord login(String title, String pw, Instant at) {
        return new LoginRecord(UUID.randomUUID(), title, "alice",
                SecretBytes.copyOf(pw.getBytes(StandardCharsets.UTF_8)), List.of(), "", List.of(), at, at, at);
    }
}
