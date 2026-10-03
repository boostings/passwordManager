package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.googlecode.lanterna.input.KeyType;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import pm.approval.ApprovalBroker;
import pm.approval.ApprovalRequest;
import pm.approval.Decision;
import pm.approval.Outcome;
import pm.approval.PolicyStore;
import pm.approval.ipc.Releaser;

/** approval-model §4 (SR-109): the prompt shows the exact argv, guards input, and needs y/s/p then Enter. */
class ApprovalDialogTest {
    private static final String UNLOCK_PHRASE = "canary-passphrase";
    private static final List<String> ARGV = List.of("/usr/bin/npm", "run", "dev", "$(rm -rf ~)");

    /** A broker in this JVM, no socket: the host side of the TUI only. */
    private static final class InProcessHost implements ApprovalHost {
        final ApprovalBroker core;
        Releaser releaser;

        InProcessHost(TuiHarness.ManualClock clock) {
            core = new ApprovalBroker(clock, e -> { }, PolicyStore.inMemory(), "alice");
        }

        @Override
        public Optional<ApprovalBroker> broker() {
            return Optional.of(core);
        }

        @Override
        public void unlocked(Releaser r) {
            releaser = r;
            core.unlock();
        }

        @Override
        public void locked() {
            releaser = null;
            core.lock();
        }

        @Override
        public void close() {
            core.lock();
        }
    }

    private final TuiHarness.ManualClock clock = new TuiHarness.ManualClock(FakeVaultPort.T0);
    private final InProcessHost host = new InProcessHost(clock);

    private TuiHarness unlocked() throws IOException {
        TuiHarness h = new TuiHarness(new FakeVaultPort(UNLOCK_PHRASE, "recovery-unused"), host, clock);
        h.unlockWith(UNLOCK_PHRASE);
        assertTrue(h.controller.isUnlocked());
        return h;
    }

    private CompletableFuture<Outcome> ask(TuiHarness h) {
        ApprovalRequest q = new ApprovalRequest(UUID.randomUUID(),
                new ApprovalRequest.Requester(ApprovalRequest.Kind.CLI, "pm env run"),
                ApprovalRequest.Operation.ENV_INJECT,
                new ApprovalRequest.Scope("app", "dev", Optional.of(new java.util.TreeSet<>(List.of("DB_URL"))), List.of()),
                Duration.ZERO, new ApprovalRequest.Display(ARGV, Optional.empty(), ApprovalRequest.Effect.INJECT),
                h.clock.instant());
        CompletableFuture<Outcome> f = host.core.withToken(t -> host.core.submit(q, t, Optional.of("alice")));
        h.tick();
        return f;
    }

    private static void pastGuard(TuiHarness h) {
        h.clock.advance(ApprovalDialog.INPUT_GUARD.plusMillis(1));
        h.tick();
    }

    @Test
    void promptShowsRequesterScopeAndEveryArgvElementOnItsOwnLine() throws IOException {
        try (TuiHarness h = unlocked()) {
            assertFalse(ask(h).isDone());
            String screen = h.screenText();
            assertTrue(screen.contains(ApprovalDialog.TITLE), screen);
            assertTrue(screen.contains("\"pm env run\"  (cli)"));
            assertTrue(screen.contains("runs as alice (verified)"));
            assertTrue(screen.contains("project app   profile dev"));
            assertTrue(screen.contains("1 variable: DB_URL"));
            for (String arg : ARGV) {
                assertTrue(screen.contains("  \"" + arg + "\""), arg);
            }
        }
    }

    @Test
    void keysInTheFirstHalfSecondAreIgnored() throws IOException {
        try (TuiHarness h = unlocked()) {
            CompletableFuture<Outcome> f = ask(h);
            h.type("y");
            h.press(KeyType.Enter);
            assertFalse(f.isDone(), "y + Enter during the guard must not approve");
            assertTrue(h.screenText().contains(ApprovalDialog.GUARDED));
            pastGuard(h);
            assertTrue(h.screenText().contains(ApprovalDialog.KEYS));
            h.press(KeyType.Enter);
            assertFalse(f.isDone(), "Enter alone never approves");
            h.type("y");
            assertFalse(f.isDone(), "y alone never approves");
            h.press(KeyType.Enter);
            assertEquals(Decision.ALLOWED_ONCE, f.join().decision());
            h.tick();
            assertFalse(h.screenText().contains(ApprovalDialog.TITLE), "the dialog closes once answered");
        }
    }

    @Test
    void sessionApprovalNeedsAConfirmationEnter() throws IOException {
        try (TuiHarness h = unlocked()) {
            CompletableFuture<Outcome> f = ask(h);
            pastGuard(h);
            h.type("s");
            assertTrue(h.screenText().contains(ApprovalDialog.CONFIRM_SESSION));
            h.press(KeyType.Enter);
            assertFalse(f.isDone());
            assertTrue(h.screenText().contains(ApprovalDialog.CONFIRM_AGAIN));
            h.press(KeyType.Enter);
            assertEquals(Decision.ALLOWED_SESSION, f.join().decision());
        }
    }

    @Test
    void policyApprovalLastsOneHour() throws IOException {
        try (TuiHarness h = unlocked()) {
            CompletableFuture<Outcome> f = ask(h);
            pastGuard(h);
            h.type("p");
            h.press(KeyType.Enter, KeyType.Enter);
            assertEquals(Decision.ALLOWED_POLICY, f.join().decision());
            assertEquals(Optional.of(h.clock.instant().plus(ApprovalDialog.POLICY_DURATION)),
                    host.core.temporaryPolicies().get(0).expires());
        }
    }

    @Test
    void nAndEscapeDeny() throws IOException {
        try (TuiHarness h = unlocked()) {
            CompletableFuture<Outcome> first = ask(h);
            CompletableFuture<Outcome> second = ask(h);
            pastGuard(h);
            h.type("n");
            assertEquals(Decision.DENIED, first.join().decision());
            h.tick(); // the next prompt appears, with its own input guard
            assertTrue(h.screenText().contains(ApprovalDialog.GUARDED));
            pastGuard(h);
            h.press(KeyType.Escape);
            assertEquals(Decision.DENIED, second.join().decision());
        }
    }

    @Test
    void lockingDeniesTheWaitingPromptAndClosesIt() throws IOException {
        try (TuiHarness h = unlocked()) {
            CompletableFuture<Outcome> f = ask(h);
            assertNotNull(host.releaser, "the session releases secrets while unlocked");
            h.ctrl('l'); // swallowed by the modal prompt: no key typed at it reaches the dashboard
            assertFalse(f.isDone());
            h.timers.fireLatest(); // idle lock
            h.pump();
            assertEquals(Decision.DENIED_LOCKED, f.join().decision());
            assertNull(host.releaser);
            assertFalse(h.screenText().contains(ApprovalDialog.TITLE));
            assertTrue(h.screenText().contains(UnlockWindow.TITLE));
        }
    }

    @Test
    void anUnansweredPromptIsDeniedAfterTheTimeout() throws IOException {
        try (TuiHarness h = unlocked()) {
            CompletableFuture<Outcome> f = ask(h);
            pastGuard(h);
            assertTrue(h.screenText().contains("denied automatically in 59 s"), h.screenText());
            h.clock.advance(ApprovalBroker.PROMPT_TIMEOUT);
            host.core.expire();
            h.tick();
            assertEquals(Decision.DENIED_TIMEOUT, f.join().decision());
            assertFalse(h.screenText().contains(ApprovalDialog.TITLE));
        }
    }
}
