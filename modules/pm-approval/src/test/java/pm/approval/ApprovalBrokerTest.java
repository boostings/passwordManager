package pm.approval;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** approval-model.md §3: one test per decision-table row, then policies, escalation and timeouts. */
class ApprovalBrokerTest {
    private static final Instant T0 = Instant.parse("2026-10-03T12:00:00Z");

    private final TestClock clock = new TestClock(T0);
    private final List<AuditEvent> events = new ArrayList<>();
    private final ApprovalBroker broker = new ApprovalBroker(clock, events::add, PolicyStore.inMemory(), "alice");
    private byte[] token;

    @BeforeEach
    void unlock() {
        broker.unlock();
        token = broker.withToken(byte[]::clone);
    }

    private CompletableFuture<Outcome> submit(ApprovalRequest q) {
        return broker.submit(q, token, Optional.of("alice"));
    }

    private static Decision now(CompletableFuture<Outcome> f) {
        assertTrue(f.isDone(), "decided without a prompt");
        return f.join().decision();
    }

    private PendingApproval onlyPrompt() {
        assertEquals(1, broker.pending().size());
        return broker.pending().get(0);
    }

    @Test
    void row1LockedDeniesWithoutPrompt() {
        broker.lock();
        assertEquals(Decision.DENIED_LOCKED, now(submit(Requests.inject(T0, "app", "dev"))));
        assertTrue(broker.pending().isEmpty());
        assertThrows(IllegalStateException.class, () -> broker.withToken(byte[]::clone));
    }

    @Test
    void row2BadTokenOrUserDeniesAndAudits() {
        byte[] wrong = token.clone();
        wrong[0] ^= 1;
        assertEquals(Decision.DENIED_AUTH, now(broker.submit(Requests.inject(T0, "app", "dev"), wrong, Optional.empty())));
        assertEquals(Decision.DENIED_AUTH, now(broker.submit(Requests.inject(T0, "app", "dev"), new byte[3], Optional.empty())));
        assertEquals(Decision.DENIED_AUTH, now(broker.submit(Requests.inject(T0, "app", "dev"), token, Optional.of("mallory"))));
        assertEquals("DENIED_AUTH", events.get(events.size() - 1).decision().orElseThrow());
        assertTrue(broker.pending().isEmpty());
    }

    @Test
    void tokenRotatesOnEveryUnlock() {
        broker.lock();
        broker.unlock();
        assertEquals(Decision.DENIED_AUTH, now(submit(Requests.inject(T0, "app", "dev"))), "old token is dead");
    }

    @Test
    void row3ReplayedOrStaleRequestsAreRefused() {
        ApprovalRequest q = Requests.inject(T0, "app", "dev");
        assertFalse(submit(q).isDone());
        assertEquals(Decision.DENIED_REPLAY, now(submit(Requests.sameIdAs(q))));
        assertEquals(Decision.DENIED_REPLAY, now(submit(Requests.inject(T0.minus(Duration.ofMinutes(6)), "app", "dev"))));
        assertEquals(Decision.DENIED_REPLAY, now(submit(Requests.inject(T0.plus(Duration.ofMinutes(2)), "app", "dev"))));
    }

    @Test
    void row4MalformedIsRejectedAtConstruction() {
        assertThrows(IllegalArgumentException.class, () -> Requests.inject(T0, "app", "Bad Profile"));
        assertThrows(IllegalArgumentException.class, () -> Requests.inject(T0, "", "dev"));
        assertThrows(IllegalArgumentException.class, () -> Requests.inject(T0, "app", "dev", "not-a-name"));
        assertEquals(Decision.DENIED_MALFORMED, broker.rejectMalformed().decision());
    }

    @Test
    void row5ExportAlwaysPromptsAndNeverLeavesAPolicy() {
        assertFalse(submit(Requests.export(T0, "app")).isDone());
        onlyPrompt().approveForSession();
        CompletableFuture<Outcome> second = submit(Requests.export(T0, "app"));
        assertFalse(second.isDone(), "export prompts again despite the session approval");
        onlyPrompt().approveOnce();
        assertEquals(Decision.ALLOWED_ONCE, second.join().decision());
    }

    @Test
    void row6SessionPolicyCoversSameScopeUntilLock() {
        CompletableFuture<Outcome> first = submit(Requests.inject(T0, "app", "dev", "DB", "KEY"));
        onlyPrompt().approveForSession();
        assertEquals(Decision.ALLOWED_SESSION, first.join().decision());

        assertEquals(Decision.ALLOWED_SESSION, now(submit(Requests.inject(T0, "app", "dev", "DB"))), "subset");
        assertFalse(submit(Requests.inject(T0, "app", "dev", "DB", "OTHER")).isDone(), "wider vars prompt");
        assertFalse(submit(Requests.inject(T0, "app", "dev")).isDone(), "whole profile is wider than listed vars");
        assertFalse(submit(Requests.inject(T0, "app", "prod", "DB")).isDone(), "other profile");
        assertFalse(submit(Requests.inject(T0, "web", "dev", "DB")).isDone(), "other project");

        broker.lock();
        broker.unlock();
        token = broker.withToken(byte[]::clone);
        assertFalse(submit(Requests.inject(T0, "app", "dev", "DB")).isDone(), "session policy died with the lock");
    }

    @Test
    void row7TemporaryPolicyExpires() {
        assertFalse(submit(Requests.inject(T0, "app", "dev")).isDone());
        onlyPrompt().approveForPolicy(Duration.ofMinutes(30));
        assertEquals(Decision.ALLOWED_POLICY, now(submit(Requests.inject(T0, "app", "dev"))));
        assertEquals(Decision.ALLOWED_POLICY, now(submit(Requests.inject(T0, "app", "dev", "ANY"))),
                "a whole-profile policy covers listed vars");
        assertEquals(1, broker.temporaryPolicies().size());

        broker.lock();
        broker.unlock();
        token = broker.withToken(byte[]::clone);
        clock.advance(Duration.ofMinutes(29));
        assertEquals(Decision.ALLOWED_POLICY, now(submit(Requests.inject(clock.instant(), "app", "dev"))),
                "temporary policies survive a lock");
        clock.advance(Duration.ofMinutes(1));
        assertFalse(submit(Requests.inject(clock.instant(), "app", "dev")).isDone(), "expired");
        assertTrue(broker.temporaryPolicies().isEmpty());
        assertThrows(IllegalArgumentException.class, () -> broker.pending().get(0).approveForPolicy(Duration.ofHours(25)));
    }

    @Test
    void revokedPolicyStopsCovering() {
        assertFalse(submit(Requests.inject(T0, "app", "dev")).isDone());
        onlyPrompt().approveForPolicy(Duration.ofHours(1));
        broker.revoke(broker.temporaryPolicies().get(0));
        assertFalse(submit(Requests.inject(T0, "app", "dev")).isDone());
    }

    @Test
    void row8BusyAfterFivePrompts() {
        for (int i = 0; i < ApprovalBroker.MAX_PENDING; i++) {
            assertFalse(submit(Requests.inject(T0, "app", "dev")).isDone());
        }
        assertEquals(Decision.DENIED_BUSY, now(submit(Requests.inject(T0, "app", "dev"))));
    }

    @Test
    void row9PromptsInArrivalOrderAndDenyWorks() {
        int[] notified = {0};
        broker.setPromptListener(() -> notified[0]++);
        ApprovalRequest a = Requests.inject(T0, "app", "dev");
        ApprovalRequest b = Requests.inject(T0, "web", "dev");
        CompletableFuture<Outcome> fa = submit(a);
        assertFalse(submit(b).isDone());
        assertEquals(2, notified[0]);
        assertEquals(a, broker.pending().get(0).request());
        broker.pending().get(0).deny();
        assertEquals(Decision.DENIED, fa.join().decision());
        assertEquals(b, broker.pending().get(0).request());
    }

    @Test
    void approveOnceCannotBeReused() {
        ApprovalRequest q = Requests.inject(T0, "app", "dev");
        CompletableFuture<Outcome> f = submit(q);
        PendingApproval prompt = onlyPrompt();
        prompt.approveOnce();
        prompt.approveForSession(); // a second answer is ignored
        Grant grant = f.join().grant().orElseThrow();
        grant.consume();
        assertThrows(IllegalStateException.class, grant::consume);
        assertEquals(Decision.DENIED_REPLAY, now(submit(Requests.sameIdAs(q))));
        assertFalse(submit(Requests.inject(T0, "app", "dev")).isDone(), "no policy was left behind");
    }

    @Test
    void unansweredPromptTimesOutAsDeny() {
        CompletableFuture<Outcome> f = submit(Requests.inject(T0, "app", "dev"));
        clock.advance(ApprovalBroker.PROMPT_TIMEOUT.minusSeconds(1));
        broker.expire();
        assertFalse(f.isDone());
        clock.advance(Duration.ofSeconds(1));
        broker.expire();
        assertEquals(Decision.DENIED_TIMEOUT, f.join().decision());
        assertTrue(broker.pending().isEmpty());
        assertTrue(events.stream().anyMatch(e -> e.decision().equals(Optional.of("DENIED_TIMEOUT"))));
    }

    @Test
    void lockDeniesWaitingPrompts() {
        CompletableFuture<Outcome> f = submit(Requests.inject(T0, "app", "dev"));
        broker.lock();
        assertEquals(Decision.DENIED_LOCKED, f.join().decision());
    }

    @Test
    void auditRecordsNamesAndCountsOnly() {
        CompletableFuture<Outcome> f = submit(Requests.inject(T0, "app", "dev", "DB", "KEY"));
        onlyPrompt().approveOnce();
        f.join();
        AuditEvent last = events.get(events.size() - 1);
        assertEquals("approval", last.kind());
        assertEquals(Optional.of("alice"), last.osUser());
        assertEquals(2, last.varCount());
        assertEquals(Optional.of("env"), last.argv0(), "program name only, never the full argv");
    }

    @Test
    void injectRequestsMustShowWhatRuns() {
        assertThrows(IllegalArgumentException.class, () -> new ApprovalRequest(java.util.UUID.randomUUID(),
                new ApprovalRequest.Requester(ApprovalRequest.Kind.CLI, "x"), ApprovalRequest.Operation.ENV_INJECT,
                ApprovalRequest.Scope.profile("app", "dev"), Duration.ZERO,
                new ApprovalRequest.Display(List.of(), Optional.empty(), ApprovalRequest.Effect.INJECT), T0));
        assertThrows(IllegalArgumentException.class, () -> new ApprovalRequest.Display(
                List.of("a\0b"), Optional.empty(), ApprovalRequest.Effect.INJECT));
        assertThrows(IllegalArgumentException.class, () -> new ApprovalRequest.Requester(
                ApprovalRequest.Kind.AGENT, "x".repeat(65)));
    }
}
