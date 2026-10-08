package pm.approval;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import pm.approval.ApprovalRequest.Display;
import pm.approval.ApprovalRequest.Effect;
import pm.approval.ApprovalRequest.Kind;
import pm.approval.ApprovalRequest.Operation;
import pm.approval.ApprovalRequest.Requester;
import pm.approval.ApprovalRequest.Scope;
import pm.approval.run.EnvRelease;
import pm.approval.run.EnvRunner;

/** The checks the request, policy, outcome and grant values make on what they are given. */
class ApprovalValuesTest {
    private static final Instant T0 = Instant.parse("2026-10-03T12:00:00Z");
    private static final Display INJECT = new Display(Requests.ARGV, Optional.empty(), Effect.INJECT);

    private static String message(Runnable r) {
        return assertThrows(IllegalArgumentException.class, r::run).getMessage();
    }

    private static SortedSet<String> names(int n) {
        return IntStream.range(0, n).mapToObj(i -> "V" + i).collect(Collectors.toCollection(TreeSet::new));
    }

    @Test
    void aScopeRefusesEmptyTooManyOrBadVariablesAndTooManyRecords() {
        assertEquals("BAD_VARS", message(() -> new Scope("app", "dev", Optional.of(new TreeSet<>()), List.of())));
        assertEquals("BAD_VARS", message(() -> new Scope("app", "dev",
                Optional.of(names(ApprovalRequest.MAX_ITEMS + 1)), List.of())));
        assertEquals("BAD_VARS", message(() -> new Scope("app", "dev",
                Optional.of(new TreeSet<>(List.of("1BAD"))), List.of())));
        assertEquals(ApprovalRequest.MAX_ITEMS, new Scope("app", "dev", Optional.of(names(ApprovalRequest.MAX_ITEMS)),
                List.of()).vars().orElseThrow().size());
        List<UUID> records = Collections.nCopies(ApprovalRequest.MAX_ITEMS + 1, UUID.randomUUID());
        assertEquals("BAD_RECORDS", message(() -> new Scope("app", "dev", Optional.empty(), records)));
    }

    @Test
    void aScopeWithRecordsIsNeverWithinAPolicy() {
        Scope policy = new Scope("app", "dev", Optional.of(new TreeSet<>(List.of("A", "B"))), List.of());
        assertTrue(new Scope("app", "dev", Optional.of(new TreeSet<>(List.of("A"))), List.of()).isWithin(policy));
        assertFalse(new Scope("app", "dev", Optional.of(new TreeSet<>(List.of("A"))), List.of(UUID.randomUUID()))
                .isWithin(policy));
        assertFalse(new Scope("app", "dev", Optional.of(new TreeSet<>(List.of("C"))), List.of()).isWithin(policy));
    }

    @Test
    void aDisplayRefusesTooManyLongOrNulArguments() {
        List<String> many = Collections.nCopies(ApprovalRequest.MAX_ARGS + 1, "x");
        assertEquals("BAD_ARGV", message(() -> new Display(many, Optional.empty(), Effect.INJECT)));
        String longArg = "x".repeat(ApprovalRequest.MAX_ARG_CHARS + 1);
        assertEquals("BAD_ARGV", message(() -> new Display(List.of(longArg), Optional.empty(), Effect.INJECT)));
        assertEquals("BAD_ARGV", message(() -> new Display(List.of("a\0b"), Optional.empty(), Effect.INJECT)));
        assertEquals(1, new Display(List.of("x".repeat(ApprovalRequest.MAX_ARG_CHARS)), Optional.empty(),
                Effect.INJECT).argv().size());
    }

    @Test
    void textFieldsRefuseEmptyLongAndControlCharacters() {
        assertEquals("BAD_LABEL", message(() -> new Requester(Kind.CLI, "")));
        assertEquals("BAD_LABEL", message(() -> new Requester(Kind.CLI, "x".repeat(ApprovalRequest.MAX_LABEL_CHARS + 1))));
        assertEquals("BAD_LABEL", message(() -> new Requester(Kind.CLI, "a\tb")));
        assertEquals("BAD_LABEL", message(() -> new Requester(Kind.CLI, "a\u007fb")));
        assertEquals("~", new Requester(Kind.CLI, "~").label(), "0x7e is printable");
    }

    @Test
    void aRequestRefusesABadDurationAndAnInjectionThatShowsSomethingElse() {
        Requester cli = new Requester(Kind.CLI, "pm env run");
        Scope scope = Scope.profile("app", "dev");
        assertEquals("BAD_DURATION", message(() -> new ApprovalRequest(UUID.randomUUID(), cli, Operation.ENV_INJECT,
                scope, Duration.ofSeconds(-1), INJECT, T0)));
        assertEquals("BAD_DURATION", message(() -> new ApprovalRequest(UUID.randomUUID(), cli, Operation.ENV_INJECT,
                scope, ApprovalRequest.MAX_DURATION.plusSeconds(1), INJECT, T0)));
        assertEquals("BAD_DISPLAY", message(() -> new ApprovalRequest(UUID.randomUUID(), cli, Operation.ENV_INJECT,
                scope, Duration.ZERO, new Display(List.of(), Optional.empty(), Effect.INJECT), T0)));
        assertEquals("BAD_DISPLAY", message(() -> new ApprovalRequest(UUID.randomUUID(), cli, Operation.ENV_INJECT,
                scope, Duration.ZERO, new Display(Requests.ARGV, Optional.empty(), Effect.SHOW), T0)));
        assertEquals(ApprovalRequest.MAX_DURATION, new ApprovalRequest(UUID.randomUUID(), cli, Operation.ENV_INJECT,
                scope, ApprovalRequest.MAX_DURATION, INJECT, T0).duration());
    }

    @Test
    void aPolicyCoversOnlyItsOwnKindLabelAndOperation() {
        ApprovalRequest q = Requests.inject(T0, "app", "dev");
        Policy policy = Policy.from(q, Optional.empty());
        assertTrue(policy.covers(q, T0));
        assertFalse(new Policy(Kind.AGENT, q.requester().label(), q.operation(), q.scope(), Optional.empty())
                .covers(q, T0), "another kind");
        assertFalse(new Policy(Kind.CLI, "pm other", q.operation(), q.scope(), Optional.empty())
                .covers(q, T0), "another label");
        assertFalse(new Policy(Kind.CLI, q.requester().label(), Operation.REVEAL, q.scope(), Optional.empty())
                .covers(q, T0), "another operation");
        assertEquals("NO_POLICY_FOR_OPERATION", message(() -> new Policy(Kind.CLI, "pm", Operation.EXPORT,
                q.scope(), Optional.empty())));
    }

    @Test
    void anOutcomeHasAGrantExactlyWhenItIsAnApproval() {
        ApprovalRequest q = Requests.inject(T0, "app", "dev");
        assertEquals("GRANT_MISMATCH", message(() -> new Outcome(Decision.ALLOWED_ONCE, Optional.empty())));
        Grant grant = new Grant(q, Decision.ALLOWED_ONCE);
        assertEquals("GRANT_MISMATCH", message(() -> new Outcome(Decision.DENIED, Optional.of(grant))));
        assertEquals("NOT_ALLOWED", message(() -> new Grant(q, Decision.DENIED)));
    }

    @Test
    void onlyAnInjectionGrantReleasesOrRunsAnything() {
        ApprovalRequest export = Requests.export(T0, "app");
        Grant grant = new Grant(export, Decision.ALLOWED_ONCE);
        assertEquals("NOT_ENV_INJECT", message(() -> EnvRelease.release(grant, List.of())));
        Grant inject = new Grant(Requests.inject(T0, "app", "dev"), Decision.ALLOWED_ONCE);
        assertEquals("NO_SUCH_PROJECT", message(() -> EnvRelease.release(inject, List.of())));
        assertThrows(IllegalStateException.class, () -> EnvRelease.release(inject, List.of()), "consumed first");
        assertEquals("NOT_ENV_INJECT", message(() -> {
            try {
                EnvRunner.start(export, new TreeMap<>(), java.util.Set.of(), Path.of("."),
                        ProcessBuilder.Redirect.DISCARD);
            } catch (java.io.IOException e) {
                throw new AssertionError(e);
            }
        }));
    }

    @Test
    void aPolicyAnswerMustLastSomeTimeAndAtMostADay() {
        ApprovalBroker broker = new ApprovalBroker(new TestClock(T0), e -> { }, PolicyStore.inMemory(), "alice");
        broker.unlock();
        byte[] token = broker.withToken(byte[]::clone);
        CompletableFuture<Outcome> f = broker.submit(Requests.inject(T0, "app", "dev"), token, Optional.empty());
        PendingApproval prompt = broker.pending().get(0);
        assertEquals("BAD_DURATION", message(() -> prompt.approveForPolicy(Duration.ZERO)));
        assertEquals("BAD_DURATION", message(() -> prompt.approveForPolicy(Duration.ofSeconds(-1))));
        prompt.approveForPolicy(ApprovalRequest.MAX_DURATION);
        assertEquals(Decision.ALLOWED_POLICY, f.join().decision());
    }

    @Test
    void unlockingTwiceRotatesTheTokenAndLockingTwiceIsHarmless() {
        List<AuditEvent> events = new ArrayList<>();
        ApprovalBroker broker = new ApprovalBroker(new TestClock(T0), events::add, PolicyStore.inMemory(), "alice");
        broker.unlock();
        byte[] first = broker.withToken(byte[]::clone);
        broker.unlock();
        java.util.HexFormat hex = java.util.HexFormat.of();
        assertFalse(hex.formatHex(first).equals(broker.withToken(hex::formatHex)), "a fresh token");
        broker.lock();
        broker.lock();
        assertThrows(IllegalStateException.class, () -> broker.withToken(byte[]::clone));
        assertEquals(List.of("unlock", "unlock", "lock", "lock"), events.stream().map(AuditEvent::kind).toList());
    }

    @Test
    void storedPoliciesWithoutAnEndAreIgnoredAndDroppedOnTheNextSave() {
        PolicyStore store = PolicyStore.inMemory();
        ApprovalRequest q = Requests.inject(T0, "app", "dev");
        Policy endless = Policy.from(q, Optional.empty());
        Policy expired = Policy.from(Requests.inject(T0, "other", "dev"), Optional.of(T0.minusSeconds(1)));
        Policy live = Policy.from(Requests.inject(T0, "third", "dev"), Optional.of(T0.plusSeconds(60)));
        store.save(List.of(endless, expired, live));
        ApprovalBroker broker = new ApprovalBroker(new TestClock(T0), e -> { }, store, "alice");
        broker.unlock();
        byte[] token = broker.withToken(byte[]::clone);
        CompletableFuture<Outcome> f = broker.submit(q, token, Optional.empty());
        assertFalse(f.isDone(), "a stored policy with no end is not a temporary policy");
        broker.pending().get(0).approveForPolicy(Duration.ofMinutes(5));
        assertEquals(Decision.ALLOWED_POLICY, f.join().decision());
        List<Policy> kept = store.load();
        assertEquals(2, kept.size(), "the endless and expired ones are gone");
        assertTrue(kept.contains(live));
        assertEquals(Optional.of(T0.plus(Duration.ofMinutes(5))), kept.get(1).expires());
    }
}
