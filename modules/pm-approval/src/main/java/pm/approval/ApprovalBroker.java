package pm.approval;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import pm.crypto.ConstantTime;
import pm.crypto.Csprng;
import pm.crypto.SecretBytes;

/**
 * The approval broker (ADR 0009, approval-model.md). It evaluates the decision table of §3 in
 * order, queues prompts for the user, keeps session and temporary policies, refuses replays and
 * audits every decision. Secrets are released elsewhere, only against a single-use {@link Grant}.
 *
 * <p><b>Threads.</b> Requests arrive on transport threads and answers on the UI thread; every
 * piece of state is guarded by one private lock (LCK00-J). Futures are completed after the lock is
 * released, so no caller code runs under it (LCK09-J).
 */
public final class ApprovalBroker {
    /** An unanswered prompt is denied after this long (SR-111). */
    public static final Duration PROMPT_TIMEOUT = Duration.ofSeconds(60);
    /** Most prompts waiting at once (decision-table row 8). */
    public static final int MAX_PENDING = 5;
    /** Session-token length in bytes. */
    public static final int TOKEN_BYTES = 32;
    /** A request older than this is refused as a replay; its id need not be remembered longer. */
    static final Duration MAX_AGE = Duration.ofMinutes(5);
    /** A request dated further in the future than this is refused. */
    static final Duration MAX_SKEW = Duration.ofMinutes(1);

    private final ReentrantLock guard = new ReentrantLock();
    private final Clock clock;
    private final AuditSink audit;
    private final PolicyStore store;
    private final String osUser;
    /** Guarded by {@link #guard}. Request ids seen within {@link #MAX_AGE}, oldest first. */
    private final Map<UUID, Instant> seen = new LinkedHashMap<>();
    /** Guarded by {@link #guard}. */
    private final List<Policy> sessionPolicies = new ArrayList<>();
    /** Guarded by {@link #guard}. */
    private final Deque<PendingApproval> queue = new ArrayDeque<>();
    /** Guarded by {@link #guard}. */
    private Runnable promptListener = () -> { };
    /** Guarded by {@link #guard}. Present while the vault is unlocked. */
    private SecretBytes token;

    /**
     * @param clock time source for timeouts, staleness and policy expiry
     * @param audit audit sink
     * @param store temporary-policy store
     * @param osUser the OS user this broker runs as; it is the only user it serves
     */
    public ApprovalBroker(Clock clock, AuditSink audit, PolicyStore store, String osUser) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.store = Objects.requireNonNull(store, "store");
        this.osUser = Objects.requireNonNull(osUser, "osUser");
    }

    /** Called with no arguments, outside the lock, whenever a prompt is queued. */
    public void setPromptListener(Runnable listener) {
        Objects.requireNonNull(listener, "listener");
        locked(() -> {
            promptListener = listener;
            return null;
        });
    }

    /** The vault was unlocked: issue a fresh session token (approval-model §5). */
    public void unlock() {
        locked(() -> {
            if (token != null) {
                token.close();
            }
            token = Csprng.secretBytes(TOKEN_BYTES);
            return null;
        });
        audit.record(AuditEvent.of("unlock"));
    }

    /**
     * The vault locked: the token is destroyed (so every client must re-read the new one after the
     * next unlock), session policies end and waiting prompts are denied.
     */
    public void lock() {
        List<PendingApproval> cancelled = locked(() -> {
            if (token != null) {
                token.close();
                token = null;
            }
            sessionPolicies.clear();
            List<PendingApproval> all = new ArrayList<>(queue);
            queue.clear();
            return all;
        });
        cancelled.forEach(p -> finish(p, Outcome.denied(Decision.DENIED_LOCKED)));
        audit.record(AuditEvent.of("lock"));
    }

    /** True between {@link #unlock()} and {@link #lock()}. */
    public boolean isUnlocked() {
        return locked(() -> token != null);
    }

    /**
     * Gives {@code use} the current session token, to write the 0600 token file.
     *
     * @throws IllegalStateException {@code LOCKED} if the vault is locked
     */
    public <R> R withToken(Function<byte[], R> use) {
        return locked(() -> {
            if (token == null) {
                throw new IllegalStateException("LOCKED");
            }
            return token.apply(use);
        });
    }

    /**
     * Evaluates {@code request} against the decision table (approval-model §3). The returned future
     * is already complete unless the request needs the user.
     *
     * @param presentedToken the session token the client presented
     * @param peerOsUser the OS user the transport verified for the client, when it can
     */
    public CompletableFuture<Outcome> submit(ApprovalRequest request, byte[] presentedToken,
            Optional<String> peerOsUser) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(presentedToken, "presentedToken");
        Objects.requireNonNull(peerOsUser, "peerOsUser");
        Instant now = clock.instant();
        Evaluation result = locked(() -> evaluate(request, presentedToken, peerOsUser, now));
        audit.record(result.event());
        if (result.prompt() != null) {
            Runnable listener = locked(() -> promptListener);
            listener.run();
            return result.prompt().result();
        }
        return CompletableFuture.completedFuture(result.outcome());
    }

    /** Records a request the transport could not decode (row 4). */
    public Outcome rejectMalformed() {
        audit.record(AuditEvent.rejected(Decision.DENIED_MALFORMED));
        return Outcome.denied(Decision.DENIED_MALFORMED);
    }

    /** Waiting prompts in arrival order; the UI shows the first one. */
    public List<PendingApproval> pending() {
        return locked(() -> List.copyOf(queue));
    }

    /** Denies every prompt older than {@link #PROMPT_TIMEOUT}; call this on every UI tick. */
    public void expire() {
        Instant now = clock.instant();
        List<PendingApproval> timedOut = locked(() -> {
            List<PendingApproval> out = new ArrayList<>();
            for (Iterator<PendingApproval> it = queue.iterator(); it.hasNext();) {
                PendingApproval p = it.next();
                if (!now.isBefore(p.arrived().plus(PROMPT_TIMEOUT))) {
                    it.remove();
                    out.add(p);
                }
            }
            seen.values().removeIf(at -> at.plus(MAX_AGE).plus(MAX_SKEW).isBefore(now));
            return out;
        });
        for (PendingApproval p : timedOut) {
            audit.record(AuditEvent.approval(p.request(), osUser, Decision.DENIED_TIMEOUT));
            finish(p, Outcome.denied(Decision.DENIED_TIMEOUT));
        }
    }

    /** Unexpired temporary policies. */
    public List<Policy> temporaryPolicies() {
        Instant now = clock.instant();
        return store.load().stream().filter(p -> p.expires().map(now::isBefore).orElse(false)).toList();
    }

    /** Removes a temporary policy. */
    public void revoke(Policy policy) {
        locked(() -> {
            List<Policy> kept = new ArrayList<>(store.load());
            kept.remove(policy);
            store.save(kept);
            return null;
        });
        audit.record(AuditEvent.of("policy"));
    }

    void answer(PendingApproval prompt, Decision decision, Duration duration) {
        Instant now = clock.instant();
        boolean wasPending = locked(() -> {
            if (!queue.remove(prompt)) {
                return false; // already answered, timed out or cancelled
            }
            ApprovalRequest request = prompt.request();
            if (decision == Decision.ALLOWED_SESSION && !request.operation().alwaysPrompts()) {
                sessionPolicies.add(Policy.from(request, Optional.empty()));
            } else if (decision == Decision.ALLOWED_POLICY && !request.operation().alwaysPrompts()) {
                List<Policy> kept = new ArrayList<>(store.load());
                kept.removeIf(p -> p.expires().map(e -> !now.isBefore(e)).orElse(true));
                kept.add(Policy.from(request, Optional.of(now.plus(duration))));
                store.save(kept);
            }
            return true;
        });
        if (!wasPending) {
            return;
        }
        // Export and share can never leave a policy behind (row 5): such an approval counts once.
        Decision effective = decision.allowed() && prompt.request().operation().alwaysPrompts()
                ? Decision.ALLOWED_ONCE : decision;
        audit.record(AuditEvent.approval(prompt.request(), osUser, effective));
        finish(prompt, effective.allowed()
                ? Outcome.allowed(prompt.request(), effective) : Outcome.denied(effective));
    }

    private Evaluation evaluate(ApprovalRequest q, byte[] presentedToken, Optional<String> peerOsUser, Instant now) {
        if (token == null) {
            return Evaluation.done(q, osUser, Decision.DENIED_LOCKED);
        }
        boolean tokenOk = presentedToken.length == TOKEN_BYTES
                && token.apply(expected -> ConstantTime.equals(expected, presentedToken));
        if (!tokenOk || peerOsUser.map(u -> !u.equals(osUser)).orElse(false)) {
            return new Evaluation(Outcome.denied(Decision.DENIED_AUTH), null, AuditEvent.rejected(Decision.DENIED_AUTH));
        }
        if (seen.containsKey(q.requestId()) || q.created().isBefore(now.minus(MAX_AGE))
                || q.created().isAfter(now.plus(MAX_SKEW))) {
            return Evaluation.done(q, osUser, Decision.DENIED_REPLAY);
        }
        seen.put(q.requestId(), q.created());
        if (!q.operation().alwaysPrompts()) {
            if (sessionPolicies.stream().anyMatch(p -> p.covers(q, now))) {
                return Evaluation.allowed(q, osUser, Decision.ALLOWED_SESSION);
            }
            if (store.load().stream().anyMatch(p -> p.expires().isPresent() && p.covers(q, now))) {
                return Evaluation.allowed(q, osUser, Decision.ALLOWED_POLICY);
            }
        }
        if (queue.size() >= MAX_PENDING) {
            return Evaluation.done(q, osUser, Decision.DENIED_BUSY);
        }
        PendingApproval prompt = new PendingApproval(this, q, now);
        queue.addLast(prompt);
        return new Evaluation(null, prompt, new AuditEvent("prompt", Optional.of(q.requestId()),
                Optional.of(q.requester().kind().name()), Optional.of(osUser), Optional.of(q.scope().project()),
                Optional.of(q.scope().profile()), q.scope().vars().map(java.util.Set::size).orElse(-1),
                Optional.empty(), q.argv0().isEmpty() ? Optional.empty() : Optional.of(q.argv0())));
    }

    private static void finish(PendingApproval prompt, Outcome outcome) {
        prompt.result().complete(outcome);
    }

    private <T> T locked(java.util.function.Supplier<T> body) {
        guard.lock();
        try {
            return body.get();
        } finally {
            guard.unlock();
        }
    }

    /** The result of one decision-table pass: a final outcome, or a queued prompt. */
    private record Evaluation(Outcome outcome, PendingApproval prompt, AuditEvent event) {
        static Evaluation done(ApprovalRequest q, String osUser, Decision decision) {
            return new Evaluation(Outcome.denied(decision), null, AuditEvent.approval(q, osUser, decision));
        }

        static Evaluation allowed(ApprovalRequest q, String osUser, Decision decision) {
            return new Evaluation(Outcome.allowed(q, decision), null, AuditEvent.approval(q, osUser, decision));
        }
    }
}
