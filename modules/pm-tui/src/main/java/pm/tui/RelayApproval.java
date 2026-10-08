package pm.tui;

import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;
import pm.approval.ApprovalBroker;
import pm.approval.ApprovalRequest;
import pm.approval.Decision;
import pm.approval.Outcome;
import pm.approval.PendingApproval;
import pm.browser.bridge.ApprovalPort;

/**
 * The bridge's {@link ApprovalPort} for one relayed request (ADR 0014 §8). Like
 * {@link ApprovalPort#inProcess} it presents the broker's session token and waits for the user,
 * and in addition it gives up as soon as the native host has gone away ({@code gone}): the
 * waiting prompt is denied, and an approval that arrives anyway is dropped with its grant unused.
 * While the prompt waits, its socket peer is registered in {@link RelayPeers} so the dialog can
 * show it; a peer that already has a prompt waiting is answered {@code DENIED_BUSY}. The
 * extension must still be allowlisted ({@code allowed}, read again each time) before the prompt
 * is raised, when the dialog shows it ({@link RelayPeers#stillAllowed}) and when the answer
 * arrives: an extension taken off the allowlist meanwhile gets {@code DENIED_AUTH}, and an
 * approval given anyway is dropped with its grant unused. A refusal never throws; only the broker
 * can produce an allowing outcome.
 *
 * <p>The broker audits the user's answer when it is given. When the user allowed a request that is
 * refused all the same (host gone, wait over, extension taken off the allowlist, or the reply
 * withheld by the relay, {@link #withheld}), {@code overruled} is told, so the refusal is audited
 * as a second entry for the same request and the log never shows a release that did not happen.
 */
final class RelayApproval implements ApprovalPort {
    /**
     * Longest wait, after the prompt was withdrawn, for an answer the user gave in that same moment:
     * once a prompt has left the broker's queue its outcome follows as soon as the broker has
     * audited it.
     */
    static final Duration SETTLE = Duration.ofSeconds(5);

    private final ApprovalBroker broker;
    private final Duration wait;
    private final CompletableFuture<Void> gone;
    private final RelayPeers.Peer peer;
    private final RelayPeers peers;
    private final BooleanSupplier allowed;
    private final BiConsumer<ApprovalRequest, Decision> overruled;
    /** The request this port last allowed, until its reply is withheld. */
    private final AtomicReference<ApprovalRequest> allowedRequest = new AtomicReference<>();

    RelayApproval(ApprovalBroker broker, Duration wait, CompletableFuture<Void> gone, RelayPeers.Peer peer,
            RelayPeers peers, BooleanSupplier allowed, BiConsumer<ApprovalRequest, Decision> overruled) {
        this.broker = Objects.requireNonNull(broker, "broker");
        this.wait = Objects.requireNonNull(wait, "wait");
        this.gone = Objects.requireNonNull(gone, "gone");
        this.peer = Objects.requireNonNull(peer, "peer");
        this.peers = Objects.requireNonNull(peers, "peers");
        this.allowed = Objects.requireNonNull(allowed, "allowed");
        this.overruled = Objects.requireNonNull(overruled, "overruled");
    }

    /** Whether this port allowed a request whose reply has not been withheld. */
    boolean granted() {
        return allowedRequest.get() != null;
    }

    /**
     * The relay withholds the reply to the request this port allowed, with {@code refusal}: the
     * refusal is audited for that request ({@code overruled}). Does nothing if none was allowed.
     */
    void withheld(Decision refusal) {
        ApprovalRequest request = allowedRequest.getAndSet(null);
        if (request != null) {
            overruled.accept(request, refusal);
        }
    }

    @Override
    public boolean isUnlocked() {
        return broker.isUnlocked();
    }

    @Override
    public Outcome approve(ApprovalRequest request) {
        if (gone.isDone()) {
            return denied(Decision.DENIED);
        }
        if (!allowed.getAsBoolean()) {
            return denied(Decision.DENIED_AUTH); // taken off the allowlist: no prompt
        }
        if (!peers.begin(request.requestId(), peer, allowed)) {
            return denied(Decision.DENIED_BUSY); // one waiting prompt per peer
        }
        try {
            return ask(request);
        } finally {
            peers.end(request.requestId(), peer);
        }
    }

    @SuppressWarnings("PMD.DoNotUseThreads") // CE-065: re-asserting the interrupt flag is not thread creation
    private Outcome ask(ApprovalRequest request) {
        byte[] session;
        try {
            session = broker.withToken(byte[]::clone);
        } catch (IllegalStateException locked) {
            return denied(Decision.DENIED_LOCKED);
        }
        CompletableFuture<Outcome> decision;
        try {
            decision = broker.submit(request, session, Optional.empty());
        } finally {
            Arrays.fill(session, (byte) 0);
        }
        try {
            CompletableFuture.anyOf(decision, gone).get(wait.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            withdraw(request);
            return refuse(request, decision, Decision.DENIED_TIMEOUT);
        } catch (ExecutionException | TimeoutException e) {
            withdraw(request);
            return refuse(request, decision, Decision.DENIED_TIMEOUT);
        }
        if (gone.isDone()) {
            // The host is gone: nobody would receive the answer, so nothing may be released.
            withdraw(request);
            return refuse(request, decision, Decision.DENIED);
        }
        Outcome outcome = decision.join();
        if (!allowed.getAsBoolean()) {
            // Taken off the allowlist while the prompt waited: whatever the answer, nothing is
            // released to it, and the grant of an approval is dropped unused.
            return refuse(request, decision, Decision.DENIED_AUTH);
        }
        if (outcome.decision().allowed()) {
            allowedRequest.set(request);
        }
        return outcome;
    }

    /**
     * Refuses {@code request} with {@code refusal}. The prompt is no longer waiting (withdrawn or
     * answered), so the user's answer is in or follows at once; if it allowed the request, the
     * broker has audited that approval, and the refusal is audited after it ({@code overruled}).
     */
    @SuppressWarnings("PMD.DoNotUseThreads") // CE-065: re-asserting the interrupt flag is not thread creation
    private Outcome refuse(ApprovalRequest request, CompletableFuture<Outcome> decision, Decision refusal) {
        Outcome answer;
        try {
            answer = decision.get(SETTLE.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // closing down
            return denied(refusal);
        } catch (ExecutionException | TimeoutException e) {
            return denied(refusal); // no answer was audited
        }
        if (answer.decision().allowed()) {
            overruled.accept(request, refusal);
        }
        return denied(refusal);
    }

    /** Denies the prompt for {@code request} if it is still waiting, so the TUI stops showing it. */
    private void withdraw(ApprovalRequest request) {
        for (PendingApproval p : broker.pending()) {
            if (p.request().requestId().equals(request.requestId())) {
                p.deny();
            }
        }
    }

    private static Outcome denied(Decision decision) {
        return new Outcome(decision, Optional.empty());
    }
}
