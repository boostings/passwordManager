package pm.browser.bridge;

import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import pm.approval.ApprovalBroker;
import pm.approval.ApprovalRequest;
import pm.approval.Decision;
import pm.approval.Outcome;

/** {@link ApprovalPort} over an in-process {@link ApprovalBroker}. */
final class BrokerApproval implements ApprovalPort {
    private final ApprovalBroker broker;
    private final Duration wait;

    BrokerApproval(ApprovalBroker broker, Duration wait) {
        this.broker = Objects.requireNonNull(broker, "broker");
        this.wait = Objects.requireNonNull(wait, "wait");
    }

    @Override
    public boolean isUnlocked() {
        return broker.isUnlocked();
    }

    @Override
    @SuppressWarnings("PMD.DoNotUseThreads") // CE-025: re-asserting the interrupt flag is not thread creation
    public Outcome approve(ApprovalRequest request) {
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
            return decision.get(wait.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return denied(Decision.DENIED_TIMEOUT);
        } catch (ExecutionException | TimeoutException e) {
            // The prompt stays queued until the broker expires it; a late approval is never used.
            return denied(Decision.DENIED_TIMEOUT);
        }
    }

    private static Outcome denied(Decision decision) {
        return new Outcome(decision, Optional.empty());
    }
}
