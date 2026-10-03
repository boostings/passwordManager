package pm.approval;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * A request waiting for the user (decision-table row 9). The prompt UI shows {@link #request()}
 * and calls exactly one of the four answer methods; later calls are ignored. An unanswered prompt
 * is denied after {@link ApprovalBroker#PROMPT_TIMEOUT} (SR-111).
 */
public final class PendingApproval {
    private final ApprovalBroker broker;
    private final ApprovalRequest asked;
    private final Instant queuedAt;
    private final CompletableFuture<Outcome> answer = new CompletableFuture<>();

    PendingApproval(ApprovalBroker broker, ApprovalRequest request, Instant arrived) {
        this.broker = Objects.requireNonNull(broker, "broker");
        this.asked = Objects.requireNonNull(request, "request");
        this.queuedAt = Objects.requireNonNull(arrived, "arrived");
    }

    /** The request, for display. */
    public ApprovalRequest request() {
        return asked;
    }

    /** When the prompt was queued. */
    public Instant arrived() {
        return queuedAt;
    }

    /** True once answered, timed out or cancelled by a lock. */
    public boolean isDone() {
        return answer.isDone();
    }

    /** Approves this request only. */
    public void approveOnce() {
        broker.answer(this, Decision.ALLOWED_ONCE, Duration.ZERO);
    }

    /** Approves this request and the same scope until the vault locks. */
    public void approveForSession() {
        broker.answer(this, Decision.ALLOWED_SESSION, Duration.ZERO);
    }

    /**
     * Approves this request and the same scope for {@code duration}.
     *
     * @throws IllegalArgumentException if {@code duration} is not positive or exceeds 24 h
     */
    public void approveForPolicy(Duration duration) {
        if (duration.isNegative() || duration.isZero() || duration.compareTo(ApprovalRequest.MAX_DURATION) > 0) {
            throw new IllegalArgumentException("BAD_DURATION");
        }
        broker.answer(this, Decision.ALLOWED_POLICY, duration);
    }

    /** Denies the request. */
    public void deny() {
        broker.answer(this, Decision.DENIED, Duration.ZERO);
    }

    CompletableFuture<Outcome> result() {
        return answer;
    }
}
