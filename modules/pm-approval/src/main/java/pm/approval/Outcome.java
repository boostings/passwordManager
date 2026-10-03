package pm.approval;

import java.util.Objects;
import java.util.Optional;

/**
 * The broker's answer to one request.
 *
 * @param decision what the decision table or the user decided
 * @param grant present exactly when {@code decision} is an approval
 */
public record Outcome(Decision decision, Optional<Grant> grant) {
    public Outcome {
        Objects.requireNonNull(decision, "decision");
        Objects.requireNonNull(grant, "grant");
        if (decision.allowed() != grant.isPresent()) {
            throw new IllegalArgumentException("GRANT_MISMATCH");
        }
    }

    static Outcome denied(Decision decision) {
        return new Outcome(decision, Optional.empty());
    }

    static Outcome allowed(ApprovalRequest request, Decision decision) {
        return new Outcome(decision, Optional.of(new Grant(request, decision)));
    }
}
