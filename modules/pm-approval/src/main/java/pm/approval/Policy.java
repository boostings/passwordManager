package pm.approval;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * A standing approval (approval-model.md §2). A session policy ({@code expires} empty) lasts until
 * the vault locks; a temporary policy lasts until {@code expires}, at most 24 h after creation. A
 * policy covers one requester kind and label, one operation and one scope, never wider than the
 * request it was created from.
 *
 * @param requesterKind requester kind it covers
 * @param label requester label it covers (untrusted, compared exactly)
 * @param operation operation it covers; never export, share or passkey
 * @param scope project, profile and variables it covers
 * @param expires end of a temporary policy; empty for a session policy
 */
public record Policy(ApprovalRequest.Kind requesterKind, String label, ApprovalRequest.Operation operation,
        ApprovalRequest.Scope scope, Optional<Instant> expires) {

    public Policy {
        Objects.requireNonNull(requesterKind, "requesterKind");
        Objects.requireNonNull(label, "label");
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(expires, "expires");
        if (Objects.requireNonNull(operation, "operation").alwaysPrompts()) {
            throw new IllegalArgumentException("NO_POLICY_FOR_OPERATION");
        }
    }

    static Policy from(ApprovalRequest request, Optional<Instant> expires) {
        return new Policy(request.requester().kind(), request.requester().label(), request.operation(),
                request.scope(), expires);
    }

    /** True if this policy covers {@code request} at {@code now}. */
    boolean covers(ApprovalRequest request, Instant now) {
        return requesterKind == request.requester().kind()
                && label.equals(request.requester().label())
                && operation == request.operation()
                && expires.map(now::isBefore).orElse(true)
                && request.scope().isWithin(scope);
    }
}
