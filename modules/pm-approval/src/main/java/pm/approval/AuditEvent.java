package pm.approval;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * One audit-log entry before it is chained (approval-model.md §7). Never holds a secret value or
 * a full argv (data-classification.md): only names, counts, the program name and the decision.
 *
 * @param kind entry kind, such as {@code approval} or {@code lock}
 * @param requestId the request, if any
 * @param requesterKind requester kind name, if any
 * @param osUser the OS user the broker verified, if any
 * @param project project title, if any
 * @param profile profile name, if any
 * @param varCount number of variables named, or -1 for none
 * @param decision decision name, if any
 * @param argv0 program name only, if any
 */
public record AuditEvent(String kind, Optional<UUID> requestId, Optional<String> requesterKind,
        Optional<String> osUser, Optional<String> project, Optional<String> profile, int varCount,
        Optional<String> decision, Optional<String> argv0) {

    public AuditEvent {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(requestId, "requestId");
        Objects.requireNonNull(requesterKind, "requesterKind");
        Objects.requireNonNull(osUser, "osUser");
        Objects.requireNonNull(project, "project");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(decision, "decision");
        Objects.requireNonNull(argv0, "argv0");
    }

    /** An entry with only a kind, such as {@code lock}. */
    public static AuditEvent of(String kind) {
        return new AuditEvent(kind, Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), -1, Optional.empty(), Optional.empty());
    }

    /** An {@code approval} entry for {@code request}. */
    static AuditEvent approval(ApprovalRequest request, String osUser, Decision decision) {
        ApprovalRequest.Scope scope = request.scope();
        return new AuditEvent("approval", Optional.of(request.requestId()),
                Optional.of(request.requester().kind().name()), Optional.of(osUser),
                Optional.of(scope.project()), Optional.of(scope.profile()),
                scope.vars().map(java.util.Set::size).orElse(-1), Optional.of(decision.name()),
                request.argv0().isEmpty() ? Optional.empty() : Optional.of(request.argv0()));
    }

    /** An entry for a request that could not be attributed (bad token or malformed). */
    static AuditEvent rejected(Decision decision) {
        return new AuditEvent("approval", Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.empty(), -1, Optional.of(decision.name()), Optional.empty());
    }
}
