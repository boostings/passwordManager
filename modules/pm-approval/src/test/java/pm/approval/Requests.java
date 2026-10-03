package pm.approval;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.UUID;
import pm.approval.ApprovalRequest.Display;
import pm.approval.ApprovalRequest.Effect;
import pm.approval.ApprovalRequest.Kind;
import pm.approval.ApprovalRequest.Operation;
import pm.approval.ApprovalRequest.Requester;
import pm.approval.ApprovalRequest.Scope;

/** Request builders for broker tests. */
final class Requests {
    static final List<String> ARGV = List.of("/usr/bin/env", "npm", "start");

    private Requests() {
    }

    static ApprovalRequest inject(Instant at, String project, String profile, String... vars) {
        Optional<SortedSet<String>> wanted = vars.length == 0 ? Optional.empty() : Optional.of(new TreeSet<>(List.of(vars)));
        return new ApprovalRequest(UUID.randomUUID(), new Requester(Kind.CLI, "pm env run"), Operation.ENV_INJECT,
                new Scope(project, profile, wanted, List.of()), Duration.ZERO,
                new Display(ARGV, Optional.empty(), Effect.INJECT), at);
    }

    static ApprovalRequest export(Instant at, String project) {
        return new ApprovalRequest(UUID.randomUUID(), new Requester(Kind.CLI, "pm env export"), Operation.EXPORT,
                Scope.profile(project, "default"), Duration.ZERO,
                new Display(List.of(), Optional.empty(), Effect.WRITE_FILE), at);
    }

    static ApprovalRequest sameIdAs(ApprovalRequest q) {
        return new ApprovalRequest(q.requestId(), q.requester(), q.operation(), q.scope(), q.duration(),
                q.display(), q.created());
    }
}
