package pm.approval.run;

import java.util.List;
import java.util.Objects;
import java.util.SortedMap;
import java.util.TreeMap;
import pm.approval.ApprovalRequest;
import pm.approval.Grant;
import pm.crypto.SecretBytes;
import pm.domain.env.ProjectEnv;
import pm.vault.record.ProjectRecord;
import pm.vault.record.VaultRecord;

/**
 * Turns an approved {@code env-inject} grant into copies of the variables it covers, read from the
 * unlocked vault's records. The copies belong to the caller (the broker server closes them once
 * sent); the records keep their own values.
 */
public final class EnvRelease {
    private EnvRelease() {
    }

    /**
     * Consumes {@code grant} and copies its variables.
     *
     * @throws IllegalArgumentException {@code NOT_ENV_INJECT}, {@code NO_SUCH_PROJECT} or
     *     {@code NO_SUCH_VARIABLE}; the broker server turns any exception into a denial
     * @throws IllegalStateException {@code GRANT_USED} if the grant was already used
     */
    public static SortedMap<String, SecretBytes> release(Grant grant, List<VaultRecord> records) {
        Objects.requireNonNull(grant, "grant");
        Objects.requireNonNull(records, "records");
        ApprovalRequest q = grant.request();
        if (q.operation() != ApprovalRequest.Operation.ENV_INJECT) {
            throw new IllegalArgumentException("NOT_ENV_INJECT");
        }
        grant.consume();
        ProjectRecord project = ProjectEnv.byTitle(records, q.scope().project())
                .orElseThrow(() -> new IllegalArgumentException("NO_SUCH_PROJECT"));
        return copy(ProjectEnv.variables(project, q.scope().profile()), q.scope());
    }

    /**
     * Copies the variables of {@code profile} that {@code scope} names (all of them for a
     * whole-profile scope).
     *
     * @throws IllegalArgumentException {@code NO_SUCH_VARIABLE} if a named variable is missing
     */
    public static SortedMap<String, SecretBytes> copy(SortedMap<String, SecretBytes> profile,
            ApprovalRequest.Scope scope) {
        java.util.SortedSet<String> names = scope.vars().orElse(new java.util.TreeSet<>(profile.keySet()));
        if (!profile.keySet().containsAll(names)) {
            throw new IllegalArgumentException("NO_SUCH_VARIABLE"); // checked before anything is copied
        }
        SortedMap<String, SecretBytes> out = new TreeMap<>();
        names.forEach(name -> out.put(name, profile.get(name).apply(SecretBytes::copyOf)));
        return out;
    }
}
