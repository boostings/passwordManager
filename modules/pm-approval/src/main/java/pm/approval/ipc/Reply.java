package pm.approval.ipc;

import java.util.Collections;
import java.util.Objects;
import java.util.SortedMap;
import java.util.TreeMap;
import pm.approval.Decision;
import pm.crypto.SecretBytes;

/**
 * The broker's answer to one request: the decision and, if allowed, the released variables. The
 * caller owns the values and closes the reply.
 *
 * @param decision the decision
 * @param vars released variables by name; empty unless allowed
 */
public record Reply(Decision decision, SortedMap<String, SecretBytes> vars) implements AutoCloseable {
    public Reply {
        Objects.requireNonNull(decision, "decision");
        vars = Collections.unmodifiableSortedMap(new TreeMap<>(vars));
        if (!decision.allowed() && !vars.isEmpty()) {
            throw new IllegalArgumentException("DENIED_WITH_VALUES");
        }
    }

    /** A denial. */
    static Reply denied(Decision decision) {
        return new Reply(decision, new TreeMap<>());
    }

    @Override
    public void close() {
        vars.values().forEach(SecretBytes::close);
    }
}
