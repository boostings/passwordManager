package pm.approval;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Permission to release the secrets of one approved request, exactly once. Whatever the user chose
 * (once, session or policy), each grant covers one request: a policy makes the next request
 * approve without a prompt, it never makes a grant reusable.
 */
public final class Grant {
    private final ApprovalRequest approved;
    private final Decision how;
    private final AtomicBoolean used = new AtomicBoolean();

    Grant(ApprovalRequest request, Decision decision) {
        this.approved = Objects.requireNonNull(request, "request");
        if (!decision.allowed()) {
            throw new IllegalArgumentException("NOT_ALLOWED");
        }
        this.how = decision;
    }

    /** The approved request. */
    public ApprovalRequest request() {
        return approved;
    }

    /** How it was approved. */
    public Decision decision() {
        return how;
    }

    /**
     * Marks the grant used.
     *
     * @throws IllegalStateException {@code GRANT_USED} on the second call
     */
    public void consume() {
        if (!used.compareAndSet(false, true)) {
            throw new IllegalStateException("GRANT_USED");
        }
    }

    /** True once {@link #consume()} has run. */
    public boolean isUsed() {
        return used.get();
    }
}
