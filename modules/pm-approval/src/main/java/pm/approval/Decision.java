package pm.approval;

/** Every outcome of the decision table (approval-model.md §2, §3). */
public enum Decision {
    /** Row 1: the vault is locked; no prompt. */
    DENIED_LOCKED,
    /** Row 2: wrong session token; no prompt, audited. */
    DENIED_AUTH,
    /** Row 3: the request id was seen before, or the request is stale. */
    DENIED_REPLAY,
    /** Row 4: the request failed validation or was too large. */
    DENIED_MALFORMED,
    /** Row 8: five prompts are already waiting. */
    DENIED_BUSY,
    /** The user did not answer within the prompt timeout (SR-111). */
    DENIED_TIMEOUT,
    /** The user said no. */
    DENIED,
    /** The user approved this request only. */
    ALLOWED_ONCE,
    /** Row 6: covered by a policy that lasts until the vault locks. */
    ALLOWED_SESSION,
    /** Row 7: covered by an unexpired temporary policy. */
    ALLOWED_POLICY;

    /** True for the three approvals. */
    public boolean allowed() {
        return this == ALLOWED_ONCE || this == ALLOWED_SESSION || this == ALLOWED_POLICY;
    }
}
