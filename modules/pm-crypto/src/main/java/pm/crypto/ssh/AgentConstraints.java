package pm.crypto.ssh;

import java.time.Duration;
import java.util.Objects;

/**
 * Constraints on an added identity (draft-miller-ssh-agent §3.2.6): a lifetime after which the
 * agent deletes the key, and whether the agent must ask for confirmation before each use.
 *
 * @param lifetime {@link Duration#ZERO} for no lifetime, otherwise whole seconds from 1 s to
 *     {@value #MAX_LIFETIME_SECONDS} s (see {@link #MAX_LIFETIME_SECONDS})
 * @param confirm whether the agent asks before every signature ({@code ssh-add -c})
 */
public record AgentConstraints(Duration lifetime, boolean confirm) {
    /** No constraints: the identity is added with {@code SSH_AGENTC_ADD_IDENTITY}. */
    public static final AgentConstraints NONE = new AgentConstraints(Duration.ZERO, false);
    /**
     * Largest lifetime accepted, 2^31 - 1 s (about 68 years). The wire field is a {@code uint32},
     * but OpenSSH's {@code ssh-agent} (10.3) fails its {@code poll} with EINVAL and exits, losing
     * every identity, for a lifetime of 2^31 s or more; {@code ssh-add -t} itself stops at
     * {@code INT_MAX} seconds.
     */
    public static final long MAX_LIFETIME_SECONDS = Integer.MAX_VALUE;
    static final int CONSTRAIN_LIFETIME = 1;
    static final int CONSTRAIN_CONFIRM = 2;

    /**
     * Validates the lifetime.
     *
     * @throws IllegalArgumentException if it is negative, has a fractional second or exceeds the maximum
     */
    public AgentConstraints {
        Objects.requireNonNull(lifetime, "lifetime");
        if (lifetime.isNegative() || lifetime.toNanosPart() != 0 || lifetime.toSeconds() > MAX_LIFETIME_SECONDS) {
            throw new IllegalArgumentException("BAD_LIFETIME");
        }
    }

    /** Whether there is nothing to constrain. */
    public boolean isNone() {
        return lifetime.isZero() && !confirm;
    }

    /** Appends the constraint list to an add-identity message. */
    void write(WireWriter w) {
        if (!lifetime.isZero()) {
            w.u8(CONSTRAIN_LIFETIME);
            w.u32(lifetime.toSeconds());
        }
        if (confirm) {
            w.u8(CONSTRAIN_CONFIRM);
        }
    }
}
