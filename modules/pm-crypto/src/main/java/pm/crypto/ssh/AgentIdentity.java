package pm.crypto.ssh;

import java.util.Objects;
import pm.crypto.ConstantTime;

/**
 * One identity an agent listed: its public key blob and comment. Holds no private material. The
 * comment comes from the agent, so control characters are replaced with {@code '?'} before it is
 * exposed (it may be printed to a terminal).
 */
public final class AgentIdentity {
    private final byte[] blob;
    private final String typeName;
    private final String commentText;

    AgentIdentity(byte[] blob, String type, String comment) {
        this.blob = blob.clone();
        this.typeName = type;
        this.commentText = comment;
    }

    /** A copy of the public key blob, as {@link SshAgentClient#remove(byte[])} takes it. */
    public byte[] publicKeyBlob() {
        return blob.clone();
    }

    /** The algorithm name at the start of the blob, for example {@code ssh-ed25519}. */
    public String type() {
        return typeName;
    }

    /** The comment, with control characters replaced. */
    public String comment() {
        return commentText;
    }

    /** The {@code SHA256:} fingerprint, as {@code ssh-add -l} prints it. */
    public String fingerprint() {
        return SshKey.fingerprint(blob);
    }

    /** Whether this is the agent's copy of {@code key}. */
    public boolean matches(SshKey key) {
        return ConstantTime.equals(blob, Objects.requireNonNull(key, "key").publicKeyBlob());
    }

    @Override
    public String toString() {
        return "AgentIdentity[" + typeName + " " + fingerprint() + "]";
    }
}
