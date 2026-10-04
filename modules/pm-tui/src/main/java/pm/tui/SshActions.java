package pm.tui;

import java.time.Duration;
import java.util.concurrent.Executor;
import pm.crypto.SecretBytes;

/**
 * ssh-agent actions the TUI offers on an SSH key item (plan.md §13 M4.4, ADR 0013). The TUI passes
 * only a copy of the item's private key text, which it owns and closes after the call; parsing the private key and talking to the agent happen behind this port in
 * {@code pm.cli}, the one module allowed to use {@code pm.crypto.ssh} (SR-060). No key byte, agent
 * reply or exception text crosses back: only an {@link Outcome}, which the TUI turns into a
 * catalogue message (SR-501).
 *
 * <p>Agent calls can block (a stalled agent is cut off by the client's deadline), so the TUI runs
 * them on {@link #executor()}, never on the GUI thread: lock and Ctrl+X keep working meanwhile.
 */
public interface SshActions {

    /** What happened; each maps to one fixed message. */
    enum Outcome {
        /** The key is now in the agent. */
        ADDED,
        /** The key was removed from the agent. */
        REMOVED,
        /** The agent does not hold this key. */
        NOT_IN_AGENT,
        /** {@code SSH_AUTH_SOCK} is unset or nothing listens there. */
        NO_AGENT,
        /** The agent socket failed its owner, permission or link checks; nothing was sent. */
        UNSAFE_SOCKET,
        /** The agent refused the key or sent an invalid reply. */
        AGENT_FAILED,
        /** The agent did not answer in time; the connection was dropped. */
        AGENT_TIMEOUT,
        /** The stored key is not a usable unencrypted Ed25519 or ECDSA P-256 key. */
        BAD_KEY,
        /** The audit log could not be written, so the key was not released. */
        AUDIT_FAILED,
        /** SSH actions are not available in this build of the UI. */
        UNAVAILABLE
    }

    /**
     * Adds the key whose OpenSSH text is {@code privateKey} to the agent, with an optional lifetime
     * ({@link Duration#ZERO} for none) and confirmation. The caller keeps ownership of the text.
     */
    Outcome add(SecretBytes privateKey, Duration lifetime, boolean confirm);

    /** Removes the identity of the key whose OpenSSH text is {@code privateKey} from the agent. */
    Outcome remove(SecretBytes privateKey);

    /** Where the TUI runs {@link #add} and {@link #remove}: off the GUI thread. Runs inline by default. */
    default Executor executor() {
        return Runnable::run;
    }

    /** A port that offers nothing, for UIs started without the CLI (tests, the plain constructor). */
    static SshActions none() {
        return new SshActions() {
            @Override
            public Outcome add(SecretBytes privateKey, Duration lifetime, boolean confirm) {
                return Outcome.UNAVAILABLE;
            }

            @Override
            public Outcome remove(SecretBytes privateKey) {
                return Outcome.UNAVAILABLE;
            }
        };
    }
}
