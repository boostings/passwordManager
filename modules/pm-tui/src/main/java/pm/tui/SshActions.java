package pm.tui;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executor;
import pm.crypto.SecretBytes;
import pm.vault.record.SshKeyRecord;

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

    /** Why a key file did not become an item. */
    enum ImportProblem {
        /** The file is missing, not a regular file, a link, too large or not readable. */
        UNREADABLE,
        /** The key is protected by a passphrase. */
        ENCRYPTED,
        /** The file is not an unencrypted Ed25519 or ECDSA P-256 OpenSSH private key. */
        UNSUPPORTED,
        /** Importing is not available in this build of the UI. */
        UNAVAILABLE
    }

    /**
     * What importing a key file gave: the new item (owned by the caller), or the problem.
     *
     * @param key the item, present exactly when {@code problem} is empty
     * @param problem why there is no item
     * @param sharedFile whether group or others can read the key file
     */
    record Imported(Optional<SshKeyRecord> key, Optional<ImportProblem> problem, boolean sharedFile) {
        /** Checks that exactly one of {@code key} and {@code problem} is present. */
        public Imported {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(problem, "problem");
            if (key.isPresent() == problem.isPresent()) {
                throw new IllegalArgumentException("exactly one of key and problem");
            }
        }

        /** No item, because of {@code problem}. */
        public static Imported failed(ImportProblem problem) {
            return new Imported(Optional.empty(), Optional.of(problem), false);
        }
    }

    /**
     * Reads the OpenSSH private key file at {@code path} ({@code ~/} is the home folder) into a new
     * SSH key item titled {@code title}, or the key's comment when the title is empty. Nothing is
     * stored; the caller adds the item to the vault.
     */
    default Imported importKey(String path, String title) {
        return Imported.failed(ImportProblem.UNAVAILABLE);
    }

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
