package pm.cli;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import pm.crypto.SecretBytes;
import pm.crypto.ssh.AgentConstraints;
import pm.crypto.ssh.SshAgentClient;
import pm.crypto.ssh.SshException;
import pm.crypto.ssh.SshKey;
import pm.tui.SshActions;

/**
 * The TUI's {@link SshActions}, implemented in {@code pm.cli} so that only this module touches
 * {@code pm.crypto.ssh} (SR-060, ADR 0013). Same rules as {@code pm ssh add/remove}: the agent
 * socket comes from {@code SSH_AUTH_SOCK} and is checked by the client, every agent call has the
 * client's deadline, and an add is audited (requester {@code TUI}) before the key is sent. Calls
 * run on one daemon thread of their own, so the TUI's GUI thread never waits on the agent.
 */
@SuppressWarnings("PMD.DoNotUseThreads") // CE-046: one daemon worker keeps agent I/O off the GUI thread
final class CliSshActions implements SshActions {
    private static final String THREAD_NAME = "pm-ssh-agent";

    private final SshCommands ssh;
    private final Path vaultPath;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, THREAD_NAME);
        t.setDaemon(true); // a call still waiting on the agent never keeps the JVM alive
        return t;
    });

    CliSshActions(SshCommands ssh, Path vaultPath) {
        this.ssh = Objects.requireNonNull(ssh, "ssh");
        this.vaultPath = Objects.requireNonNull(vaultPath, "vaultPath");
    }

    @Override
    public Outcome add(SecretBytes privateKey, Duration lifetime, boolean confirm) {
        AgentConstraints constraints;
        try {
            constraints = new AgentConstraints(lifetime, confirm);
        } catch (IllegalArgumentException e) {
            return Outcome.AGENT_FAILED;
        }
        try (SshAgentClient agent = ssh.connect(); SshKey key = SshKey.parse(privateKey)) {
            ssh.release(vaultPath, "TUI", SshCommands.AUDIT_TARGET_AGENT, key.fingerprint(),
                    () -> agent.add(key, constraints));
            return Outcome.ADDED;
        } catch (SshException e) {
            return outcome(e.code());
        } catch (UsageException e) {
            return Outcome.AUDIT_FAILED; // the only usage failure here: the audit log could not be written
        }
    }

    @Override
    public Outcome remove(SecretBytes privateKey) {
        try (SshAgentClient agent = ssh.connect(); SshKey key = SshKey.parse(privateKey)) {
            agent.remove(key);
            return Outcome.REMOVED;
        } catch (SshException e) {
            return e.code() == SshException.Code.AGENT_REFUSED ? Outcome.NOT_IN_AGENT : outcome(e.code());
        }
    }

    @Override
    public Executor executor() {
        return worker;
    }

    /** The UI outcome for an SSH failure code. */
    static Outcome outcome(SshException.Code code) {
        return switch (code) {
            case MALFORMED_KEY, ENCRYPTED_KEY, UNSUPPORTED_KEY -> Outcome.BAD_KEY;
            case NO_AGENT -> Outcome.NO_AGENT;
            case UNSAFE_SOCKET -> Outcome.UNSAFE_SOCKET;
            case TIMEOUT -> Outcome.AGENT_TIMEOUT;
            case AGENT_REFUSED, BAD_REPLY, IO, TARGET_EXISTS, UNSAFE_TARGET -> Outcome.AGENT_FAILED;
        };
    }
}
