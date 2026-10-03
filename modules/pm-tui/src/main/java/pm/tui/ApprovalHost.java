package pm.tui;

import java.nio.file.Path;
import java.time.Clock;
import java.util.Optional;
import pm.approval.ApprovalBroker;
import pm.approval.ipc.Releaser;
import pm.domain.env.Env;

/**
 * Where the TUI's approval broker lives (ADR 0009). While the vault is unlocked the TUI shows the
 * broker's prompts and releases approved secrets from its session; on lock the broker's token and
 * session policies go too.
 */
public interface ApprovalHost extends AutoCloseable {
    /** The broker whose prompts the TUI shows, once one is running. */
    Optional<ApprovalBroker> broker();

    /** The vault unlocked: start or resume serving; approved secrets come from {@code releaser}. */
    void unlocked(Releaser releaser);

    /** The vault locked: the token is withdrawn, session policies end, waiting prompts are denied. */
    void locked();

    /** Stops serving for good. Idempotent. */
    @Override
    void close();

    /** No broker: {@code pm env run} falls back to unlocking the vault itself. */
    static ApprovalHost none() {
        return new ApprovalHost() {
            @Override
            public Optional<ApprovalBroker> broker() {
                return Optional.empty();
            }

            @Override
            public void unlocked(Releaser releaser) {
                // nothing to serve
            }

            @Override
            public void locked() {
                // nothing to withdraw
            }

            @Override
            public void close() {
                // nothing to stop
            }
        };
    }

    /**
     * A broker on the Unix domain socket in the run directory for {@code vaultDir}
     * (approval-model §5), auditing to the vault's {@code audit.log}. If the socket or the log
     * cannot be set up, the TUI works on without a broker.
     *
     * @param osUser the only OS user the broker serves
     */
    static ApprovalHost socket(Path vaultDir, Env env, Clock clock, String osUser) {
        return new SocketApprovalHost(vaultDir, env, clock, osUser);
    }
}
