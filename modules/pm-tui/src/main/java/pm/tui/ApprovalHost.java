package pm.tui;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import pm.approval.ApprovalBroker;
import pm.approval.AuditEvent;
import pm.approval.ipc.Releaser;
import pm.domain.env.Env;
import pm.tui.lan.LanState;

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

    /**
     * Appends {@code event} to the vault's audit log (LAN sharing in the TUI, M3.6). The caller
     * refuses the operation when this returns false (approval-model §7: no audit, no release).
     *
     * @return whether the entry was written; true when this host has no log to write to
     */
    default boolean audit(AuditEvent event) {
        return true;
    }

    /**
     * The LAN state every pm process of this vault must see: removed-device markers next to the
     * vault file and the pairing lockout in the run directory (M3.6, lan-share.md §8.1).
     *
     * @return the state; empty when this host knows no vault file (the TUI then keeps that state
     *     for its own process only)
     * @throws IOException a directory exists but is not safe to use, or cannot be created
     */
    default Optional<LanState> lanState() throws IOException {
        return Optional.empty();
    }

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
        return new SocketApprovalHost(vaultDir, env, clock, osUser, Optional.empty());
    }

    /**
     * As {@link #socket}, for the vault in {@code vaultFile}; this host also gives the TUI the LAN
     * state of that vault ({@link #lanState}).
     */
    static ApprovalHost socketFor(Path vaultFile, Env env, Clock clock, String osUser) {
        Path vaultDir = Objects.requireNonNull(vaultFile.toAbsolutePath().getParent(), "vault dir");
        return new SocketApprovalHost(vaultDir, env, clock, osUser, Optional.of(vaultFile));
    }
}
