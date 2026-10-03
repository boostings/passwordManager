package pm.tui;

import java.nio.file.Path;
import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import pm.approval.ApprovalBroker;
import pm.approval.AuditException;
import pm.approval.AuditLog;
import pm.approval.PolicyStore;
import pm.approval.ipc.BrokerServer;
import pm.approval.ipc.IpcException;
import pm.approval.ipc.Releaser;
import pm.approval.ipc.RunDir;
import pm.domain.env.Env;

/**
 * {@link ApprovalHost} over a {@link BrokerServer}. Started on the first unlock and kept until the
 * TUI exits; between lock and unlock the token file is absent, so clients see no broker. Every
 * audit entry goes through {@link AuditLog#append}, which shares the log safely with CLI commands.
 * Called on the GUI thread, except {@link #release} on broker threads.
 */
final class SocketApprovalHost implements ApprovalHost {
    private static final Releaser DENY_ALL = grant -> {
        throw new IllegalStateException("LOCKED");
    };

    private final Path vaultDir;
    private final Env env;
    private final Clock clock;
    private final String osUser;
    /** Read by broker threads, written on the GUI thread. */
    private final AtomicReference<Releaser> current = new AtomicReference<>(DENY_ALL);
    /** Set once if the socket or the log could not be set up; then no further attempt is made. */
    private final AtomicBoolean failed = new AtomicBoolean();
    // GUI-thread confined.
    private ApprovalBroker active;
    private BrokerServer server;

    SocketApprovalHost(Path vaultDir, Env env, Clock clock, String osUser) {
        this.vaultDir = Objects.requireNonNull(vaultDir, "vaultDir");
        this.env = Objects.requireNonNull(env, "env");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.osUser = Objects.requireNonNull(osUser, "osUser");
    }

    @Override
    public Optional<ApprovalBroker> broker() {
        return Optional.ofNullable(server == null ? null : active);
    }

    @Override
    public void unlocked(Releaser releaser) {
        current.set(Objects.requireNonNull(releaser, "releaser"));
        if (server == null && !failed.get()) {
            start();
        }
        if (server != null) {
            try {
                server.unlocked();
            } catch (IpcException e) {
                stop(); // no token file, no broker: env run falls back to the CLI path
            }
        }
    }

    @Override
    public void locked() {
        current.set(DENY_ALL);
        if (server != null) {
            try {
                server.locked();
            } catch (IpcException e) {
                stop(); // the token file could not be removed: stop serving altogether
            }
        }
    }

    @Override
    public void close() {
        current.set(DENY_ALL);
        stop();
    }

    private void start() {
        Path log = vaultDir.resolve(AuditLog.FILE_NAME);
        ApprovalBroker b = new ApprovalBroker(clock, event -> {
            try {
                AuditLog.append(log, clock, event);
            } catch (AuditException e) {
                throw new IllegalStateException("AUDIT_WRITE", e); // the broker fails the request closed
            }
        }, PolicyStore.inMemory(), osUser);
        try {
            AuditLog.check(log); // a damaged log is reported by refusing to serve, not by guessing
            server = BrokerServer.start(RunDir.prepare(RunDir.locate(env, vaultDir)), b, this::release);
            active = b;
        } catch (AuditException | IpcException e) {
            failed.set(true);
        }
    }

    private java.util.SortedMap<String, pm.crypto.SecretBytes> release(pm.approval.Grant grant) {
        return current.get().release(grant);
    }

    private void stop() {
        if (server != null) {
            server.close();
            server = null;
        }
        if (active != null) {
            active.lock();
            active = null;
        }
    }
}
