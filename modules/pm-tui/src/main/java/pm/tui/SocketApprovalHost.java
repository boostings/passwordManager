package pm.tui;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import pm.approval.ApprovalBroker;
import pm.approval.ApprovalRequest;
import pm.approval.AuditException;
import pm.approval.AuditEvent;
import pm.approval.AuditLog;
import pm.approval.PolicyStore;
import pm.approval.ipc.BrokerServer;
import pm.approval.ipc.IpcException;
import pm.approval.ipc.Releaser;
import pm.approval.ipc.RunDir;
import pm.browser.bridge.VaultPort;
import pm.domain.env.Env;
import pm.tui.lan.LanState;

/**
 * {@link ApprovalHost} over a {@link BrokerServer}. Started on the first unlock and kept until the
 * TUI exits; between lock and unlock the token file is absent, so clients see no broker. Every
 * audit entry goes through {@link AuditLog#append}, which shares the log safely with CLI commands.
 * For the default vault it also serves the {@link BrowserRelay} (ADR 0014 §8), whose requests reach
 * the same broker and, while unlocked, the session; if the relay cannot start (another pm window
 * serves the browser, or the socket cannot be set up), the broker still runs, the extension is
 * refused as if pm were closed, and {@link #browserNote} says why.
 * Called on the GUI thread, except {@link #release} and the relay's vault port on broker threads.
 */
final class SocketApprovalHost implements ApprovalHost {
    private static final Releaser DENY_ALL = grant -> {
        throw new IllegalStateException("LOCKED");
    };

    private final Path vaultDir;
    private final Optional<Path> vaultFile;
    private final boolean defaultVault;
    private final Env env;
    private final Clock clock;
    private final String osUser;
    private final BrowserRelay.Limits limits;
    private final String osName;
    /** Read by broker threads, written on the GUI thread. */
    private final AtomicReference<Releaser> current = new AtomicReference<>(DENY_ALL);
    /** Read by relay threads, written on the GUI thread. */
    private final AtomicReference<VaultPort> browserVault = new AtomicReference<>(GuiThreadBrowserVault.LOCKED);
    /** Set once if the socket or the log could not be set up; then no further attempt is made. */
    private final AtomicBoolean failed = new AtomicBoolean();
    // GUI-thread confined.
    private ApprovalBroker active;
    private BrokerServer server;
    private BrowserRelay relay;
    private Optional<String> note;
    /** The log's message for the last failed {@link #audit}; empty after a success or a plain I/O failure. */
    private Optional<String> lastAuditFailure = Optional.empty();

    SocketApprovalHost(Path vaultDir, Env env, Clock clock, String osUser, Optional<Path> vaultFile,
            boolean defaultVault) {
        this(vaultDir, env, clock, osUser, vaultFile, defaultVault, BrowserRelay.Limits.DEFAULT,
                System.getProperty("os.name", ""));
    }

    SocketApprovalHost(Path vaultDir, Env env, Clock clock, String osUser, Optional<Path> vaultFile,
            boolean defaultVault, BrowserRelay.Limits limits, String osName) {
        this.vaultDir = Objects.requireNonNull(vaultDir, "vaultDir");
        this.vaultFile = Objects.requireNonNull(vaultFile, "vaultFile");
        this.defaultVault = defaultVault && vaultFile.isPresent();
        this.env = Objects.requireNonNull(env, "env");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.osUser = Objects.requireNonNull(osUser, "osUser");
        this.limits = Objects.requireNonNull(limits, "limits");
        this.osName = Objects.requireNonNull(osName, "osName");
        this.note = this.defaultVault ? Optional.empty() : Optional.of(Messages.BROWSER_NOT_DEFAULT);
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
    public void browser(VaultPort vault) {
        browserVault.set(Objects.requireNonNull(vault, "vault"));
    }

    @Override
    public void locked() {
        current.set(DENY_ALL);
        browserVault.set(GuiThreadBrowserVault.LOCKED);
        if (server != null) {
            try {
                server.locked();
            } catch (IpcException e) {
                stop(); // the token file could not be removed: stop serving altogether
            }
        }
    }

    @Override
    public boolean audit(AuditEvent event) {
        try {
            AuditLog.append(vaultDir.resolve(AuditLog.FILE_NAME), clock, event);
            lastAuditFailure = Optional.empty();
            return true;
        } catch (AuditException e) {
            lastAuditFailure = Optional.of(e).filter(f -> f.code() != AuditException.Code.IO)
                    .map(AuditException::userMessage);
            return false;
        }
    }

    @Override
    public String auditFailure(String fallback) {
        return lastAuditFailure.orElse(fallback);
    }

    @Override
    public Optional<LanState> lanState() throws IOException {
        if (vaultFile.isEmpty()) {
            return Optional.empty();
        }
        try {
            return Optional.of(LanState.forVault(vaultFile.get(), RunDir.prepare(RunDir.locate(env, vaultDir)).path()));
        } catch (IpcException e) {
            throw new IOException("unsafe run directory", e);
        }
    }

    @Override
    public Optional<String> peer(ApprovalRequest request) {
        return relay == null ? Optional.empty() : relay.peerOf(request.requestId());
    }

    @Override
    public boolean stillAsked(ApprovalRequest request) {
        return relay == null || relay.stillAllowed(request.requestId());
    }

    @Override
    public Optional<String> browserNote() {
        return note;
    }

    @Override
    public void close() {
        current.set(DENY_ALL);
        browserVault.set(GuiThreadBrowserVault.LOCKED);
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
            if (defaultVault) { // no broker, no prompts: the relay cannot serve either
                note = Optional.of(e instanceof IpcException ipc && ipc.code() == IpcException.Code.IO
                        ? Messages.browserOff(BrowserRelay.Unavailable.IN_USE) : Messages.BROWSER_NO_APPROVALS);
            }
            return;
        }
        if (defaultVault) {
            try {
                relay = BrowserRelay.start(vaultFile.orElseThrow(), new BrowserRelay.Wiring(b, browserVault::get,
                        this::audit, clock, osUser, BrowserRelay.APPROVAL_WAIT, limits), osName);
                note = Optional.empty();
            } catch (BrowserRelay.NotStarted e) {
                relay = null; // the broker serves on; the extension is told pm is locked
                note = Optional.of(Messages.browserOff(e.reason()));
            }
        }
    }

    private java.util.SortedMap<String, pm.crypto.SecretBytes> release(pm.approval.Grant grant) {
        return current.get().release(grant);
    }

    private void stop() {
        if (relay != null) {
            relay.close();
            relay = null;
        }
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
