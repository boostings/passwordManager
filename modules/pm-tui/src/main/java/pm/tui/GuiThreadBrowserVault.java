package pm.tui;

import com.googlecode.lanterna.gui2.TextGUIThread;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import pm.approval.ApprovalRequest;
import pm.approval.Decision;
import pm.approval.Grant;
import pm.browser.bridge.Origin;
import pm.browser.bridge.VaultPort;
import pm.browser.host.HostException;
import pm.crypto.Csprng;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.vault.VaultException;
import pm.vault.record.LoginRecord;
import pm.vault.record.VaultRecord;

/**
 * The bridge's {@link VaultPort} over the TUI's open session (ADR 0014 §8). Relay threads call it;
 * the session belongs to the GUI thread, so every access runs there through
 * {@code invokeAndWait}, as {@link GuiThreadReleaser} does for {@code env run}. A password is
 * copied out only under an unused {@code AUTOFILL} grant from the browser extension, which the
 * copy consumes; a saved login is stored and written to disk before the call returns.
 */
final class GuiThreadBrowserVault implements VaultPort {
    /** A port with no session: every call refuses as locked. */
    static final VaultPort LOCKED = new VaultPort() {
        @Override
        public List<Login> logins() {
            return List.of();
        }

        @Override
        public SecretBytes password(Grant grant, UUID entry) throws HostException {
            throw HostException.denied(Decision.DENIED_LOCKED);
        }

        @Override
        public UUID save(Grant grant, Origin origin, String username, SecretChars password) throws HostException {
            throw HostException.denied(Decision.DENIED_LOCKED);
        }
    };

    private final TextGUIThread guiThread;
    private final Supplier<Optional<Session>> session;
    private final Clock clock;
    private final Runnable onSaved;

    /**
     * @param session the open session, empty while locked; read on the GUI thread only
     * @param onSaved runs on the GUI thread after a login was saved (refreshes the dashboard)
     */
    GuiThreadBrowserVault(TextGUIThread guiThread, Supplier<Optional<Session>> session, Clock clock,
            Runnable onSaved) {
        this.guiThread = Objects.requireNonNull(guiThread, "guiThread");
        this.session = Objects.requireNonNull(session, "session");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.onSaved = Objects.requireNonNull(onSaved, "onSaved");
    }

    /** A step run on the GUI thread against the open session. */
    @FunctionalInterface
    private interface Step<T> {
        T run(Session open) throws HostException;
    }

    @Override
    public List<Login> logins() {
        try {
            return onGui(open -> open.records().stream()
                    .filter(LoginRecord.class::isInstance)
                    .map(LoginRecord.class::cast)
                    .map(l -> new Login(l.id(), l.title(), l.username(), l.urls()))
                    .toList());
        } catch (HostException locked) {
            return List.of();
        }
    }

    @Override
    public SecretBytes password(Grant grant, UUID entry) throws HostException {
        requireBrowserGrant(grant);
        return onGui(open -> {
            LoginRecord login = find(open.records(), entry);
            grant.consume();
            return login.password().apply(SecretBytes::copyOf);
        });
    }

    @Override
    public UUID save(Grant grant, Origin origin, String username, SecretChars password) throws HostException {
        requireBrowserGrant(grant);
        return onGui(open -> {
            grant.consume();
            Instant now = clock.instant();
            LoginRecord login;
            SecretBytes bytes = password.toUtf8();
            try {
                login = new LoginRecord(Csprng.uuid(), origin.host(), username, bytes, List.of(origin.text()), "",
                        List.of(), now, now, now);
            } catch (IllegalArgumentException e) {
                bytes.close();
                throw new HostException(HostException.Code.BAD_FIELD);
            }
            try {
                open.put(login);
            } catch (RuntimeException e) {
                login.close();
                throw new HostException(HostException.Code.INTERNAL);
            }
            try {
                open.save();
            } catch (VaultException e) {
                open.remove(login.id());
                login.close();
                throw new HostException(HostException.Code.INTERNAL); // not saved, so nothing is released
            }
            onSaved.run();
            return login.id();
        });
    }

    private static LoginRecord find(List<VaultRecord> records, UUID entry) throws HostException {
        for (VaultRecord r : records) {
            // Class.cast, not a pattern binding: PMD CloseResource reports AutoCloseable bindings.
            if (r instanceof LoginRecord && r.id().equals(entry)) {
                return LoginRecord.class.cast(r);
            }
        }
        throw new HostException(HostException.Code.NOT_FOUND);
    }

    /** Only a grant the broker issued for the browser extension, not yet used, may open the vault. */
    private static void requireBrowserGrant(Grant grant) throws HostException {
        ApprovalRequest r = grant.request();
        if (grant.isUsed() || r.operation() != ApprovalRequest.Operation.AUTOFILL
                || r.requester().kind() != ApprovalRequest.Kind.EXTENSION) {
            throw new HostException(HostException.Code.INTERNAL);
        }
    }

    @SuppressWarnings("PMD.DoNotUseThreads") // CE-065: re-asserting the interrupt flag is not thread creation
    private <T> T onGui(Step<T> step) throws HostException {
        AtomicReference<T> out = new AtomicReference<>();
        AtomicReference<HostException> refused = new AtomicReference<>();
        AtomicReference<RuntimeException> failure = new AtomicReference<>();
        Runnable task = () -> {
            try {
                Optional<Session> open = session.get();
                if (open.isEmpty() || open.get().isLocked()) {
                    throw HostException.denied(Decision.DENIED_LOCKED);
                }
                out.set(step.run(open.get()));
            } catch (HostException e) {
                refused.set(e);
            } catch (RuntimeException e) { // never let a failure end the GUI thread's loop
                failure.set(e);
            }
        };
        try {
            guiThread.invokeAndWait(task);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HostException(HostException.Code.INTERNAL);
        }
        if (refused.get() != null) {
            throw refused.get();
        }
        if (failure.get() != null) {
            throw new HostException(HostException.Code.INTERNAL);
        }
        return out.get();
    }
}
