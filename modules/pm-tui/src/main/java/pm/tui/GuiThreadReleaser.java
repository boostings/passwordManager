package pm.tui;

import com.googlecode.lanterna.gui2.TextGUIThread;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.SortedMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import pm.approval.Grant;
import pm.approval.ipc.Releaser;
import pm.approval.run.EnvRelease;
import pm.crypto.SecretBytes;
import pm.vault.record.VaultRecord;

/**
 * Releases approved variables from the TUI's session. Broker threads call {@link #release}; the
 * session belongs to the GUI thread, so the copy is made there through {@code invokeAndWait}.
 * Nothing thrown by the copy reaches the GUI thread, which would end the UI loop.
 */
final class GuiThreadReleaser implements Releaser {
    private final TextGUIThread guiThread;
    private final Supplier<Optional<List<VaultRecord>>> records;

    /** @param records the open session's records, empty while locked; read on the GUI thread only */
    GuiThreadReleaser(TextGUIThread guiThread, Supplier<Optional<List<VaultRecord>>> records) {
        this.guiThread = Objects.requireNonNull(guiThread, "guiThread");
        this.records = Objects.requireNonNull(records, "records");
    }

    @Override
    @SuppressWarnings("PMD.DoNotUseThreads") // CE-002: re-asserting the interrupt flag is not thread creation
    public SortedMap<String, SecretBytes> release(Grant grant) {
        AtomicReference<SortedMap<String, SecretBytes>> out = new AtomicReference<>();
        AtomicReference<RuntimeException> failure = new AtomicReference<>();
        Runnable copy = () -> {
            try {
                List<VaultRecord> open = records.get().orElseThrow(() -> new IllegalStateException("LOCKED"));
                out.set(EnvRelease.release(grant, open));
            } catch (RuntimeException e) {
                failure.set(e);
            }
        };
        try {
            guiThread.invokeAndWait(copy);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("INTERRUPTED", e);
        }
        if (failure.get() != null) {
            throw new IllegalStateException("NOT_RELEASED", failure.get()); // the server denies
        }
        return Objects.requireNonNull(out.get(), "released");
    }
}
