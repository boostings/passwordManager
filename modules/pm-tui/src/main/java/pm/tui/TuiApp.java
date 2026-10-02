package pm.tui;

import com.googlecode.lanterna.terminal.Terminal;
import java.io.IOException;
import java.time.Duration;
import java.util.Objects;
import pm.vault.VaultService;

/**
 * Lanterna terminal UI: unlock, dashboard with search, record detail with masked secrets, and
 * idle auto-lock (plan.md §13 M1, SR-503, SR-504).
 */
@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)
public final class TuiApp {
    /** Default idle auto-lock timeout (SR-504). */
    public static final Duration DEFAULT_IDLE_LOCK = Duration.ofMinutes(5);

    /** §2 contract constructor; delegates through {@link VaultServiceAdapter}. */
    public TuiApp(VaultService service, Duration idleLock) {
        this(new VaultServiceAdapter(service), idleLock);
    }

    /** Port constructor, used by tests with an in-memory {@link VaultPort}. */
    public TuiApp(VaultPort port, Duration idleLock) {
        Objects.requireNonNull(port, "port");
        Objects.requireNonNull(idleLock, "idleLock");
    }

    /** Runs the UI on {@code terminal} until the user quits. */
    public void run(Terminal terminal) throws IOException {
        throw new UnsupportedOperationException("M1 stub");
    }
}
