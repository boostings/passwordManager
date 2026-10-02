package pm.cli;

import java.io.IOException;
import pm.tui.VaultPort;

/**
 * Starts the terminal UI over a vault port (plan.md §13 M1, SR-504); a seam so {@code tui} can be
 * tested without a real terminal.
 */
@FunctionalInterface
interface TuiLauncher {

    /** Runs the UI until the user quits. */
    void launch(VaultPort port) throws IOException;
}
