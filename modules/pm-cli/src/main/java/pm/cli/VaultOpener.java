package pm.cli;

import java.nio.file.Path;
import pm.tui.VaultPort;

/**
 * Builds the {@link VaultPort} for one invocation. {@code creating} is true only for {@code init}:
 * Argon2id parameters are tuned to the machine only when a vault is created, because unlock reads
 * them from the vault header (ADR 0007), so other commands skip the 500 ms benchmark.
 */
@FunctionalInterface
interface VaultOpener {

    /**
     * Opens the port for {@code vaultFile}.
     *
     * @param creating whether the command creates a new vault
     */
    VaultPort open(Path vaultFile, boolean creating);
}
