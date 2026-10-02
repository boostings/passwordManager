package pm.cli;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Objects;
import java.util.function.UnaryOperator;

/**
 * Resolves the vault path: the {@code --vault} argument after normalisation and validation
 * (IDS01-J), or a per-OS default built from the {@code os.name} and {@code user.home} system
 * properties. The environment is never read (ENV02-J).
 */
final class VaultPaths {
    static final String OS_NAME = "os.name";
    static final String USER_HOME = "user.home";

    private static final String MAC_PREFIX = "mac";
    private static final String DARWIN_PREFIX = "darwin";
    private static final String WINDOWS_PREFIX = "windows";
    private static final String APP_DIR = "pm";
    private static final String VAULT_FILE = "vault.pmv";

    private VaultPaths() {
    }

    /**
     * Default vault file: macOS {@code ~/Library/Application Support/pm/vault.pmv}, Windows
     * {@code ~\AppData\Roaming\pm\vault.pmv}, otherwise {@code ~/.local/share/pm/vault.pmv}.
     *
     * @param properties system-property lookup, injectable for tests
     */
    static Path defaultPath(UnaryOperator<String> properties) throws UsageException {
        String home = properties.apply(USER_HOME);
        if (home == null || home.isBlank()) {
            throw new UsageException(Messages.NO_HOME_DIR);
        }
        String os = Objects.requireNonNullElse(properties.apply(OS_NAME), "").toLowerCase(Locale.ROOT);
        Path base = toPath(home, Messages.NO_HOME_DIR);
        Path dataDir;
        if (os.startsWith(MAC_PREFIX) || os.startsWith(DARWIN_PREFIX)) {
            dataDir = base.resolve("Library").resolve("Application Support");
        } else if (os.startsWith(WINDOWS_PREFIX)) {
            dataDir = base.resolve("AppData").resolve("Roaming");
        } else {
            dataDir = base.resolve(".local").resolve("share");
        }
        return dataDir.resolve(APP_DIR).resolve(VAULT_FILE).toAbsolutePath().normalize();
    }

    /**
     * Validates a {@code --vault} value and returns its canonical form: absolute, with {@code .} and
     * {@code ..} removed (IDS01-J). The result must still name a file.
     */
    static Path fromArgument(String raw) throws UsageException {
        if (raw.isBlank()) {
            throw new UsageException(Messages.EMPTY_VAULT_PATH);
        }
        if (Cli.hasControlChars(raw)) {
            throw new UsageException(Messages.INVALID_VAULT_PATH);
        }
        Path path = toPath(raw, Messages.INVALID_VAULT_PATH).toAbsolutePath().normalize();
        if (path.getFileName() == null) {
            throw new UsageException(Messages.INVALID_VAULT_PATH);
        }
        return path;
    }

    private static Path toPath(String value, Messages onError) throws UsageException {
        try {
            return Path.of(value);
        } catch (InvalidPathException e) {
            throw new UsageException(onError);
        }
    }
}
