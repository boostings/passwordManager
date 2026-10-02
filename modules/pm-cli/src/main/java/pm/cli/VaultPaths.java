package pm.cli;

import java.io.File;
import java.nio.file.Files;
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
    private static final String HOME_SHORTHAND = "~";
    private static final String CURRENT_DIR = ".";
    private static final String PARENT_DIR = "..";
    private static final String SEPARATOR = "/";

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
     * {@code ..} removed (IDS01-J). The value must name a file: a trailing separator, a last element
     * of {@code .} or {@code ..}, or an existing directory is refused.
     *
     * <p>A leading {@code ~} is refused rather than expanded. The shell expands {@code ~} only when
     * it is unquoted, so a {@code ~} that reaches us was quoted or came from a script; expanding
     * only {@code ~/} would be a partial imitation of the shell ({@code ~user} has no portable
     * meaning in Java), and resolving it relative to the working directory, as before, silently
     * creates a directory literally named {@code ~}. A file whose name starts with {@code ~} can
     * still be named as {@code ./~name}.
     */
    static Path fromArgument(String raw) throws UsageException {
        if (raw.isBlank()) {
            throw new UsageException(Messages.EMPTY_VAULT_PATH);
        }
        if (Cli.hasUnsafeChars(raw)) {
            throw new UsageException(Messages.INVALID_VAULT_PATH);
        }
        if (raw.startsWith(HOME_SHORTHAND)) {
            throw new UsageException(Messages.VAULT_PATH_TILDE);
        }
        if (raw.endsWith(SEPARATOR) || raw.endsWith(File.separator)) {
            throw new UsageException(Messages.VAULT_PATH_NOT_FILE);
        }
        Path given = toPath(raw, Messages.INVALID_VAULT_PATH);
        Path lastElement = given.getFileName();
        if (lastElement == null) {
            throw new UsageException(Messages.INVALID_VAULT_PATH);
        }
        String last = lastElement.toString();
        if (CURRENT_DIR.equals(last) || PARENT_DIR.equals(last)) {
            throw new UsageException(Messages.VAULT_PATH_NOT_FILE);
        }
        Path path = given.toAbsolutePath().normalize();
        if (path.getFileName() == null || Files.isDirectory(path)) {
            throw new UsageException(Messages.VAULT_PATH_NOT_FILE);
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
