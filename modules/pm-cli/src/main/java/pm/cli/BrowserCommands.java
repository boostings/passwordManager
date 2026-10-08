package pm.cli;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.StringJoiner;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
import pm.browser.host.ExtensionAllowlist;
import pm.browser.host.HostException;
import pm.browser.host.Json;
import pm.browser.host.JsonText;
import pm.browser.host.NativeFrames;
import pm.crypto.ConstantTime;
import pm.crypto.Csprng;
import pm.domain.env.Env;

/**
 * {@code pm browser install | uninstall | status} (ADR 0014 §8, SR-114): registers pm as the
 * Chromium native messaging host {@value #HOST_NAME} for the current user.
 *
 * <pre>
 * pm browser install [--browser chrome|chromium|edge|brave|all] [--extension-id &lt;id&gt;]
 * pm browser uninstall [--browser ...] [--extension-id &lt;id&gt;]
 * pm browser status [--browser ...]
 * </pre>
 *
 * <p>The manifest ({@code <browser dir>/NativeMessagingHosts/pm.browser.json}) names the pm
 * launcher by absolute path and allows exactly one origin, {@code chrome-extension://<id>/}. The
 * same ID goes into the allowlist next to the default vault ({@link ExtensionAllowlist#FILE_NAME}),
 * which the host checks itself: the allowlist stays the one list of allowed extensions, and the
 * manifest is only the browser's own first gate.
 *
 * <p>Every write is atomic (owner-only temporary file, flushed, renamed over the target). A
 * folder or file that is a symbolic link, owned by another user or writable by group or others is
 * refused and left alone, and so is a manifest under pm's host name that pm did not write.
 * Install checks everything first and adds the ID to the allowlist only once at least one
 * manifest for it is pm's; installing twice changes nothing. Uninstall removes only pm's own
 * manifests ({@code --extension-id}: only that extension's, and that ID from the allowlist) and
 * clears the allowlist once no pm manifest is left. Status also lists the allowlisted IDs. The
 * launcher must be one only the user and root can change ({@link #safeLauncher}); a source
 * checkout's {@code scripts/pm} is never registered. On Windows the host is registered in the
 * registry, which pm never writes: the command prints the manual steps instead and exits
 * {@link ExitCodes#NOT_DONE}.
 */
final class BrowserCommands {
    /** The native messaging host name the extension connects to. */
    static final String HOST_NAME = "pm.browser";
    /** The manifest's description, part of what marks a manifest as pm's. */
    static final String DESCRIPTION = "pm password manager native messaging host";
    static final String MANIFEST_FILE = HOST_NAME + ".json";
    static final String HOSTS_DIR = "NativeMessagingHosts";
    static final String BROWSER = "--browser";
    static final String EXTENSION_ID = "--extension-id";
    static final String ALL = "all";

    private static final String STDIO = "stdio";
    private static final String ORIGIN_PREFIX = "chrome-extension://";
    private static final Pattern ORIGIN = Pattern.compile("chrome-extension://[a-p]{32}/");
    private static final Set<String> MANIFEST_MEMBERS = Set.of("name", "description", "path", "type", "allowed_origins");
    /** Largest manifest read back; pm's own is well under 1 KiB. */
    private static final int MAX_MANIFEST_BYTES = 16 * 1024;
    private static final Set<PosixFilePermission> OWNER_FILE = PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> OWNER_DIR = PosixFilePermissions.fromString("rwx------");
    private static final String JPACKAGE_APP_PATH = "jpackage.app-path";
    private static final String USER_NAME = "user.name";
    private static final Pattern SLASH = Pattern.compile("/");
    /** The release archive's module folder ({@code <home>/app}, docs/release/packaging.md). */
    private static final String RELEASE_APP_DIR = "app";
    /** A development checkout's launcher, relative to the checkout: runs Gradle on every start. */
    private static final Path CHECKOUT_LAUNCHER = Path.of("scripts", "pm");
    private static final int ONE = 1;
    /** {@code S_ISVTX}: in a folder with it, only a file's owner may rename or delete the file. */
    private static final int STICKY = 0x200; // the sticky bit, octal 01000

    /** Where a Chromium-family browser keeps its per-user data, per platform. */
    enum Browser {
        CHROME("chrome", "Google/Chrome", "google-chrome", "Google\\Chrome"),
        CHROMIUM("chromium", "Chromium", "chromium", "Chromium"),
        EDGE("edge", "Microsoft Edge", "microsoft-edge", "Microsoft\\Edge"),
        BRAVE("brave", "BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser", "BraveSoftware\\Brave-Browser");

        private final String name;
        private final String mac;
        private final String linux;
        private final String registry;

        Browser(String name, String mac, String linux, String registry) {
            this.name = name;
            this.mac = mac;
            this.linux = linux;
            this.registry = registry;
        }

        String label() {
            return name;
        }

        /** The browser's user data folder under {@code home}, with no {@code XDG_CONFIG_HOME}. */
        Path root(Os os, Path home) {
            return root(os, home, Optional.empty());
        }

        /**
         * The browser's user data folder: on macOS under {@code ~/Library/Application Support}, on
         * Linux under {@code config} ({@code XDG_CONFIG_HOME}, which Chromium honours, when set to
         * an absolute path) or else {@code ~/.config}.
         */
        Path root(Os os, Path home, Optional<Path> config) {
            Path base = os == Os.MAC ? home.resolve("Library").resolve("Application Support")
                    : config.orElse(home.resolve(".config"));
            for (String part : SLASH.split(os == Os.MAC ? mac : linux, -1)) {
                base = base.resolve(part);
            }
            return base;
        }

        /** The registry key Chrome reads on Windows (written by hand, never by pm). */
        String registryKey() {
            return "HKEY_CURRENT_USER\\Software\\" + registry + "\\NativeMessagingHosts\\" + HOST_NAME;
        }
    }

    /** Operating system family. */
    enum Os { MAC, LINUX, WINDOWS }

    /**
     * Where pm runs.
     *
     * @param config {@code XDG_CONFIG_HOME} if set to an absolute path (Linux browser folders)
     * @param user the OS user whose folders and files are trusted (their owner)
     * @param launcher the program the browser should start, if pm can tell
     * @param checkout whether pm runs from a source checkout, whose {@code scripts/pm} starts Gradle
     *     on every launch and so is never registered
     */
    record Platform(Os os, Path home, Optional<Path> config, String user, Optional<Path> launcher, boolean checkout) {
        Platform {
            Objects.requireNonNull(os, "os");
            Objects.requireNonNull(home, "home");
            Objects.requireNonNull(config, "config");
            Objects.requireNonNull(user, "user");
            Objects.requireNonNull(launcher, "launcher");
        }

        /** An installed pm with no {@code XDG_CONFIG_HOME}. */
        Platform(Os os, Path home, String user, Optional<Path> launcher) {
            this(os, home, Optional.empty(), user, launcher, false);
        }

        /**
         * The running system: the launcher is the jpackage executable or {@code bin/pm} of the
         * release archive, worked out from where the {@code pm.cli} module was loaded; a development
         * checkout is recognised and has none.
         */
        static Platform system(UnaryOperator<String> properties, Env env) throws UsageException {
            String home = properties.apply(VaultPaths.USER_HOME);
            String user = properties.apply(USER_NAME);
            if (home == null || home.isBlank() || user == null || user.isBlank()) {
                throw new UsageException(Messages.NO_HOME_DIR);
            }
            String name = Objects.requireNonNullElse(properties.apply(VaultPaths.OS_NAME), "").toLowerCase(Locale.ROOT);
            Os os = name.startsWith("mac") || name.startsWith("darwin") ? Os.MAC
                    : name.startsWith("windows") ? Os.WINDOWS : Os.LINUX;
            Optional<Path> found = launcher(properties);
            boolean checkout = found.isPresent() && found.get().endsWith(CHECKOUT_LAUNCHER);
            return new Platform(os, Path.of(home), env.path(Env.Var.XDG_CONFIG_HOME), user,
                    checkout ? Optional.empty() : found, checkout);
        }

        private static Optional<Path> launcher(UnaryOperator<String> properties) {
            String app = properties.apply(JPACKAGE_APP_PATH);
            if (app != null && !app.isBlank()) {
                return Optional.of(Path.of(app));
            }
            Optional<URI> location = ModuleLayer.boot().configuration().findModule("pm.cli")
                    .flatMap(m -> m.reference().location());
            if (location.isEmpty() || !"file".equals(location.get().getScheme())) {
                return Optional.empty();
            }
            Path dir = Path.of(location.get()).getParent();
            if (dir == null || dir.getParent() == null) {
                return Optional.empty();
            }
            Path parent = dir.getParent();
            if (RELEASE_APP_DIR.equals(String.valueOf(dir.getFileName()))) {
                return Optional.of(parent.resolve("bin").resolve("pm")); // release archive
            }
            Path dev = FileSystems.getDefault().getPath("modules", "pm-cli", "build", "modules");
            if (dir.endsWith(dev)) {
                Path root = dir;
                for (int i = 0; i < dev.getNameCount() && root != null; i++) {
                    root = root.getParent();
                }
                return Optional.ofNullable(root).map(r -> r.resolve(CHECKOUT_LAUNCHER)); // checkout: refused
            }
            return Optional.empty();
        }
    }

    /** What a browser's manifest slot holds. */
    enum State { INSTALLED, MISSING, FOREIGN, STALE, UNSAFE, NO_BROWSER }

    private enum Safety { SAFE, ABSENT, UNSAFE }

    private final Platform platform;
    private final Path vaultDir;

    BrowserCommands(Platform platform, Path vaultDir) {
        this.platform = Objects.requireNonNull(platform, "platform");
        this.vaultDir = Objects.requireNonNull(vaultDir, "vaultDir");
    }

    /** Runs {@code pm browser} with the arguments after the group word. */
    int run(List<String> sub, ConsoleIo io) throws UsageException {
        if (sub.isEmpty()) {
            throw new UsageException(Messages.WRONG_ARG_COUNT);
        }
        List<String> rest = sub.subList(1, sub.size());
        return switch (sub.get(0)) {
            case "install" -> {
                CommandArgs args = CommandArgs.parse(rest, Set.of(), Set.of(BROWSER, EXTENSION_ID)).arity(0);
                yield install(browsers(args), args.value(EXTENSION_ID), io);
            }
            case "uninstall" -> {
                CommandArgs args = CommandArgs.parse(rest, Set.of(), Set.of(BROWSER, EXTENSION_ID)).arity(0);
                yield uninstall(browsers(args), args.value(EXTENSION_ID), io);
            }
            case "status" -> status(browsers(CommandArgs.parse(rest, Set.of(), Set.of(BROWSER)).arity(0)), io);
            default -> throw new UsageException(Messages.UNKNOWN_COMMAND);
        };
    }

    /** The browsers named by {@code --browser}; empty means every supported one ({@code all}). */
    private static List<Browser> browsers(CommandArgs args) throws UsageException {
        String chosen = args.value(BROWSER).orElse(ALL);
        if (ALL.equals(chosen)) {
            return List.of();
        }
        for (Browser b : Browser.values()) {
            if (b.label().equals(chosen)) {
                return List.of(b);
            }
        }
        throw new UsageException(Messages.BRIDGE_UNKNOWN_BROWSER);
    }

    // ---- install -----------------------------------------------------------------------------

    private int install(List<Browser> named, Optional<String> givenId, ConsoleIo io) throws UsageException {
        if (givenId.isPresent() && !ExtensionAllowlist.isValidId(givenId.get())) {
            throw new UsageException(Messages.BRIDGE_BAD_EXTENSION_ID);
        }
        if (platform.os() == Os.WINDOWS) {
            return windowsSteps(named, givenId, io);
        }
        Safety dir = check(vaultDir, true);
        if (dir != Safety.SAFE) {
            io.err().println((dir == Safety.ABSENT ? Messages.BRIDGE_NO_VAULT : Messages.BRIDGE_UNSAFE_ALLOWLIST).text());
            return ExitCodes.NOT_DONE;
        }
        Path allowFile = vaultDir.resolve(ExtensionAllowlist.FILE_NAME);
        Optional<ExtensionAllowlist> current = readAllowlist(allowFile);
        if (current.isEmpty()) {
            io.err().println(Messages.BRIDGE_UNSAFE_ALLOWLIST.text());
            return ExitCodes.NOT_DONE;
        }
        String id = givenId.orElse(null);
        if (id == null) {
            List<String> ids = current.get().ids();
            if (ids.size() != ONE) {
                throw new UsageException(Messages.BRIDGE_NEED_EXTENSION_ID);
            }
            id = ids.get(0);
        }
        if (platform.checkout()) {
            io.err().println(Messages.BRIDGE_CHECKOUT_LAUNCHER.text());
            return ExitCodes.NOT_DONE;
        }
        Optional<Path> launcher = platform.launcher().flatMap(l -> safeLauncher(l, platform.user()));
        if (launcher.isEmpty()) {
            io.err().println(Messages.BRIDGE_NO_LAUNCHER.text());
            return ExitCodes.NOT_DONE;
        }
        // Every check runs before anything is written: the allowlist text, then each browser's slot.
        ExtensionAllowlist next = current.get().with(id);
        String allowText;
        try {
            allowText = next.fileText();
        } catch (IllegalArgumentException e) {
            io.err().println(Messages.BRIDGE_ALLOWLIST_FULL.text());
            return ExitCodes.NOT_DONE;
        }
        List<Browser> targets = new ArrayList<>();
        boolean allDone = true;
        boolean blocked = false;
        for (Browser b : named.isEmpty() ? List.of(Browser.values()) : named) {
            State slot = state(b, Optional.empty());
            if (slot == State.NO_BROWSER) {
                if (!named.isEmpty()) {
                    io.out().println(b.label() + Messages.BRIDGE_STATUS_NO_BROWSER.text());
                    allDone = false;
                }
            } else if (slot == State.FOREIGN || slot == State.UNSAFE) {
                report(io, b, slot); // left alone
                allDone = false;
                blocked = true;
            } else {
                targets.add(b);
            }
        }
        if (targets.isEmpty()) {
            io.err().println((blocked ? Messages.BRIDGE_NOTHING_INSTALLABLE : Messages.BRIDGE_NO_BROWSER).text());
            return ExitCodes.NOT_DONE;
        }
        // Each browser's manifest is its own record: installing adds this ID to it and nothing else.
        boolean any = false;
        for (Browser b : targets) {
            boolean done = installOne(b, manifest(launcher.get(), idsAfterInstall(b, next, id)), io);
            any |= done;
            allDone &= done;
        }
        // The allowlist changes only once at least one manifest is pm's for this extension.
        if (!any) {
            io.err().println(Messages.BRIDGE_NOTHING_INSTALLABLE.text());
            return ExitCodes.NOT_DONE;
        }
        if (!writeAllowlist(current.get(), id, allowText, allowFile, io)) {
            return ExitCodes.NOT_DONE;
        }
        io.out().println(Messages.BRIDGE_RESTART.text());
        return allDone ? ExitCodes.OK : ExitCodes.NOT_DONE;
    }

    private static boolean writeAllowlist(ExtensionAllowlist current, String id, String text, Path allowFile,
            ConsoleIo io) {
        if (current.allows(id)) {
            io.out().println(Messages.BRIDGE_ALLOWLIST_HAS.text() + id);
            return true;
        }
        try {
            writeAtomically(allowFile, text.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            io.err().println(Messages.BRIDGE_ALLOWLIST_NOT_WRITTEN.text()); // the manifests are already written
            return false;
        }
        io.out().println(Messages.BRIDGE_ALLOWLIST_ADDED.text() + id);
        return true;
    }

    /** {@code b}'s user data folder on this platform. */
    private Path root(Browser b) {
        return b.root(platform.os(), platform.home(), platform.config());
    }

    private boolean installOne(Browser b, byte[] manifest, ConsoleIo io) {
        Path root = root(b);
        Path hosts = root.resolve(HOSTS_DIR);
        Path file = hosts.resolve(MANIFEST_FILE);
        try {
            if (check(root, true) != Safety.SAFE || !safeAncestors(root)) {
                return report(io, b, State.UNSAFE);
            }
            Safety dir = check(hosts, true);
            if (dir == Safety.UNSAFE) {
                return report(io, b, State.UNSAFE);
            }
            if (dir == Safety.ABSENT) {
                Files.createDirectory(hosts, PosixFilePermissions.asFileAttribute(OWNER_DIR));
                Files.setPosixFilePermissions(hosts, OWNER_DIR);
            }
            Safety existing = check(file, false);
            if (existing == Safety.UNSAFE) {
                return report(io, b, State.UNSAFE);
            }
            if (existing == Safety.SAFE) {
                Optional<byte[]> old = readSmall(file);
                if (old.isEmpty() || !isOurs(old.get())) {
                    return report(io, b, State.FOREIGN);
                }
                // SR-016: byte arrays are compared with ConstantTime everywhere outside pm.crypto.
                if (ConstantTime.equals(manifest, old.get())) {
                    io.out().println(b.label() + Messages.BRIDGE_ALREADY.text());
                    return true;
                }
            }
            writeAtomically(file, manifest);
            io.out().println(b.label() + Messages.BRIDGE_INSTALLED.text());
            return true;
        } catch (IOException | UnsupportedOperationException e) {
            io.out().println(b.label() + Messages.BRIDGE_FAILED.text());
            return false;
        }
    }

    // ---- uninstall and status ----------------------------------------------------------------

    /**
     * Removes pm's manifests, or with {@code --extension-id} takes that extension off them (a
     * manifest is removed once it allows no other extension), and then updates the allowlist: an ID
     * that no manifest of pm's allows any more is taken off it, and once no browser holds a
     * manifest of pm's, it is cleared.
     */
    private int uninstall(List<Browser> named, Optional<String> id, ConsoleIo io) throws UsageException {
        if (id.isPresent() && !ExtensionAllowlist.isValidId(id.get())) {
            throw new UsageException(Messages.BRIDGE_BAD_EXTENSION_ID);
        }
        if (platform.os() == Os.WINDOWS) {
            io.err().println(Messages.BRIDGE_WINDOWS_NO_REGISTRY.text());
            return ExitCodes.NOT_DONE;
        }
        boolean clean = true;
        for (Browser b : named.isEmpty() ? List.of(Browser.values()) : named) {
            State state = state(b, Optional.empty());
            Path file = root(b).resolve(HOSTS_DIR).resolve(MANIFEST_FILE);
            List<String> ids = state == State.INSTALLED ? manifestIds(file) : List.of();
            if (state == State.INSTALLED && id.isPresent() && !ids.contains(id.get())) {
                state = State.MISSING; // pm's manifest for other extensions only: kept
            }
            switch (state) {
                case INSTALLED, STALE -> {
                    List<String> rest = new ArrayList<>(ids);
                    id.ifPresent(gone -> rest.removeIf(gone::equals)); // every copy, should one be repeated
                    try {
                        if (id.isPresent() && !rest.isEmpty()) {
                            writeAtomically(file, manifest(manifestPath(readSmall(file).orElseThrow()), rest));
                            io.out().println(b.label() + Messages.BRIDGE_ORIGIN_REMOVED.text());
                        } else {
                            Files.delete(file);
                            io.out().println(b.label() + Messages.BRIDGE_REMOVED.text());
                        }
                    } catch (IOException | NoSuchElementException e) {
                        io.out().println(b.label() + Messages.BRIDGE_FAILED.text());
                        clean = false;
                    }
                }
                case MISSING -> io.out().println(b.label() + Messages.BRIDGE_NOTHING_TO_REMOVE.text());
                case NO_BROWSER -> {
                    if (!named.isEmpty()) {
                        io.out().println(b.label() + Messages.BRIDGE_STATUS_NO_BROWSER.text());
                    }
                }
                case FOREIGN, UNSAFE -> clean &= report(io, b, state);
            }
        }
        return shrinkAllowlist(io) && clean ? ExitCodes.OK : ExitCodes.NOT_DONE;
    }

    /**
     * What {@code b}'s manifest allows once {@code id} is installed there: the IDs its manifest of
     * pm's allows now that stay allowlisted ({@code next}), in their order, then {@code id} if it is
     * not among them. An ID installed for another browser, or taken off this one, is never added.
     */
    private List<String> idsAfterInstall(Browser b, ExtensionAllowlist next, String id) {
        List<String> ids = new ArrayList<>();
        if (state(b, Optional.empty()) == State.INSTALLED) {
            manifestIds(root(b).resolve(HOSTS_DIR).resolve(MANIFEST_FILE)).stream()
                    .filter(next::allows).distinct().forEach(ids::add);
        }
        if (!ids.contains(id)) {
            ids.add(id);
        }
        return ids;
    }

    /**
     * The allowlist after an uninstall: the IDs that a manifest of pm's still allows, so it stays the
     * union of what the browsers' manifests allow; false if it had to change but could not be
     * written.
     */
    private boolean shrinkAllowlist(ConsoleIo io) {
        Safety dir = check(vaultDir, true);
        if (dir == Safety.ABSENT) {
            return true; // no vault, no allowlist
        }
        Path file = vaultDir.resolve(ExtensionAllowlist.FILE_NAME);
        Optional<ExtensionAllowlist> current = dir == Safety.SAFE ? readAllowlist(file) : Optional.empty();
        if (current.isEmpty()) {
            io.err().println(Messages.BRIDGE_UNSAFE_ALLOWLIST.text());
            return false;
        }
        // An ID stays allowlisted while a manifest of pm's still allows it (another browser's).
        List<String> stillAllowed = allowedByManifests();
        List<State> states = Arrays.stream(Browser.values()).map(b -> state(b, Optional.empty())).toList();
        boolean anyLeft = states.contains(State.INSTALLED);
        // A manifest pm cannot read may still be pm's: clearing locks it out too, but say so.
        boolean unread = states.contains(State.FOREIGN) || states.contains(State.UNSAFE);
        ExtensionAllowlist next = ExtensionAllowlist.of(current.get().ids().stream()
                .filter(stillAllowed::contains).toList());
        if (!anyLeft) {
            next = ExtensionAllowlist.of(List.of());
        }
        if (next.ids().equals(current.get().ids())) {
            return true;
        }
        try {
            writeAtomically(file, next.fileText().getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            io.err().println(Messages.BRIDGE_ALLOWLIST_NOT_WRITTEN.text());
            return false;
        }
        for (String gone : current.get().ids()) {
            if (!next.allows(gone)) {
                io.out().println(Messages.BRIDGE_ALLOWLIST_REMOVED.text() + gone);
            }
        }
        if (!anyLeft) {
            io.out().println((unread ? Messages.BRIDGE_ALLOWLIST_CLEARED_UNREAD : Messages.BRIDGE_ALLOWLIST_CLEARED).text());
        }
        return true;
    }

    private int status(List<Browser> named, ConsoleIo io) {
        if (platform.os() == Os.WINDOWS) {
            io.err().println(Messages.BRIDGE_WINDOWS_NO_REGISTRY.text());
            return ExitCodes.NOT_DONE;
        }
        Optional<Path> launcher = platform.launcher().flatMap(l -> safeLauncher(l, platform.user()));
        Safety dir = check(vaultDir, true);
        Optional<ExtensionAllowlist> allowed = dir == Safety.ABSENT ? Optional.of(ExtensionAllowlist.of(List.of()))
                : dir == Safety.SAFE ? readAllowlist(vaultDir.resolve(ExtensionAllowlist.FILE_NAME)) : Optional.empty();
        for (Browser b : named.isEmpty() ? List.of(Browser.values()) : named) {
            State state = state(b, launcher);
            if (state == State.INSTALLED && !originsAllowed(b, allowed)) {
                state = State.STALE;
            }
            report(io, b, state);
            if (state == State.INSTALLED || state == State.STALE) { // exactly what the browser will allow
                manifestIds(root(b).resolve(HOSTS_DIR).resolve(MANIFEST_FILE))
                        .forEach(i -> io.out().println(Messages.BRIDGE_STATUS_ALLOWS.text() + i));
            }
        }
        if (allowed.isEmpty()) {
            io.out().println(Messages.BRIDGE_ALLOWLIST_UNREADABLE.text());
        } else if (allowed.get().ids().isEmpty()) {
            io.out().println(Messages.BRIDGE_ALLOWLIST_EMPTY.text());
        } else {
            List<String> inManifests = allowedByManifests();
            allowed.get().ids().forEach(i -> io.out().println(Messages.BRIDGE_ALLOWLIST_LISTED.text() + i
                    + (inManifests.contains(i) ? "" : Messages.BRIDGE_ALLOWLIST_NO_MANIFEST.text())));
        }
        return ExitCodes.OK;
    }

    /** Every extension ID that a manifest of pm's, in any browser, allows. */
    private List<String> allowedByManifests() {
        List<String> ids = new ArrayList<>();
        for (Browser b : Browser.values()) {
            if (state(b, Optional.empty()) == State.INSTALLED) {
                ids.addAll(manifestIds(root(b).resolve(HOSTS_DIR).resolve(MANIFEST_FILE)));
            }
        }
        return ids;
    }

    /** Prints {@code state} for {@code b}; true for the states that need nothing done. */
    private static boolean report(ConsoleIo io, Browser b, State state) {
        Messages m = switch (state) {
            case INSTALLED -> Messages.BRIDGE_STATUS_INSTALLED;
            case MISSING -> Messages.BRIDGE_STATUS_MISSING;
            case FOREIGN -> Messages.BRIDGE_STATUS_FOREIGN;
            case STALE -> Messages.BRIDGE_STATUS_STALE;
            case UNSAFE -> Messages.BRIDGE_STATUS_UNSAFE;
            case NO_BROWSER -> Messages.BRIDGE_STATUS_NO_BROWSER;
        };
        io.out().println(b.label() + m.text());
        return state == State.INSTALLED || state == State.MISSING;
    }

    /**
     * What {@code b}'s manifest slot holds. With {@code launcher} given, pm's manifest naming any
     * other program is {@link State#STALE}; without, any manifest of pm's counts as installed.
     */
    State state(Browser b, Optional<Path> launcher) {
        Path root = root(b);
        if (!Files.isDirectory(root)) {
            return State.NO_BROWSER;
        }
        Path hosts = root.resolve(HOSTS_DIR);
        Safety dir = check(hosts, true);
        if (check(root, true) != Safety.SAFE || dir == Safety.UNSAFE || !safeAncestors(root)) {
            return State.UNSAFE;
        }
        Path file = hosts.resolve(MANIFEST_FILE);
        Safety f = dir == Safety.ABSENT ? Safety.ABSENT : check(file, false);
        if (f == Safety.ABSENT) {
            return State.MISSING;
        }
        if (f == Safety.UNSAFE) {
            return State.UNSAFE;
        }
        Optional<byte[]> bytes = readSmall(file);
        if (bytes.isEmpty() || !isOurs(bytes.get())) {
            return State.FOREIGN;
        }
        if (launcher.isPresent() && !launcher.get().toString().equals(manifestPath(bytes.get()))) {
            return State.STALE;
        }
        return State.INSTALLED;
    }

    private boolean originsAllowed(Browser b, Optional<ExtensionAllowlist> allowed) {
        if (allowed.isEmpty()) {
            return false;
        }
        List<String> ids = manifestIds(root(b).resolve(HOSTS_DIR).resolve(MANIFEST_FILE));
        return !ids.isEmpty() && ids.stream().allMatch(allowed.get()::allows);
    }

    /** The extension IDs pm's manifest {@code file} allows; empty if it is not pm's or unreadable. */
    static List<String> manifestIds(Path file) {
        Optional<byte[]> bytes = readSmall(file);
        if (bytes.isEmpty() || !isOurs(bytes.get())) {
            return List.of();
        }
        Json parsed = parse(bytes.get());
        try {
            List<String> ids = new ArrayList<>();
            if (parsed instanceof Json.Obj o && o.get("allowed_origins") instanceof Json.Arr origins) {
                for (Json item : origins.items()) {
                    String text = ((Json.Str) item).text(); // isOurs: every item is an origin string
                    ids.add(text.substring(ORIGIN_PREFIX.length(), text.length() - 1));
                }
            }
            return ids;
        } finally {
            parsed.wipe();
        }
    }

    // ---- Windows: printed steps only ---------------------------------------------------------

    private int windowsSteps(List<Browser> named, Optional<String> id, ConsoleIo io) {
        io.out().println(Messages.BRIDGE_WINDOWS.text());
        for (Browser b : named.isEmpty() ? List.of(Browser.values()) : named) {
            io.out().println("  " + b.registryKey());
        }
        io.out().println(Messages.BRIDGE_WINDOWS_MANIFEST.text());
        String extension = id.orElse("<extension-id>");
        Path launcher = platform.launcher().orElse(Path.of("pm.exe"));
        io.out().print(new String(manifest(launcher, List.of(extension)), StandardCharsets.UTF_8));
        io.out().println(Messages.BRIDGE_WINDOWS_ALLOWLIST.text());
        io.out().println("  " + extension);
        return ExitCodes.NOT_DONE;
    }

    // ---- the manifest ------------------------------------------------------------------------

    /**
     * pm's manifest for {@code launcher} allowing the extensions {@code ids}, in that order: fixed
     * member order, UTF-8.
     */
    static byte[] manifest(Path launcher, List<String> ids) {
        return manifest(launcher.toString(), ids);
    }

    private static byte[] manifest(String launcher, List<String> ids) {
        StringJoiner origins = new StringJoiner(", ", "[", "]");
        ids.forEach(i -> origins.add(quote(ORIGIN_PREFIX + i + "/")));
        String text = "{\n"
                + "  \"name\": " + quote(HOST_NAME) + ",\n"
                + "  \"description\": " + quote(DESCRIPTION) + ",\n"
                + "  \"path\": " + quote(launcher) + ",\n"
                + "  \"type\": " + quote(STDIO) + ",\n"
                + "  \"allowed_origins\": " + origins + "\n"
                + "}\n";
        return text.getBytes(StandardCharsets.UTF_8);
    }

    /** A JSON string literal: quotes, backslashes and every control character escaped. */
    static String quote(String s) {
        StringBuilder out = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') {
                out.append('\\').append(c);
            } else if (c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0) || c == 0x2028 || c == 0x2029) {
                out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.append('"').toString();
    }

    /**
     * Whether {@code bytes} is a manifest pm wrote: exactly pm's five members, pm's name,
     * description and type, a string path and only extension origins.
     */
    static boolean isOurs(byte[] bytes) {
        Json parsed = parse(bytes);
        try {
            if (!(parsed instanceof Json.Obj o) || !o.names().equals(MANIFEST_MEMBERS)) {
                return false;
            }
            boolean fixed = o.get("name") instanceof Json.Str n && HOST_NAME.equals(n.text())
                    && o.get("description") instanceof Json.Str d && DESCRIPTION.equals(d.text())
                    && o.get("type") instanceof Json.Str t && STDIO.equals(t.text())
                    && o.get("path") instanceof Json.Str;
            return fixed && o.get("allowed_origins") instanceof Json.Arr origins && !origins.items().isEmpty()
                    && origins.items().stream().allMatch(i -> i instanceof Json.Str s && ORIGIN.matcher(s.text()).matches());
        } finally {
            parsed.wipe();
        }
    }

    private static String manifestPath(byte[] bytes) {
        Json parsed = parse(bytes);
        try {
            return parsed instanceof Json.Obj o && o.get("path") instanceof Json.Str p ? p.text() : "";
        } finally {
            parsed.wipe();
        }
    }

    /** {@code bytes} parsed as strict JSON; {@link Json.Null} for anything that is not. */
    private static Json parse(byte[] bytes) {
        char[] text = null;
        try {
            text = NativeFrames.utf8(bytes);
            return JsonText.parse(text);
        } catch (HostException e) {
            return Json.Null.NULL;
        } finally {
            if (text != null) {
                Arrays.fill(text, '\0');
            }
        }
    }

    // ---- files -------------------------------------------------------------------------------

    private Optional<ExtensionAllowlist> readAllowlist(Path file) {
        Safety s = check(file, false);
        if (s == Safety.ABSENT) {
            return Optional.of(ExtensionAllowlist.of(List.of()));
        }
        if (s == Safety.UNSAFE) {
            return Optional.empty();
        }
        try {
            return Optional.of(ExtensionAllowlist.read(file));
        } catch (IOException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /**
     * Whether {@code path} is absent, or a directory ({@code dir}) or regular file that is no
     * link, belongs to {@link Platform#user()} and is not writable by group or others.
     */
    private Safety check(Path path, boolean dir) {
        PosixFileAttributes a;
        try {
            a = Files.readAttributes(path, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (NoSuchFileException e) {
            return Safety.ABSENT;
        } catch (IOException | UnsupportedOperationException e) {
            return Safety.UNSAFE;
        }
        boolean kind = dir ? a.isDirectory() : a.isRegularFile();
        boolean shared = a.permissions().contains(PosixFilePermission.GROUP_WRITE)
                || a.permissions().contains(PosixFilePermission.OTHERS_WRITE);
        return kind && !a.isSymbolicLink() && !shared && platform.user().equals(a.owner().getName())
                ? Safety.SAFE : Safety.UNSAFE;
    }

    /**
     * {@code launcher} resolved to a real path, if nobody but {@code user} and root can change what
     * it runs: a regular executable owned by {@code user} or root and not writable by group or
     * others, in folders that are each owned by {@code user} or root and not writable by group or
     * others, except a root-owned sticky folder such as {@code /tmp}, where only a file's owner may
     * replace it. (A folder writable by an admin group, such as macOS {@code /Applications}, is
     * refused: any member could swap the program the browser starts.)
     */
    static Optional<Path> safeLauncher(Path launcher, String user) {
        try {
            Path real = launcher.toRealPath();
            PosixFileAttributes a = Files.readAttributes(real, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!a.isRegularFile() || !Files.isExecutable(real) || !ownedByUserOrRoot(real, a, user) || shared(a)) {
                return Optional.empty();
            }
            return safeFolders(real.getParent(), Optional.empty(), user) ? Optional.of(real) : Optional.empty();
        } catch (IOException | UnsupportedOperationException | IllegalArgumentException | ClassCastException e) {
            return Optional.empty();
        }
    }

    /**
     * Whether nobody but the user and root can rename or replace the folders above {@code root},
     * {@code b}'s user data folder, and so swap the folder pm writes the manifest into: the same
     * rule as for the launcher's folders ({@link #safeFolders}), on the real path of {@code root}'s
     * parent, from there up to the user's home, or up to {@code /} if the folder is not inside the
     * home (an {@code XDG_CONFIG_HOME} elsewhere). A link among them is followed and the folder it
     * leads to is what counts; {@code root} itself, and what pm creates in it, must be no link
     * ({@link #check}).
     */
    private boolean safeAncestors(Path root) {
        try {
            Path parent = root.toRealPath().getParent();
            return parent != null && safeFolders(parent, Optional.of(platform.home().toRealPath()), platform.user());
        } catch (IOException | UnsupportedOperationException | ClassCastException e) {
            return false;
        }
    }

    /**
     * Whether {@code first} and each folder above it, up to and including {@code stop} (or up to
     * {@code /} when {@code stop} is absent or not above it), is a directory owned by {@code user}
     * or root and not writable by group or others, except a root-owned sticky folder such as
     * {@code /tmp}, where only an entry's owner may rename it. {@code first} is a real path.
     */
    private static boolean safeFolders(Path first, Optional<Path> stop, String user) throws IOException {
        for (Path dir = first; dir != null; dir = dir.getParent()) {
            PosixFileAttributes d = Files.readAttributes(dir, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            boolean stickyRoot = isRoot(dir) && (mode(dir) & STICKY) != 0;
            if (!d.isDirectory() || !ownedByUserOrRoot(dir, d, user) || (shared(d) && !stickyRoot)) {
                return false;
            }
            if (stop.isPresent() && stop.get().equals(dir)) {
                return true; // the user's home: what is above it is not the user's to secure
            }
        }
        return true;
    }

    private static boolean shared(PosixFileAttributes a) {
        return a.permissions().contains(PosixFilePermission.GROUP_WRITE)
                || a.permissions().contains(PosixFilePermission.OTHERS_WRITE);
    }

    private static boolean ownedByUserOrRoot(Path path, PosixFileAttributes a, String user) throws IOException {
        return user.equals(a.owner().getName()) || isRoot(path);
    }

    private static boolean isRoot(Path path) throws IOException {
        return ((Integer) Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS)) == 0;
    }

    private static int mode(Path path) throws IOException {
        return (Integer) Files.getAttribute(path, "unix:mode", LinkOption.NOFOLLOW_LINKS);
    }

    /** {@code file}'s bytes if it is at most {@link #MAX_MANIFEST_BYTES}; a link is not followed. */
    private static Optional<byte[]> readSmall(Path file) {
        try (FileChannel ch = FileChannel.open(file, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            ByteBuffer buf = ByteBuffer.allocate(MAX_MANIFEST_BYTES + 1);
            int read = 0;
            while (read >= 0 && buf.hasRemaining()) { // until end of file or one byte past the limit
                read = ch.read(buf);
            }
            return buf.position() > MAX_MANIFEST_BYTES ? Optional.empty()
                    : Optional.of(Arrays.copyOf(buf.array(), buf.position()));
        } catch (IOException | UnsupportedOperationException e) {
            return Optional.empty();
        }
    }

    /**
     * Writes {@code bytes} to {@code target} atomically: a new owner-only (0600) file next to it,
     * flushed to disk, then renamed over the target.
     */
    static void writeAtomically(Path target, byte[] bytes) throws IOException {
        Path dir = Objects.requireNonNull(target.getParent(), "target");
        Path tmp = dir.resolve("." + target.getFileName() + "." + Csprng.uuid() + ".tmp");
        FileAttribute<Set<PosixFilePermission>> owner = PosixFilePermissions.asFileAttribute(OWNER_FILE);
        try {
            try (FileChannel ch = FileChannel.open(tmp, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS), owner)) {
                ByteBuffer buf = ByteBuffer.wrap(bytes);
                while (buf.hasRemaining()) {
                    ch.write(buf);
                }
                ch.force(true);
            }
            Files.setPosixFilePermissions(tmp, OWNER_FILE);
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
