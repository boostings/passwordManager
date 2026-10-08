package pm.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import pm.browser.host.ExtensionAllowlist;
import pm.domain.env.Env;

/**
 * ADR 0014 §8, SR-114: {@code pm browser install | uninstall | status} write exactly pm's
 * manifest, owner-only and atomically, keep the allowlist the one list of extensions, refuse
 * links, other owners, shared-writable folders and other programs' manifests, and never touch the
 * Windows registry. Every path is under a temporary home; the real browser folders are never used.
 */
@Tag("T-EXT-07")
class BrowserCommandsTest {
    private static final Instant NOW = Instant.parse("2026-10-04T12:00:00Z");
    private static final String ID = "abcdefghijklmnopabcdefghijklmnop";
    private static final String OTHER_ID = "ponmlkjihgfedcbaponmlkjihgfedcba";
    private static final String ME = System.getProperty("user.name");

    @TempDir
    Path home;
    private Path launcher;
    private Path vaultDir;

    @BeforeEach
    void setUp() throws IOException {
        launcher = Files.createDirectories(home.resolve("opt/pm/bin")).resolve("pm");
        Files.writeString(launcher, "#!/bin/sh\n", StandardCharsets.US_ASCII);
        Files.setPosixFilePermissions(launcher, PosixFilePermissions.fromString("rwx------"));
        vaultDir = home.resolve("Library/Application Support/pm");
        Files.createDirectories(vaultDir);
        Files.setPosixFilePermissions(vaultDir, PosixFilePermissions.fromString("rwx------"));
    }

    private Path root(BrowserCommands.Browser b, BrowserCommands.Os os) {
        return b.root(os, home);
    }

    private Path chrome() throws IOException {
        return Files.createDirectories(root(BrowserCommands.Browser.CHROME, BrowserCommands.Os.MAC));
    }

    private static Path manifestIn(Path root) {
        return root.resolve(BrowserCommands.HOSTS_DIR).resolve(BrowserCommands.MANIFEST_FILE);
    }

    private Path allowlist() {
        return vaultDir.resolve(ExtensionAllowlist.FILE_NAME);
    }

    private int run(FakeConsoleIo io, BrowserCommands.Os os, String user, String... args) {
        return run(io, new BrowserCommands.Platform(os, home, user, Optional.of(launcher)), args);
    }

    private int run(FakeConsoleIo io, BrowserCommands.Platform platform, String... args) {
        String osName = switch (platform.os()) {
            case MAC -> "Mac OS X";
            case LINUX -> "Linux";
            case WINDOWS -> "Windows 11";
        };
        Map<String, String> props = Map.of(VaultPaths.OS_NAME, osName, VaultPaths.USER_HOME, home.toString());
        return new Cli(props::get, Clock.fixed(NOW, ZoneOffset.UTC), p -> { })
                .withBrowserPlatform(p -> platform)
                .run(args, io, (path, creating) -> {
                    throw new AssertionError("pm browser must not open the vault");
                });
    }

    private int run(FakeConsoleIo io, String... args) {
        return run(io, BrowserCommands.Os.MAC, ME, args);
    }

    private String expectedManifest() throws IOException {
        return "{\n"
                + "  \"name\": \"pm.browser\",\n"
                + "  \"description\": \"pm password manager native messaging host\",\n"
                + "  \"path\": \"" + launcher.toRealPath() + "\",\n"
                + "  \"type\": \"stdio\",\n"
                + "  \"allowed_origins\": [\"chrome-extension://" + ID + "/\"]\n"
                + "}\n";
    }

    private static String perms(Path p) throws IOException {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(p));
    }

    private long filesUnder(Path dir) throws IOException {
        try (Stream<Path> s = Files.walk(dir)) {
            return s.filter(Files::isRegularFile).count();
        }
    }

    @Test
    void installWritesExactlyPmsManifestOwnerOnlyAndAllowlistsTheExtension() throws IOException {
        Path chrome = chrome();
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, "browser", "install", "--browser", "chrome", "--extension-id", ID), io::errText);
        Path manifest = manifestIn(chrome);
        assertEquals(expectedManifest(), Files.readString(manifest, StandardCharsets.UTF_8));
        assertEquals("rw-------", perms(manifest));
        assertEquals("rwx------", perms(manifest.getParent()));
        assertEquals(List.of(ID), ExtensionAllowlist.read(allowlist()).ids());
        assertEquals("rw-------", perms(allowlist()));
        assertTrue(io.outText().contains("chrome" + Messages.BRIDGE_INSTALLED.text()), io::outText);
        assertTrue(io.outText().contains(Messages.BRIDGE_ALLOWLIST_ADDED.text() + ID));
        try (Stream<Path> left = Files.list(manifest.getParent())) {
            assertEquals(1, left.count(), "no temporary file is left behind");
        }
    }

    @Test
    void installingTwiceChangesNothing() throws IOException {
        Path manifest = manifestIn(chrome());
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--extension-id", ID));
        byte[] first = Files.readAllBytes(manifest);
        var modified = Files.getLastModifiedTime(manifest);
        var allowModified = Files.getLastModifiedTime(allowlist());
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, "browser", "install"), io::errText); // the one allowlisted ID
        assertArrayEquals(first, Files.readAllBytes(manifest));
        assertEquals(modified, Files.getLastModifiedTime(manifest));
        assertEquals(allowModified, Files.getLastModifiedTime(allowlist()));
        assertTrue(io.outText().contains("chrome" + Messages.BRIDGE_ALREADY.text()), io::outText);
        assertTrue(io.outText().contains(Messages.BRIDGE_ALLOWLIST_HAS.text() + ID));
    }

    @Test
    void aBadExtensionIdIsAUsageErrorAndWritesNothing() throws IOException {
        chrome();
        for (String bad : List.of("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP", "abcdefghijklmnopabcdefghijklmno",
                "abcdefghijklmnopabcdefghijklmnoq", "abcdefghijklmnopabcdefghijklmnop/")) {
            FakeConsoleIo io = new FakeConsoleIo();
            assertEquals(ExitCodes.USAGE, run(io, "browser", "install", "--extension-id", bad), bad);
            assertTrue(io.errText().contains(Messages.BRIDGE_BAD_EXTENSION_ID.text()), io::errText);
        }
        assertEquals(0, filesUnder(home.resolve("Library")));
    }

    @Test
    void withoutAnIdTheAllowlistMustHoldExactlyOne() throws IOException {
        chrome();
        FakeConsoleIo none = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(none, "browser", "install"));
        assertTrue(none.errText().contains(Messages.BRIDGE_NEED_EXTENSION_ID.text()));
        Files.writeString(allowlist(), ID + "\n" + OTHER_ID + "\n", StandardCharsets.US_ASCII);
        Files.setPosixFilePermissions(allowlist(), PosixFilePermissions.fromString("rw-------"));
        FakeConsoleIo two = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(two, "browser", "install"));
        assertFalse(Files.exists(manifestIn(chrome())));
    }

    /**
     * m54b-005: installing B after A keeps A in the manifest (it lists every allowlisted extension),
     * status shows exactly what the manifest allows, and uninstalling A takes only A off the
     * manifest and the allowlist.
     */
    @Test
    void aSecondExtensionJoinsTheManifestAndUninstallingTheFirstKeepsTheSecond() throws IOException {
        Path manifest = manifestIn(chrome());
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--extension-id", ID));
        assertEquals(List.of(ID), BrowserCommands.manifestIds(manifest));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--extension-id", OTHER_ID));
        assertEquals(List.of(ID, OTHER_ID), ExtensionAllowlist.read(allowlist()).ids());
        assertEquals(List.of(ID, OTHER_ID), BrowserCommands.manifestIds(manifest), "A is not dropped");
        assertEquals(new String(BrowserCommands.manifest(launcher.toRealPath(), List.of(ID, OTHER_ID)),
                StandardCharsets.UTF_8), Files.readString(manifest));
        FakeConsoleIo both = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(both, "browser", "status", "--browser", "chrome"));
        assertEquals("chrome" + Messages.BRIDGE_STATUS_INSTALLED.text() + "\n"
                + Messages.BRIDGE_STATUS_ALLOWS.text() + ID + "\n"
                + Messages.BRIDGE_STATUS_ALLOWS.text() + OTHER_ID + "\n"
                + Messages.BRIDGE_ALLOWLIST_LISTED.text() + ID + "\n"
                + Messages.BRIDGE_ALLOWLIST_LISTED.text() + OTHER_ID + "\n", both.outText());

        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, "browser", "uninstall", "--extension-id", ID), io::errText);
        assertTrue(io.outText().contains("chrome" + Messages.BRIDGE_ORIGIN_REMOVED.text()), io::outText);
        assertTrue(io.outText().contains(Messages.BRIDGE_ALLOWLIST_REMOVED.text() + ID), io::outText);
        assertEquals(List.of(OTHER_ID), BrowserCommands.manifestIds(manifest), "only A is taken off");
        assertEquals(List.of(OTHER_ID), ExtensionAllowlist.read(allowlist()).ids());
        assertEquals("rw-------", perms(manifest));
        FakeConsoleIo after = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(after, "browser", "status", "--browser", "chrome"));
        assertEquals("chrome" + Messages.BRIDGE_STATUS_INSTALLED.text() + "\n"
                + Messages.BRIDGE_STATUS_ALLOWS.text() + OTHER_ID + "\n"
                + Messages.BRIDGE_ALLOWLIST_LISTED.text() + OTHER_ID + "\n", after.outText());
    }

    /**
     * m54c-001: each browser's manifest is its own record. Installing B in Chromium does not allow A
     * there (A was installed for Chrome only), and taking A off Chromium sticks: a later install of
     * C in Chromium does not bring A back. The allowlist stays the union of what the manifests allow.
     */
    @Test
    void eachBrowsersManifestAllowsOnlyWhatWasInstalledForIt() throws IOException {
        String third = "aaaabbbbccccddddeeeeffffgggghhhh";
        Path chrome = chrome();
        Path chromium = Files.createDirectories(root(BrowserCommands.Browser.CHROMIUM, BrowserCommands.Os.MAC));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--browser", "chrome",
                "--extension-id", ID));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--browser", "chromium",
                "--extension-id", OTHER_ID));
        assertEquals(List.of(OTHER_ID), BrowserCommands.manifestIds(manifestIn(chromium)), "A is not widened to Chromium");
        assertEquals(List.of(ID), BrowserCommands.manifestIds(manifestIn(chrome)), "B is not widened to Chrome");
        assertEquals(Set.of(ID, OTHER_ID), Set.copyOf(ExtensionAllowlist.read(allowlist()).ids()));

        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--browser", "chromium",
                "--extension-id", ID));
        assertEquals(List.of(OTHER_ID, ID), BrowserCommands.manifestIds(manifestIn(chromium)));
        FakeConsoleIo off = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(off, "browser", "uninstall", "--browser", "chromium", "--extension-id", ID));
        assertTrue(off.outText().contains("chromium" + Messages.BRIDGE_ORIGIN_REMOVED.text()), off::outText);
        assertEquals(List.of(OTHER_ID), BrowserCommands.manifestIds(manifestIn(chromium)));
        assertEquals(Set.of(ID, OTHER_ID), Set.copyOf(ExtensionAllowlist.read(allowlist()).ids()), "Chrome still allows A");

        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, "browser", "install", "--browser", "chromium", "--extension-id", third),
                io::errText);
        assertEquals(List.of(OTHER_ID, third), BrowserCommands.manifestIds(manifestIn(chromium)),
                "the removal of A from Chromium sticks");
        assertEquals(List.of(ID), BrowserCommands.manifestIds(manifestIn(chrome)), "Chrome is untouched");
        assertEquals(Set.of(ID, OTHER_ID, third), Set.copyOf(ExtensionAllowlist.read(allowlist()).ids()));
        FakeConsoleIo status = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(status, "browser", "status", "--browser", "chromium"));
        assertTrue(status.outText().startsWith("chromium" + Messages.BRIDGE_STATUS_INSTALLED.text() + "\n"
                + Messages.BRIDGE_STATUS_ALLOWS.text() + OTHER_ID + "\n"
                + Messages.BRIDGE_STATUS_ALLOWS.text() + third + "\n"
                + Messages.BRIDGE_ALLOWLIST_LISTED.text()), status::outText);
        assertFalse(status.outText().contains(Messages.BRIDGE_STATUS_ALLOWS.text() + ID), status::outText);

        // The browser-wide uninstall of Chromium takes off the allowlist what only Chromium allowed.
        FakeConsoleIo gone = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(gone, "browser", "uninstall", "--browser", "chromium"));
        assertTrue(gone.outText().contains(Messages.BRIDGE_ALLOWLIST_REMOVED.text() + OTHER_ID), gone::outText);
        assertTrue(gone.outText().contains(Messages.BRIDGE_ALLOWLIST_REMOVED.text() + third), gone::outText);
        assertEquals(List.of(ID), ExtensionAllowlist.read(allowlist()).ids());
        assertEquals(List.of(ID), BrowserCommands.manifestIds(manifestIn(chrome)));
    }

    /**
     * An extension stays allowlisted while another browser's manifest still allows it, and status
     * says when an allowlisted extension is in no manifest.
     */
    @Test
    void anExtensionStaysAllowlistedWhileAManifestAllowsIt() throws IOException {
        Path chrome = chrome();
        Path brave = Files.createDirectories(root(BrowserCommands.Browser.BRAVE, BrowserCommands.Os.MAC));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--extension-id", ID));
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, "browser", "uninstall", "--browser", "chrome", "--extension-id", ID));
        assertTrue(io.outText().contains("chrome" + Messages.BRIDGE_REMOVED.text()), io::outText);
        assertFalse(Files.exists(manifestIn(chrome)), "nothing left in it: removed");
        assertEquals(List.of(ID), BrowserCommands.manifestIds(manifestIn(brave)));
        assertEquals(List.of(ID), ExtensionAllowlist.read(allowlist()).ids(), "brave still allows it");
        assertFalse(io.outText().contains(Messages.BRIDGE_ALLOWLIST_REMOVED.text()), io::outText);

        Files.writeString(allowlist(), ID + "\n" + OTHER_ID + "\n", StandardCharsets.US_ASCII);
        FakeConsoleIo status = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(status, "browser", "status"));
        assertTrue(status.outText().contains(Messages.BRIDGE_ALLOWLIST_LISTED.text() + ID + "\n"), status::outText);
        assertTrue(status.outText().contains(Messages.BRIDGE_ALLOWLIST_LISTED.text() + OTHER_ID
                + Messages.BRIDGE_ALLOWLIST_NO_MANIFEST.text()), status::outText);
    }

    @Test
    void aLinkedManifestFolderIsRefused() throws IOException {
        Path chrome = chrome();
        Path elsewhere = Files.createDirectories(home.resolve("elsewhere"));
        Files.createSymbolicLink(chrome.resolve(BrowserCommands.HOSTS_DIR), elsewhere);
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_DONE, run(io, "browser", "install", "--extension-id", ID));
        assertTrue(io.outText().contains("chrome" + Messages.BRIDGE_STATUS_UNSAFE.text()), io::outText);
        assertEquals(0, filesUnder(elsewhere));
    }

    @Test
    void aLinkedManifestFileIsRefusedAndLeftAlone() throws IOException {
        Path chrome = chrome();
        Path hosts = Files.createDirectory(chrome.resolve(BrowserCommands.HOSTS_DIR));
        Path target = Files.writeString(home.resolve("target.json"), "{}", StandardCharsets.US_ASCII);
        Files.createSymbolicLink(hosts.resolve(BrowserCommands.MANIFEST_FILE), target);
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_DONE, run(io, "browser", "install", "--extension-id", ID));
        assertEquals("{}", Files.readString(target));
        assertTrue(Files.isSymbolicLink(hosts.resolve(BrowserCommands.MANIFEST_FILE)));
        assertEquals(ExitCodes.NOT_DONE, run(new FakeConsoleIo(), "browser", "uninstall"));
        assertTrue(Files.isSymbolicLink(hosts.resolve(BrowserCommands.MANIFEST_FILE)), "uninstall leaves it too");
    }

    @Test
    void aGroupWritableFolderIsRefused() throws IOException {
        Path chrome = chrome();
        Path hosts = Files.createDirectory(chrome.resolve(BrowserCommands.HOSTS_DIR));
        Files.setPosixFilePermissions(hosts, PosixFilePermissions.fromString("rwxrwx---"));
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_DONE, run(io, "browser", "install", "--extension-id", ID));
        assertTrue(io.outText().contains("chrome" + Messages.BRIDGE_STATUS_UNSAFE.text()), io::outText);
        assertFalse(Files.exists(manifestIn(chrome)));
    }

    /**
     * The folders above the browser folder follow the launcher's rule (m54b-004): a link on the way
     * that leads to a world-writable folder, where anyone could swap the browser folder, is refused
     * and nothing is written; the same link to a folder only the user can change is followed.
     */
    @Test
    void aLinkedAncestorLeadingToAWorldWritableFolderIsRefused() throws IOException {
        Path shared = Files.createDirectories(home.resolve("shared"));
        Files.setPosixFilePermissions(shared, modeOf("777"));
        Path chrome = Files.createDirectories(shared.resolve("Chrome"));
        Files.createSymbolicLink(home.resolve("Library/Application Support/Google"), shared);
        assertTrue(Files.isDirectory(root(BrowserCommands.Browser.CHROME, BrowserCommands.Os.MAC)));
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_DONE, run(io, "browser", "install", "--browser", "chrome", "--extension-id", ID));
        assertTrue(io.outText().contains("chrome" + Messages.BRIDGE_STATUS_UNSAFE.text()), io::outText);
        assertEquals(0, filesUnder(shared));
        assertFalse(Files.exists(allowlist()), "the allowlist is untouched");
        FakeConsoleIo status = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(status, "browser", "status", "--browser", "chrome"));
        assertTrue(status.outText().contains("chrome" + Messages.BRIDGE_STATUS_UNSAFE.text()), status::outText);

        Files.setPosixFilePermissions(shared, PosixFilePermissions.fromString("rwx------"));
        FakeConsoleIo ok = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(ok, "browser", "install", "--browser", "chrome", "--extension-id", ID),
                ok::errText);
        assertEquals(expectedManifest(), Files.readString(manifestIn(chrome)));
    }

    /** A world-writable {@code XDG_CONFIG_HOME} on Linux is refused the same way (m54b-004). */
    @Test
    void aWorldWritableXdgConfigHomeIsRefused() throws IOException {
        Path config = Files.createDirectories(home.resolve("xdg"));
        Files.setPosixFilePermissions(config, modeOf("777"));
        Path chrome = Files.createDirectories(config.resolve("google-chrome"));
        vaultDir = Files.createDirectories(home.resolve(".local/share/pm"));
        Files.setPosixFilePermissions(vaultDir, PosixFilePermissions.fromString("rwx------"));
        BrowserCommands.Platform p = new BrowserCommands.Platform(BrowserCommands.Os.LINUX, home, Optional.of(config),
                ME, Optional.of(launcher), false);
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_DONE, run(io, p, "browser", "install", "--browser", "chrome", "--extension-id", ID));
        assertTrue(io.outText().contains("chrome" + Messages.BRIDGE_STATUS_UNSAFE.text()), io::outText);
        assertFalse(Files.exists(chrome.resolve(BrowserCommands.HOSTS_DIR)), "nothing created");
        assertFalse(Files.exists(allowlist()), "the allowlist is untouched");

        Files.setPosixFilePermissions(config, PosixFilePermissions.fromString("rwx------"));
        FakeConsoleIo ok = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(ok, p, "browser", "install", "--browser", "chrome", "--extension-id", ID),
                ok::errText);
        assertEquals(expectedManifest(), Files.readString(manifestIn(chrome)));
    }

    @Test
    void aSharedWritableVaultFolderMeansNoAllowlistChange() throws IOException {
        chrome();
        Files.setPosixFilePermissions(vaultDir, PosixFilePermissions.fromString("rwxrwx---"));
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_DONE, run(io, "browser", "install", "--extension-id", ID));
        assertTrue(io.errText().contains(Messages.BRIDGE_UNSAFE_ALLOWLIST.text()), io::errText);
        Files.setPosixFilePermissions(vaultDir, PosixFilePermissions.fromString("rwx------"));
        assertEquals(0, filesUnder(home.resolve("Library")));
    }

    @Test
    void foldersOwnedByAnotherUserAreRefused() throws IOException {
        chrome();
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_DONE, run(io, BrowserCommands.Os.MAC, "someone-else",
                "browser", "install", "--extension-id", ID));
        assertTrue(io.errText().contains(Messages.BRIDGE_UNSAFE_ALLOWLIST.text()), io::errText);
        assertEquals(0, filesUnder(home.resolve("Library")));
        FakeConsoleIo status = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(status, BrowserCommands.Os.MAC, "someone-else", "browser", "status"));
        assertTrue(status.outText().contains("chrome" + Messages.BRIDGE_STATUS_UNSAFE.text()), status::outText);
    }

    @Test
    void anotherProgramsManifestIsNeitherReplacedNorRemoved() throws IOException {
        Path chrome = chrome();
        Path hosts = Files.createDirectory(chrome.resolve(BrowserCommands.HOSTS_DIR));
        String theirs = "{\"name\":\"pm.browser\",\"description\":\"something else\",\"path\":\"/tmp/x\","
                + "\"type\":\"stdio\",\"allowed_origins\":[\"chrome-extension://" + ID + "/\"]}";
        Path manifest = Files.writeString(hosts.resolve(BrowserCommands.MANIFEST_FILE), theirs, StandardCharsets.UTF_8);
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_DONE, run(io, "browser", "install", "--extension-id", ID));
        assertTrue(io.outText().contains("chrome" + Messages.BRIDGE_STATUS_FOREIGN.text()), io::outText);
        assertEquals(theirs, Files.readString(manifest));
        assertTrue(io.errText().contains(Messages.BRIDGE_NOTHING_INSTALLABLE.text()), io::errText);
        assertFalse(Files.exists(allowlist()), "no manifest of pm's, so no allowlist entry");
        assertEquals(ExitCodes.NOT_DONE, run(new FakeConsoleIo(), "browser", "uninstall"));
        assertEquals(theirs, Files.readString(manifest));
    }

    @Test
    void uninstallRemovesOnlyPmsManifestsAndThenClearsTheAllowlist() throws IOException {
        Path chrome = chrome();
        Path brave = Files.createDirectories(root(BrowserCommands.Browser.BRAVE, BrowserCommands.Os.MAC));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--extension-id", ID));
        assertTrue(Files.exists(manifestIn(chrome)));
        assertTrue(Files.exists(manifestIn(brave)));
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, "browser", "uninstall", "--browser", "brave"));
        assertTrue(io.outText().contains("brave" + Messages.BRIDGE_REMOVED.text()), io::outText);
        assertFalse(Files.exists(manifestIn(brave)));
        assertTrue(Files.exists(manifestIn(chrome)), "only the named browser");
        assertEquals(List.of(ID), ExtensionAllowlist.read(allowlist()).ids(), "chrome still holds a manifest");
        FakeConsoleIo all = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(all, "browser", "uninstall"));
        assertFalse(Files.exists(manifestIn(chrome)));
        assertTrue(all.outText().contains(Messages.BRIDGE_ALLOWLIST_CLEARED.text()), all::outText);
        assertEquals(List.of(), ExtensionAllowlist.read(allowlist()).ids(), "no manifest left: nobody is allowed");
        FakeConsoleIo again = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(again, "browser", "uninstall"));
        assertTrue(again.outText().contains("chrome" + Messages.BRIDGE_NOTHING_TO_REMOVE.text()), again::outText);
    }

    @Test
    void statusReportsEveryState() throws IOException {
        chrome();
        Path chromium = Files.createDirectories(root(BrowserCommands.Browser.CHROMIUM, BrowserCommands.Os.MAC));
        Path edge = Files.createDirectories(root(BrowserCommands.Browser.EDGE, BrowserCommands.Os.MAC));
        Path brave = Files.createDirectories(root(BrowserCommands.Browser.BRAVE, BrowserCommands.Os.MAC));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--browser", "chrome",
                "--extension-id", ID));
        assertTrue(Files.exists(chromium));
        // edge: another program's manifest; brave: pm's manifest for a pm that has moved.
        Files.createDirectory(edge.resolve(BrowserCommands.HOSTS_DIR));
        Files.writeString(manifestIn(edge), "not json", StandardCharsets.US_ASCII);
        Files.createDirectory(brave.resolve(BrowserCommands.HOSTS_DIR));
        Files.write(manifestIn(brave), BrowserCommands.manifest(home.resolve("old/pm"), List.of(ID)));
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, "browser", "status"));
        String out = io.outText();
        assertTrue(out.contains("chrome" + Messages.BRIDGE_STATUS_INSTALLED.text()), out);
        assertTrue(out.contains("chromium" + Messages.BRIDGE_STATUS_MISSING.text()), out);
        assertTrue(out.contains("edge" + Messages.BRIDGE_STATUS_FOREIGN.text()), out);
        assertTrue(out.contains("brave" + Messages.BRIDGE_STATUS_STALE.text()), out);
        Files.writeString(allowlist(), OTHER_ID + "\n", StandardCharsets.US_ASCII);
        FakeConsoleIo removed = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(removed, "browser", "status", "--browser", "chrome"));
        assertTrue(removed.outText().contains("chrome" + Messages.BRIDGE_STATUS_STALE.text()),
                "an extension no longer in the allowlist is stale: " + removed.outText());
    }

    @Test
    void withNoBrowserNothingIsWritten() throws IOException {
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_DONE, run(io, "browser", "install", "--extension-id", ID));
        assertTrue(io.errText().contains(Messages.BRIDGE_NO_BROWSER.text()), io::errText);
        assertEquals(0, filesUnder(home.resolve("Library")), "not even the allowlist");
        FakeConsoleIo named = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_DONE, run(named, "browser", "install", "--browser", "edge", "--extension-id", ID));
        assertTrue(named.outText().contains("edge" + Messages.BRIDGE_STATUS_NO_BROWSER.text()), named::outText);
    }

    @Test
    void linuxUsesTheConfigFolders() throws IOException {
        Path chrome = Files.createDirectories(home.resolve(".config/google-chrome"));
        vaultDir = Files.createDirectories(home.resolve(".local/share/pm"));
        Files.setPosixFilePermissions(vaultDir, PosixFilePermissions.fromString("rwx------"));
        assertEquals(chrome, root(BrowserCommands.Browser.CHROME, BrowserCommands.Os.LINUX));
        assertEquals(home.resolve(".config/BraveSoftware/Brave-Browser"),
                root(BrowserCommands.Browser.BRAVE, BrowserCommands.Os.LINUX));
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, BrowserCommands.Os.LINUX, ME, "browser", "install", "--extension-id", ID),
                io::errText);
        assertEquals(expectedManifest(), Files.readString(manifestIn(chrome)));
        assertEquals(List.of(ID), ExtensionAllowlist.read(vaultDir.resolve(ExtensionAllowlist.FILE_NAME)).ids());
    }

    @Test
    void windowsPrintsTheStepsAndWritesNothing() throws IOException {
        long before = filesUnder(home);
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_DONE, run(io, BrowserCommands.Os.WINDOWS, ME,
                "browser", "install", "--browser", "edge", "--extension-id", ID));
        String out = io.outText();
        assertTrue(out.contains(Messages.BRIDGE_WINDOWS.text()), out);
        assertTrue(out.contains("HKEY_CURRENT_USER\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\pm.browser"), out);
        assertTrue(out.contains("\"allowed_origins\": [\"chrome-extension://" + ID + "/\"]"), out);
        assertEquals(before, filesUnder(home));
        assertEquals(ExitCodes.NOT_DONE, run(new FakeConsoleIo(), BrowserCommands.Os.WINDOWS, ME, "browser", "status"));
        assertEquals(ExitCodes.NOT_DONE, run(new FakeConsoleIo(), BrowserCommands.Os.WINDOWS, ME, "browser", "uninstall"));
        assertEquals(before, filesUnder(home));
    }

    @Test
    void onlyTheDefaultVaultAndKnownBrowsersAndCommands() throws IOException {
        chrome();
        FakeConsoleIo vault = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(vault, "--vault", home.resolve("other.pmv").toString(),
                "browser", "install", "--extension-id", ID));
        assertTrue(vault.errText().contains(Messages.BRIDGE_DEFAULT_VAULT_ONLY.text()), vault::errText);
        FakeConsoleIo browser = new FakeConsoleIo();
        assertEquals(ExitCodes.USAGE, run(browser, "browser", "install", "--browser", "firefox"));
        assertTrue(browser.errText().contains(Messages.BRIDGE_UNKNOWN_BROWSER.text()), browser::errText);
        assertEquals(ExitCodes.USAGE, run(new FakeConsoleIo(), "browser", "remove"));
        assertEquals(ExitCodes.USAGE, run(new FakeConsoleIo(), "browser"));
        assertEquals(0, filesUnder(home.resolve("Library")));
    }

    @Test
    void anUnsafeLauncherIsNotRegistered() throws IOException {
        chrome();
        Files.setPosixFilePermissions(launcher, PosixFilePermissions.fromString("rwxrwx---"));
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_DONE, run(io, "browser", "install", "--extension-id", ID));
        assertTrue(io.errText().contains(Messages.BRIDGE_NO_LAUNCHER.text()), io::errText);
        Files.setPosixFilePermissions(launcher, PosixFilePermissions.fromString("rw-------"));
        assertTrue(BrowserCommands.safeLauncher(launcher, ME).isEmpty(), "not executable");
        assertEquals(0, filesUnder(home.resolve("Library")));
    }

    // ---- M5.4 review fixes -------------------------------------------------------------------

    @Test
    void uninstallOfOneExtensionRemovesItsManifestsAndItsAllowlistEntryAndStatusListsTheRest() throws IOException {
        Path chrome = chrome();
        Path brave = Files.createDirectories(root(BrowserCommands.Browser.BRAVE, BrowserCommands.Os.MAC));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--browser", "chrome",
                "--extension-id", ID));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--browser", "brave",
                "--extension-id", OTHER_ID));
        assertEquals(List.of(ID, OTHER_ID), ExtensionAllowlist.read(allowlist()).ids());
        FakeConsoleIo listed = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(listed, "browser", "status"));
        assertTrue(listed.outText().contains(Messages.BRIDGE_ALLOWLIST_LISTED.text() + ID), listed::outText);
        assertTrue(listed.outText().contains(Messages.BRIDGE_ALLOWLIST_LISTED.text() + OTHER_ID), listed::outText);

        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, "browser", "uninstall", "--extension-id", ID));
        assertFalse(Files.exists(manifestIn(chrome)), "the manifest for that extension is gone");
        assertTrue(Files.exists(manifestIn(brave)), "the other extension's manifest stays");
        assertTrue(io.outText().contains(Messages.BRIDGE_ALLOWLIST_REMOVED.text() + ID), io::outText);
        assertEquals(List.of(OTHER_ID), ExtensionAllowlist.read(allowlist()).ids());

        FakeConsoleIo rest = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(rest, "browser", "uninstall"));
        assertFalse(Files.exists(manifestIn(brave)));
        assertTrue(rest.outText().contains(Messages.BRIDGE_ALLOWLIST_CLEARED.text()), rest::outText);
        FakeConsoleIo none = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(none, "browser", "status"));
        assertTrue(none.outText().contains(Messages.BRIDGE_ALLOWLIST_EMPTY.text()), none::outText);
        assertEquals(ExitCodes.USAGE, run(new FakeConsoleIo(), "browser", "uninstall", "--extension-id", "bad"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"777", "770"})
    void aLauncherBelowAFolderOthersCanWriteIsRefused(String mode) throws IOException {
        chrome();
        Path shared = Files.createDirectories(home.resolve("shared/bin"));
        Path exposed = Files.copy(launcher, shared.resolve("pm"));
        Files.setPosixFilePermissions(exposed, PosixFilePermissions.fromString("rwx------"));
        assertTrue(BrowserCommands.safeLauncher(exposed, ME).isPresent(), "safe while every folder is private");
        assertTrue(BrowserCommands.safeLauncher(exposed, ME + "-not").isEmpty(), "owned by neither that user nor root");
        Files.setPosixFilePermissions(home.resolve("shared"), modeOf(mode));
        assertTrue(BrowserCommands.safeLauncher(exposed, ME).isEmpty(), "an ancestor others can write: " + mode);
        FakeConsoleIo io = new FakeConsoleIo();
        BrowserCommands.Platform p = new BrowserCommands.Platform(BrowserCommands.Os.MAC, home, ME, Optional.of(exposed));
        assertEquals(ExitCodes.NOT_DONE, run(io, p, "browser", "install", "--extension-id", ID));
        assertTrue(io.errText().contains(Messages.BRIDGE_NO_LAUNCHER.text()), io::errText);
        assertEquals(0, filesUnder(home.resolve("Library")), "nothing written");
        Files.setPosixFilePermissions(home.resolve("shared"), PosixFilePermissions.fromString("rwx------"));
    }

    /** The permissions of an octal mode such as {@code 777}, in the enum's owner, group, others order. */
    private static Set<PosixFilePermission> modeOf(String octal) {
        int bits = Integer.parseInt(octal, 8);
        PosixFilePermission[] all = PosixFilePermission.values();
        Set<PosixFilePermission> set = EnumSet.noneOf(PosixFilePermission.class);
        for (int i = 0; i < all.length; i++) {
            if ((bits & (1 << (all.length - 1 - i))) != 0) {
                set.add(all[i]);
            }
        }
        return set;
    }

    @Test
    void aSourceCheckoutsLauncherIsRefusedWithAClearMessage() throws IOException, UsageException {
        chrome();
        Path script = Files.createDirectories(home.resolve("repo/scripts")).resolve("pm");
        Map<String, String> props = Map.of(VaultPaths.USER_HOME, home.toString(), "user.name", ME,
                VaultPaths.OS_NAME, "Mac OS X", "jpackage.app-path", script.toString());
        BrowserCommands.Platform p = BrowserCommands.Platform.system(props::get, Env.of(Map.of()));
        assertTrue(p.checkout());
        assertEquals(Optional.empty(), p.launcher());
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_DONE, run(io, p, "browser", "install", "--extension-id", ID));
        assertTrue(io.errText().contains(Messages.BRIDGE_CHECKOUT_LAUNCHER.text()), io::errText);
        assertEquals(0, filesUnder(home.resolve("Library")), "nothing written");
        Map<String, String> installed = Map.of(VaultPaths.USER_HOME, home.toString(), "user.name", ME,
                VaultPaths.OS_NAME, "Mac OS X", "jpackage.app-path", launcher.toString());
        BrowserCommands.Platform q = BrowserCommands.Platform.system(installed::get, Env.of(Map.of()));
        assertFalse(q.checkout());
        assertEquals(Optional.of(launcher), q.launcher());
    }

    @Test
    void linuxHonoursAnAbsoluteXdgConfigHome() throws IOException, UsageException {
        Path config = home.resolve("xdg-config");
        Map<String, String> props = Map.of(VaultPaths.USER_HOME, home.toString(), "user.name", ME,
                VaultPaths.OS_NAME, "Linux", "jpackage.app-path", launcher.toString());
        BrowserCommands.Platform p = BrowserCommands.Platform.system(props::get,
                Env.of(Map.of("XDG_CONFIG_HOME", config.toString())));
        assertEquals(Optional.of(config), p.config());
        assertEquals(Optional.empty(), BrowserCommands.Platform.system(props::get,
                Env.of(Map.of("XDG_CONFIG_HOME", "relative/config"))).config(), "a relative one is ignored");
        assertEquals(config.resolve("google-chrome"),
                BrowserCommands.Browser.CHROME.root(BrowserCommands.Os.LINUX, home, Optional.of(config)));
        Path chrome = Files.createDirectories(config.resolve("google-chrome"));
        vaultDir = Files.createDirectories(home.resolve(".local/share/pm"));
        Files.setPosixFilePermissions(vaultDir, PosixFilePermissions.fromString("rwx------"));
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, p, "browser", "install", "--extension-id", ID), io::errText);
        assertEquals(expectedManifest(), Files.readString(manifestIn(chrome)));
        assertFalse(Files.exists(home.resolve(".config/google-chrome")), "not the default folder");
    }

    @Test
    void aManifestReachedThroughALinkIsNotRead() throws IOException {
        Path real = Files.write(home.resolve("real.json"), BrowserCommands.manifest(launcher, List.of(ID)));
        Path link = Files.createSymbolicLink(home.resolve("link.json"), real);
        assertEquals(List.of(ID), BrowserCommands.manifestIds(real));
        assertEquals(List.of(), BrowserCommands.manifestIds(link), "a link is never followed");
    }

    @Test
    void manifestStringsAreEscaped() {
        assertEquals("\"a\\\"b\\\\c\\u000a\"", BrowserCommands.quote("a\"b\\c\n"));
        assertTrue(BrowserCommands.isOurs(BrowserCommands.manifest(Path.of("/opt/p \"q\"/pm"), List.of(ID))));
    }

    @Test
    void browserCommandsRunWithoutATerminal() throws IOException {
        chrome();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        Map<String, String> props = Map.of(VaultPaths.OS_NAME, "Mac OS X", VaultPaths.USER_HOME, home.toString());
        BrowserCommands.Platform platform =
                new BrowserCommands.Platform(BrowserCommands.Os.MAC, home, ME, Optional.of(launcher));
        int code = new Cli(props::get, Clock.fixed(NOW, ZoneOffset.UTC), p -> { })
                .withBrowserPlatform(p -> platform)
                .run(new String[] {"browser", "status"}, Optional.empty(),
                        new PrintStream(out, true, StandardCharsets.UTF_8), new PrintStream(err, true, StandardCharsets.UTF_8));
        assertEquals(ExitCodes.OK, code, err::toString);
        assertTrue(out.toString(StandardCharsets.UTF_8).contains("chrome" + Messages.BRIDGE_STATUS_MISSING.text()));
    }

    @Test
    void uninstallTakesEveryCopyOfARepeatedOrigin() throws IOException {
        Path chrome = chrome();
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--extension-id", OTHER_ID));
        Files.write(manifestIn(chrome), BrowserCommands.manifest(launcher.toRealPath(), List.of(ID, OTHER_ID, ID)));
        Files.writeString(allowlist(), ID + "\n" + OTHER_ID + "\n", StandardCharsets.US_ASCII);
        FakeConsoleIo io = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(io, "browser", "uninstall", "--extension-id", ID), io::errText);
        assertEquals(List.of(OTHER_ID), BrowserCommands.manifestIds(manifestIn(chrome)), "no copy of the origin is left");
        assertEquals(List.of(OTHER_ID), ExtensionAllowlist.read(allowlist()).ids());
    }

    @Test
    void anAllowlistThatCannotBeWrittenAfterTheManifestSaysTheManifestChanged() throws IOException {
        Path chrome = chrome();
        Files.setPosixFilePermissions(vaultDir, PosixFilePermissions.fromString("r-x------"));
        try {
            FakeConsoleIo io = new FakeConsoleIo();
            assertEquals(ExitCodes.NOT_DONE, run(io, "browser", "install", "--extension-id", ID));
            assertTrue(Files.exists(manifestIn(chrome)), "the manifest was written first");
            assertTrue(io.errText().contains(Messages.BRIDGE_ALLOWLIST_NOT_WRITTEN.text()), io::errText);
            assertFalse(io.errText().contains("nothing was changed"), io::errText);
        } finally {
            Files.setPosixFilePermissions(vaultDir, PosixFilePermissions.fromString("rwx------"));
        }
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--extension-id", ID), "a rerun finishes");
        assertEquals(List.of(ID), ExtensionAllowlist.read(allowlist()).ids());
    }

    @Test
    void clearingTheAllowlistPastAnUnreadableManifestSaysSo() throws IOException {
        Path chrome = chrome();
        Path chromium = Files.createDirectories(root(BrowserCommands.Browser.CHROMIUM, BrowserCommands.Os.MAC));
        assertEquals(ExitCodes.OK, run(new FakeConsoleIo(), "browser", "install", "--extension-id", ID));
        Files.setPosixFilePermissions(manifestIn(chromium), PosixFilePermissions.fromString("---------"));
        try {
            FakeConsoleIo io = new FakeConsoleIo();
            run(io, "browser", "uninstall", "--browser", "chrome", "--extension-id", ID);
            assertFalse(Files.exists(manifestIn(chrome)));
            assertEquals(List.of(), ExtensionAllowlist.read(allowlist()).ids(), "fails closed");
            assertTrue(io.outText().contains(Messages.BRIDGE_ALLOWLIST_CLEARED_UNREAD.text()), io::outText);
            assertFalse(io.outText().contains(Messages.BRIDGE_ALLOWLIST_CLEARED.text()), io::outText);
        } finally {
            Files.setPosixFilePermissions(manifestIn(chromium), PosixFilePermissions.fromString("rw-------"));
        }
    }
}
