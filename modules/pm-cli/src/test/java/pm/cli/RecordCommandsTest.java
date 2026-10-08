package pm.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.vault.record.LoginRecord;
import pm.vault.record.ProjectRecord;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/**
 * M7.7 item commands: {@code show} masks every secret unless {@code --reveal}, which prints only a
 * login's or a Wi-Fi network's password (SR-132); {@code edit} and {@code wifi add} take a new
 * secret only from the prompt, typed twice, or from the generator (SR-133); {@code rm} asks first.
 * The secrets here are deliberately not the canary: {@code --reveal} must print them.
 */
@SuppressWarnings("PMD.CloseResource") // CE-087: records stay owned by FakeVaultPort, which closes them
class RecordCommandsTest {
    private static final String UNLOCK = "unlock-phrase-r7";
    private static final String REVEALED_PASSWORD = "reveal-me-5f2a";
    private static final String PSK = "wifi-psk-91c0";
    private static final String TYPED = "typed-new-3b7e";
    private static final Instant THEN = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant NOW = Instant.parse("2026-10-06T09:00:00Z");

    private final FakeVaultPort port = new FakeVaultPort().withVault(UNLOCK);

    private int run(FakeConsoleIo io, String... args) {
        Cli cli = new Cli(Map.of(VaultPaths.OS_NAME, "Linux", VaultPaths.USER_HOME, "/home/alice")::get,
                Clock.fixed(NOW, ZoneOffset.UTC), p -> { });
        return cli.run(args, io, (path, creating) -> port);
    }

    private static FakeConsoleIo unlocking() {
        return new FakeConsoleIo().secret(UNLOCK);
    }

    private static SecretBytes bytes(String s) {
        return SecretBytes.copyOf(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String text(SecretBytes s) {
        return s.apply(b -> new String(b, StandardCharsets.UTF_8));
    }

    private LoginRecord login(String title, String password) {
        LoginRecord r = new LoginRecord(UUID.randomUUID(), title, "octocat", bytes(password),
                List.of("https://github.com"), "first line\nsecond line", List.of("dev"), THEN, THEN, THEN);
        port.stored.add(r);
        return r;
    }

    private WifiRecord wifi(String title, String security, String psk) {
        WifiRecord r = new WifiRecord(UUID.randomUUID(), title, "HomeNet", security, bytes(psk), false, "", THEN, THEN);
        port.stored.add(r);
        return r;
    }

    private SshKeyRecord sshKey(String title) {
        SshTestKeys.Key key = SshTestKeys.ed25519("me@desk");
        SshKeyRecord r = new SshKeyRecord(UUID.randomUUID(), title, "ssh-ed25519", SecretBytes.copyOf(key.file()),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOr me@desk", "SHA256:abc", "me@desk", List.of("example.com"),
                THEN, THEN);
        port.stored.add(r);
        return r;
    }

    /** A shown label, padded as {@code pm show} pads it. */
    private static String f(String label) {
        return String.format(java.util.Locale.ROOT, "%-14s", label + ":");
    }

    private VaultRecord only() {
        assertEquals(1, port.stored.size());
        return port.stored.get(0);
    }

    // ---- show --------------------------------------------------------------------------------

    @Test
    void showMasksThePasswordAndPrintsTheOtherFields() {
        LoginRecord r = login("GitHub", REVEALED_PASSWORD);
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "show", "GitHub"), io::errText);
        String out = io.outText();
        assertFalse(out.contains(REVEALED_PASSWORD), "masked by default");
        assertTrue(out.contains(f("password") + Messages.VALUE_MASKED.text()), out);
        assertTrue(out.contains(f("id") + r.id()), out);
        assertTrue(out.contains(f("type") + "login"), out);
        assertTrue(out.contains(f("username") + "octocat"), out);
        assertTrue(out.contains(f("urls") + "https://github.com"), out);
        assertTrue(out.contains("notes:\n  first line\n  second line\n"), out);
        assertTrue(io.allSecretsZeroed());
    }

    @Test
    void revealPrintsTheLoginPasswordOnceAndNothingElseSecret() {
        login("GitHub", REVEALED_PASSWORD);
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "show", "GitHub", "--reveal"), io::errText);
        assertTrue(io.outText().contains(f("password") + REVEALED_PASSWORD + "\n"), io::outText);
        assertEquals(io.outText().indexOf(REVEALED_PASSWORD), io.outText().lastIndexOf(REVEALED_PASSWORD), "printed once");
        assertFalse(io.errText().contains(REVEALED_PASSWORD));
        assertEquals(REVEALED_PASSWORD, text(((LoginRecord) only()).password()), "showing changes nothing");
        assertEquals(0, port.saves);
    }

    @Test
    void revealPrintsTheWifiPassword() {
        wifi("Home", "WPA2", PSK);
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "show", "Home", "--reveal"), io::errText);
        assertTrue(io.outText().contains(f("password") + PSK), io::outText);
        assertTrue(io.outText().contains(f("ssid") + "HomeNet"), io::outText);
    }

    @Test
    void anOpenNetworkHasNoPasswordToMask() {
        wifi("Cafe", "OPEN", "");
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "show", "Cafe"), io::errText);
        assertTrue(io.outText().contains(f("password") + Messages.VALUE_NONE.text()), io::outText);
    }

    @Test
    void revealNeverPrintsAnSshPrivateKeyOrAProjectVariable() {
        SshKeyRecord key = sshKey("laptop");
        FakeConsoleIo ssh = unlocking();
        assertEquals(ExitCodes.USAGE, run(ssh, "show", "laptop", "--reveal"));
        assertTrue(ssh.errText().contains(Messages.REVEAL_SSH_KEY.text()), ssh::errText);
        assertEquals(Messages.PROMPT_PASSPHRASE.text(), ssh.outText(), "a refused --reveal prints no half view");
        FakeConsoleIo masked = unlocking();
        assertEquals(ExitCodes.OK, run(masked, "show", key.id().toString()), masked::errText);
        assertTrue(masked.outText().contains(f("private key") + Messages.VALUE_MASKED.text()), masked::outText);
        assertTrue(masked.outText().contains(f("fingerprint") + "SHA256:abc"), masked::outText);
        assertFalse(masked.outText().contains("OPENSSH PRIVATE KEY"), masked::outText);

        port.stored.add(new ProjectRecord(UUID.randomUUID(), "app", "/src/app", "", Map.of("API_KEY",
                bytes(REVEALED_PASSWORD)), Map.of(), THEN, THEN));
        FakeConsoleIo project = unlocking();
        assertEquals(ExitCodes.OK, run(project, "show", "app"), project::errText);
        assertTrue(project.outText().contains(f("variables") + "default: API_KEY"), project::outText);
        assertFalse(project.outText().contains(REVEALED_PASSWORD), "values leave only through pm env");
        FakeConsoleIo revealProject = unlocking();
        assertEquals(ExitCodes.USAGE, run(revealProject, "show", "app", "--reveal"));
        assertTrue(revealProject.errText().contains(Messages.REVEAL_PROJECT.text()));
        assertFalse(revealProject.outText().contains(REVEALED_PASSWORD));
    }

    @Test
    void revealRefusesAPasswordThatWouldDriveTheTerminal() {
        login("Evil", "pw\u001b]0;owned\u0007");
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.USAGE, run(io, "show", "Evil", "--reveal"));
        assertTrue(io.errText().contains(Messages.REVEAL_UNPRINTABLE.text()), io::errText);
        assertEquals(Messages.PROMPT_PASSPHRASE.text(), io.outText());
    }

    @Test
    void revealRefusesAPasswordThatWouldPrintAsBlanks() {
        // m77-004: Hangul fillers, the braille blank, U+034F, a variation selector, NBSP and a tag
        // character print as nothing or a blank, so a password read off the screen would be wrong.
        String[] invisible = {"\u3164", "\u115F", "\uFFA0", "\u2800", "\u034F", "\uFE0F", "\u00A0", "\u3000",
            Character.toString(0xE0041)};
        for (String c : invisible) {
            port.stored.clear();
            login("Blank", "pass" + c + "word");
            FakeConsoleIo io = unlocking();
            assertEquals(ExitCodes.USAGE, run(io, "show", "Blank", "--reveal"), Integer.toHexString(c.codePointAt(0)));
            assertTrue(io.errText().contains(Messages.REVEAL_UNPRINTABLE.text()), io::errText);
            assertFalse(io.outText().contains("pass"), io::outText);
        }
        port.stored.clear();
        login("Accents", "caf\u00e9 e\u0301 \u5bc6\u7801");
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "show", "Accents", "--reveal"), io::errText);
        assertTrue(io.outText().contains("caf\u00e9 e\u0301 \u5bc6\u7801"), "a plain space, accents and CJK print");
    }

    @Test
    void anAmbiguousTitleIsRefusedWithTheIdsToPickFrom() {
        LoginRecord a = login("Mail", REVEALED_PASSWORD);
        LoginRecord b = login("Mail", "other-secret-1");
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.USAGE, run(io, "show", "Mail"));
        assertTrue(io.errText().contains(Messages.AMBIGUOUS_RECORD.text()), io::errText);
        assertTrue(io.errText().contains(a.id().toString()) && io.errText().contains(b.id().toString()));
        assertEquals(Messages.PROMPT_PASSPHRASE.text(), io.outText());
        FakeConsoleIo byId = unlocking();
        assertEquals(ExitCodes.OK, run(byId, "show", b.id().toString()), byId::errText);
        assertTrue(byId.outText().contains(b.id().toString()));

        FakeConsoleIo none = unlocking();
        assertEquals(ExitCodes.USAGE, run(none, "show", "Nope"));
        assertTrue(none.errText().contains(Messages.NO_SUCH_RECORD.text()));
        assertEquals(ExitCodes.USAGE, run(unlocking(), "show"), "an item is required");
    }

    // ---- edit --------------------------------------------------------------------------------

    @Test
    void editChangesTheNamedFieldsAndKeepsThePassword() {
        LoginRecord old = login("GitHub", REVEALED_PASSWORD);
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "edit", "GitHub", "--title", "GitHub work", "--username", "",
                "--urls", "https://a.example, https://b.example", "--notes", "rotated"), io::errText);
        LoginRecord now = (LoginRecord) only();
        assertEquals(old.id(), now.id());
        assertEquals("GitHub work", now.title());
        assertEquals("", now.username(), "an empty value clears the field");
        assertEquals(List.of("https://a.example", "https://b.example"), now.urls());
        assertEquals(List.of("dev"), now.tags(), "untouched");
        assertEquals("rotated", now.notes());
        assertEquals(REVEALED_PASSWORD, text(now.password()));
        assertEquals(THEN, now.created());
        assertEquals(NOW, now.updated());
        assertEquals(1, port.saves);
        assertTrue(io.outText().contains(Messages.EDITED.text() + old.id()));
        assertEquals(1, io.secretsRead(), "only the vault passphrase was asked for");
    }

    @Test
    void editPasswordIsTypedTwiceAndNeverTakenFromTheCommandLine() {
        login("GitHub", REVEALED_PASSWORD);
        FakeConsoleIo io = unlocking().secret(TYPED).secret(TYPED);
        assertEquals(ExitCodes.OK, run(io, "edit", "GitHub", "--password"), io::errText);
        assertEquals(TYPED, text(((LoginRecord) only()).password()));
        assertFalse(io.outText().contains(TYPED) || io.errText().contains(TYPED));
        assertTrue(io.allSecretsZeroed());

        FakeConsoleIo argv = unlocking();
        assertEquals(ExitCodes.USAGE, run(argv, "edit", "GitHub", "--password", "on-argv"));
        assertTrue(argv.errText().contains(Messages.WRONG_ARG_COUNT.text()), argv::errText);
        assertEquals(TYPED, text(((LoginRecord) only()).password()), "a value after --password is no password");

        FakeConsoleIo mismatch = unlocking().secret("one-1").secret("two-2");
        assertEquals(ExitCodes.USAGE, run(mismatch, "edit", "GitHub", "--password"));
        assertTrue(mismatch.errText().contains(Messages.PASSWORD_MISMATCH.text()));
        assertEquals(TYPED, text(((LoginRecord) only()).password()));
        assertEquals(1, port.saves);
    }

    @Test
    void editGenerateUsesTheGeneratorPolicyAndPrintsOnlyTheEntropy() {
        login("GitHub", REVEALED_PASSWORD);
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "edit", "GitHub", "--generate", "--length", "32"), io::errText);
        String generated = text(((LoginRecord) only()).password());
        assertEquals(32, generated.length());
        assertFalse(io.outText().contains(generated));
        assertTrue(io.outText().contains(Messages.EDIT_GENERATED.text()), io::outText);

        FakeConsoleIo stray = unlocking();
        assertEquals(ExitCodes.USAGE, run(stray, "edit", "GitHub", "--length", "32"));
        assertTrue(stray.errText().contains(Messages.EDIT_GENERATE_OPTIONS.text()));
        FakeConsoleIo both = unlocking();
        assertEquals(ExitCodes.USAGE, run(both, "edit", "GitHub", "--generate", "--password"));
        assertTrue(both.errText().contains(Messages.EDIT_TWO_SOURCES.text()));
        FakeConsoleIo nothing = unlocking();
        assertEquals(ExitCodes.USAGE, run(nothing, "edit", "GitHub"));
        assertTrue(nothing.errText().contains(Messages.EDIT_NOTHING.text()));
        assertEquals(1, port.saves);
    }

    @Test
    void editWifiChangesSsidSecurityAndHidden() {
        WifiRecord old = wifi("Home", "WPA2", PSK);
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "edit", "Home", "--ssid", "HomeNet-5G", "--security", "wpa3", "--hidden"),
                io::errText);
        WifiRecord now = (WifiRecord) only();
        assertEquals(old.id(), now.id());
        assertEquals("HomeNet-5G", now.ssid());
        assertEquals("WPA3", now.security());
        assertTrue(now.hidden());
        assertEquals(PSK, text(now.password()));

        FakeConsoleIo login = unlocking();
        assertEquals(ExitCodes.USAGE, run(login, "edit", "Home", "--username", "x"));
        assertTrue(login.errText().contains(Messages.EDIT_LOGIN_ONLY.text()));
        FakeConsoleIo bad = unlocking();
        assertEquals(ExitCodes.USAGE, run(bad, "edit", "Home", "--security", "WPA9"));
        assertTrue(bad.errText().contains(Messages.BAD_SECURITY.text()));
        FakeConsoleIo openWithPassword = unlocking();
        assertEquals(ExitCodes.USAGE, run(openWithPassword, "edit", "Home", "--security", "open", "--password"));
        assertTrue(openWithPassword.errText().contains(Messages.OPEN_HAS_NO_PASSWORD.text()));

        FakeConsoleIo open = unlocking();
        assertEquals(ExitCodes.OK, run(open, "edit", "Home", "--security", "OPEN", "--not-hidden"), open::errText);
        assertEquals(0, ((WifiRecord) only()).password().length(), "an open network keeps no password");
        assertFalse(((WifiRecord) only()).hidden());
        FakeConsoleIo back = unlocking();
        assertEquals(ExitCodes.USAGE, run(back, "edit", "Home", "--security", "WPA2"));
        assertTrue(back.errText().contains(Messages.WIFI_NEEDS_PASSWORD.text()));
    }

    @Test
    void anEmptyTitleOrSsidIsNamedAsSuch() {
        // m77-008: the parser used to report an empty --title as control characters.
        login("Named", REVEALED_PASSWORD);
        FakeConsoleIo title = unlocking();
        assertEquals(ExitCodes.USAGE, run(title, "edit", "Named", "--title", ""));
        assertTrue(title.errText().contains(Messages.EMPTY_TITLE.text()), title::errText);
        FakeConsoleIo blank = unlocking();
        assertEquals(ExitCodes.USAGE, run(blank, "edit", "Named", "--title", "  "));
        assertTrue(blank.errText().contains(Messages.EMPTY_TITLE.text()), blank::errText);
        assertEquals("Named", only().title());
        port.stored.clear();
        wifi("Home", "WPA2", PSK);
        FakeConsoleIo ssid = unlocking();
        assertEquals(ExitCodes.USAGE, run(ssid, "edit", "Home", "--ssid", ""));
        assertTrue(ssid.errText().contains(Messages.EMPTY_SSID.text()), ssid::errText);
        FakeConsoleIo add = unlocking();
        assertEquals(ExitCodes.USAGE, run(add, "wifi", "add", "Cafe", "--title", ""));
        assertTrue(add.errText().contains(Messages.EMPTY_TITLE.text()), add::errText);
        assertEquals(1, port.stored.size());
    }

    @Test
    void editRefusesOtherTypesAndCrossTypeOptions() {
        sshKey("laptop");
        FakeConsoleIo ssh = unlocking();
        assertEquals(ExitCodes.USAGE, run(ssh, "edit", "laptop", "--title", "desk"));
        assertTrue(ssh.errText().contains(Messages.EDIT_UNSUPPORTED.text()));
        login("GitHub", REVEALED_PASSWORD);
        FakeConsoleIo cross = unlocking();
        assertEquals(ExitCodes.USAGE, run(cross, "edit", "GitHub", "--ssid", "x"));
        assertTrue(cross.errText().contains(Messages.EDIT_WIFI_ONLY.text()));
        assertEquals(0, port.saves);
    }

    // ---- rm ----------------------------------------------------------------------------------

    @Test
    void rmAsksForYAndOnlyThenRemoves() {
        LoginRecord r = login("GitHub", REVEALED_PASSWORD);
        FakeConsoleIo no = unlocking().line("n");
        assertEquals(ExitCodes.DENIED, run(no, "rm", "GitHub"));
        assertTrue(no.errText().contains(Messages.RM_CANCELLED.text()));
        assertSame(r, only());
        assertEquals(0, port.saves);

        FakeConsoleIo yes = unlocking().line("y");
        assertEquals(ExitCodes.OK, run(yes, "rm", "GitHub"), yes::errText);
        assertTrue(yes.outText().contains(Messages.RM_ITEM.text()) && yes.outText().contains(r.id().toString()));
        assertTrue(yes.outText().contains(Messages.REMOVED.text() + r.id()));
        assertEquals(List.of(), port.stored);
        assertEquals(1, port.saves);
        assertFalse(yes.outText().contains(REVEALED_PASSWORD));
    }

    @Test
    void rmYesSkipsThePromptAndAnSshKeyGetsTheAgentNote() {
        sshKey("laptop");
        FakeConsoleIo io = unlocking();
        assertEquals(ExitCodes.OK, run(io, "rm", "laptop", "--yes"), io::errText);
        assertTrue(io.outText().contains(Messages.RM_SSH_AGENT.text()), io::outText);
        assertEquals(List.of(), port.stored);
        login("GitHub", REVEALED_PASSWORD);
        FakeConsoleIo plain = unlocking();
        assertEquals(ExitCodes.OK, run(plain, "rm", "GitHub", "--yes"));
        assertFalse(plain.outText().contains(Messages.RM_SSH_AGENT.text()), "only for ssh keys");
        for (Messages m : List.of(Messages.RM_ITEM, Messages.RM_SSH_AGENT, Messages.RM_CONFIRM, Messages.RM_CANCELLED,
                Messages.REMOVED)) {
            assertFalse(m.text().contains("passkey"), "no passkey special case: " + m);
        }
    }

    // ---- wifi add ----------------------------------------------------------------------------

    @Test
    void wifiAddPromptsForThePskTwice() {
        FakeConsoleIo io = unlocking().secret(PSK).secret(PSK);
        assertEquals(ExitCodes.OK, run(io, "wifi", "add", "HomeNet", "--hidden", "--notes", "router in hall"),
                io::errText);
        WifiRecord r = (WifiRecord) only();
        assertEquals("HomeNet", r.ssid());
        assertEquals("HomeNet", r.title(), "the title defaults to the SSID");
        assertEquals(RecordCommands.DEFAULT_SECURITY, r.security());
        assertTrue(r.hidden());
        assertEquals("router in hall", r.notes());
        assertEquals(PSK, text(r.password()));
        assertEquals(NOW, r.created());
        assertTrue(io.outText().contains(Messages.WIFI_ADDED.text() + r.id()));
        assertFalse(io.outText().contains(PSK) || io.errText().contains(PSK));
        assertTrue(io.allSecretsZeroed());
        assertEquals(1, port.saves);
    }

    @Test
    void wifiAddOpenAsksForNoPskAndAMismatchAddsNothing() {
        FakeConsoleIo open = unlocking();
        assertEquals(ExitCodes.OK, run(open, "wifi", "add", "Cafe", "--security", "open", "--title", "Cafe wifi"),
                open::errText);
        assertEquals(1, open.secretsRead());
        WifiRecord r = (WifiRecord) only();
        assertEquals("OPEN", r.security());
        assertEquals("Cafe wifi", r.title());
        assertEquals(0, r.password().length());

        FakeConsoleIo mismatch = unlocking().secret(PSK).secret(PSK + "x");
        assertEquals(ExitCodes.USAGE, run(mismatch, "wifi", "add", "Other"));
        assertTrue(mismatch.errText().contains(Messages.PASSWORD_MISMATCH.text()));
        FakeConsoleIo bad = unlocking();
        assertEquals(ExitCodes.USAGE, run(bad, "wifi", "add", "Other", "--security", "TKIP"));
        assertTrue(bad.errText().contains(Messages.BAD_SECURITY.text()));
        assertEquals(1, port.stored.size());
        assertEquals(ExitCodes.USAGE, run(unlocking(), "wifi", "add"), "an SSID is required");
        assertEquals(ExitCodes.USAGE, run(unlocking(), "wifi"), "wifi needs a subcommand");
    }
}
