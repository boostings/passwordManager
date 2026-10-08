package pm.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.approval.AuditException;
import pm.approval.AuditLog;
import pm.crypto.Argon2Params;
import pm.crypto.SecretChars;
import pm.domain.env.Env;
import pm.tui.Session;
import pm.tui.lan.BrowserWindow;
import pm.tui.lan.Pairing;
import pm.vault.VaultException;
import pm.vault.record.LoginRecord;
import pm.vault.record.TrustedDeviceRecord;
import pm.vault.record.VaultRecord;

/**
 * M3.6 acceptance test: two vaults, each driven only through the {@code pm} commands over the real
 * file-backed stack, pair over loopback with the SAS confirmed by a typed {@code y} on both sides,
 * then one shares a login and the other receives it; the received item equals the original. A
 * revoked window lets nothing through (fail closed), an unpaired third vault is turned away, and
 * after {@code devices remove} the sender can no longer address that device. The waiting side of
 * each step runs on a second thread, as a second process would; the listening address reaches the
 * test through {@link Cli#withLanListener}.
 */
@Tag("T-LAN-01")
@Tag("T-LAN-02")
@Tag("T-LAN-06")
@Tag("T-LAN-08")
class LanEndToEndTest {
    private static final Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
    private static final String VAULT_PASSPHRASE = "correct horse lan e2e";
    private static final String LOGIN_SECRET = "lan-e2e-login-secret-77c1";
    private static final String TITLE = "GitHub";
    private static final String LOOPBACK = InetAddress.getLoopbackAddress().getHostAddress();
    private static final Duration WAIT = Duration.ofSeconds(30);

    @TempDir
    Path tmp;

    private Path alice;
    private Path bob;
    private Path carol;
    private Env runtime;
    /** What every pm run sees as now; fixed unless a test lets it move. */
    private Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    @BeforeEach
    void vaults() throws IOException {
        alice = tmp.resolve("a").resolve("vault.pmv");
        bob = tmp.resolve("b").resolve("vault.pmv");
        carol = tmp.resolve("c").resolve("vault.pmv");
        Path xdg = Files.createDirectory(tmp.resolve("xdg"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        runtime = Env.of(Map.of("XDG_RUNTIME_DIR", xdg.toString()));
        for (Path v : List.of(alice, bob, carol)) {
            assertEquals(ExitCodes.OK, run(v, "x", null, new FakeConsoleIo().secret(VAULT_PASSPHRASE).secret(VAULT_PASSPHRASE),
                    "init"));
        }
        FakeConsoleIo add = unlocking().line(TITLE).line("octocat").secret(LOGIN_SECRET).line("https://github.com")
                .line("dev");
        assertEquals(ExitCodes.OK, run(alice, "alice", null, add, "add-login"), add::errText);
    }

    @Test
    void pairShareReceiveRevokeAndRefuseAnUnpairedPeer() throws IOException, InterruptedException,
            ExecutionException, TimeoutException, VaultException, AuditException {
        pair();

        FakeConsoleIo devices = unlocking();
        assertEquals(ExitCodes.OK, run(alice, "alice", null, devices, "devices"), devices::errText);
        assertTrue(devices.outText().contains("pm bob"), devices::outText);
        String bobFingerprint = only(trusted(alice)).fingerprint();
        assertTrue(devices.outText().contains(bobFingerprint));
        assertEquals(bobFingerprint, ownFingerprint(bob), "each side pinned the key the other one holds");

        // An unpaired vault is turned away; the window stays open and the paired one then gets the item.
        LinkedBlockingQueue<String> listening = new LinkedBlockingQueue<>();
        FakeConsoleIo sender = unlocking().line("y");
        CompletableFuture<Integer> share = async(() -> run(alice, "alice", listening::add, sender,
                "share", TITLE, "--to", "pm bob", "--bind", LOOPBACK));
        String address = take(listening);
        FakeConsoleIo stranger = unlocking().line("y");
        assertEquals(ExitCodes.NOT_DONE, run(carol, "carol", null, stranger, "receive", address), stranger::errText);
        assertTrue(stranger.errText().contains(Messages.RECEIVE_UNREACHABLE.text()));
        assertEquals(List.of(), items(carol), "nothing reached the unpaired vault");

        FakeConsoleIo receiver = unlocking().line("y");
        assertEquals(ExitCodes.OK, run(bob, "bob", null, receiver, "receive", address), receiver::errText);
        assertEquals(ExitCodes.OK, share.get(WAIT.toSeconds(), TimeUnit.SECONDS), sender::errText);
        assertTrue(receiver.outText().contains("login: " + TITLE));
        assertTrue(sender.outText().contains(Messages.SHARE_DELIVERED.text()));
        assertTrue(sender.errText().contains(Messages.SHARE_REFUSED.text() + "1"), sender::errText);
        assertSameLogin(alice, bob);
        for (FakeConsoleIo io : List.of(sender, receiver, stranger, devices)) {
            assertFalse(io.outText().contains(LOGIN_SECRET) || io.errText().contains(LOGIN_SECRET), "no value printed");
        }

        // A revoked window sends nothing, and the share-id marker is gone.
        FakeConsoleIo second = unlocking().line("y");
        CompletableFuture<Integer> revoked = async(() -> run(alice, "alice", listening::add, second,
                "share", TITLE, "--to", "pm bob", "--bind", LOOPBACK));
        String secondAddress = take(listening);
        String id = shareId();
        FakeConsoleIo revoke = new FakeConsoleIo();
        assertEquals(ExitCodes.OK, run(alice, "alice", null, revoke, "revoke", id), revoke::errText);
        assertEquals(ExitCodes.NOT_DONE, revoked.get(WAIT.toSeconds(), TimeUnit.SECONDS), second::errText);
        assertTrue(second.errText().contains(Messages.SHARE_REVOKED.text()));
        FakeConsoleIo late = unlocking().line("y");
        assertEquals(ExitCodes.NOT_DONE, run(bob, "bob", null, late, "receive", secondAddress));
        assertEquals(1, items(bob).size(), "the revoked share added nothing");
        assertEquals(ExitCodes.USAGE, run(alice, "alice", null, new FakeConsoleIo(), "revoke", id), "already gone");

        // Removing the device lists what to rotate; it can no longer be addressed.
        FakeConsoleIo remove = unlocking();
        assertEquals(ExitCodes.OK, run(alice, "alice", null, remove, "devices", "remove", "pm bob"), remove::errText);
        assertTrue(remove.outText().contains(Messages.ROTATE_CHECKLIST.text()));
        assertTrue(remove.outText().contains("[ ] login: " + TITLE), remove::outText);
        assertEquals(List.of(), trusted(alice));
        FakeConsoleIo gone = unlocking();
        assertEquals(ExitCodes.USAGE, run(alice, "alice", null, gone, "share", TITLE, "--to", "pm bob"));
        assertTrue(gone.errText().contains(Messages.NO_SUCH_DEVICE.text()));

        Path log = alice.resolveSibling(AuditLog.FILE_NAME);
        assertEquals(7, AuditLog.check(log), "pair, two approvals, two share outcomes, revoke, remove");
        String audit = Files.readAllLines(log, StandardCharsets.US_ASCII).stream()
                .map(l -> new String(Base64.getDecoder().decode(l), StandardCharsets.ISO_8859_1))
                .collect(Collectors.joining("\n"));
        for (String entry : List.of("pair", "PAIRED", "approval", "ALLOWED_ONCE", "DELIVERED", "revoke", "REVOKED",
                "REMOVED")) {
            assertTrue(audit.contains(entry), entry);
        }
        assertFalse(audit.contains(LOGIN_SECRET), "the audit log never holds the value");
    }

    @Test
    void browserShareShowsTheUrlFingerprintAndWarningsAndIsRevocable() throws IOException, InterruptedException,
            ExecutionException, TimeoutException {
        LinkedBlockingQueue<String> listening = new LinkedBlockingQueue<>();
        FakeConsoleIo sender = unlocking().line("y");
        CompletableFuture<Integer> share = async(() -> run(alice, "alice", listening::add, sender,
                "share", TITLE, "--browser", "--ttl", "5m", "--bind", LOOPBACK));
        String url = take(listening);
        assertTrue(url.startsWith("https://127.0.0.1:"), url);
        assertEquals(ExitCodes.OK, run(alice, "alice", null, new FakeConsoleIo(), "revoke", shareId()));
        assertEquals(ExitCodes.NOT_DONE, share.get(WAIT.toSeconds(), TimeUnit.SECONDS), sender::errText);
        String out = sender.outText();
        for (String warning : BrowserWindow.WARNINGS) {
            assertTrue(out.contains(warning), warning);
        }
        assertTrue(out.contains(Messages.BROWSER_URL.text() + url));
        assertTrue(out.contains(Messages.SHARE_FOR.text() + "5m"), out);
        assertFalse(out.contains("PT5M"), "the time to live is not printed as ISO 8601");
        assertTrue(out.indexOf(Messages.SHARE_CONFIRM.text()) > out.indexOf(BrowserWindow.WARNINGS.get(0)),
                "the warnings come before the approval");
        assertTrue(out.lines().anyMatch(l -> l.startsWith(Messages.BROWSER_FINGERPRINT.text())
                && l.substring(Messages.BROWSER_FINGERPRINT.text().length()).matches("([0-9A-F]{2}:){31}[0-9A-F]{2}")),
                out);
        assertFalse(out.contains(LOGIN_SECRET), "the value itself is never printed");
    }

    @Test
    void anAuditFailureAfterPinningSaysTheDeviceWasPaired() throws IOException, InterruptedException,
            ExecutionException, TimeoutException, VaultException {
        // A directory where bob's audit log belongs: the append fails after the device is pinned.
        Files.createDirectory(bob.resolveSibling(AuditLog.FILE_NAME));
        LinkedBlockingQueue<String> listening = new LinkedBlockingQueue<>();
        FakeConsoleIo responder = unlocking().line("y");
        CompletableFuture<Integer> listen = async(() -> run(alice, "alice", listening::add, responder,
                "pair", "--listen", "--bind", LOOPBACK));
        String address = take(listening);
        FakeConsoleIo initiator = unlocking().line("y");
        assertEquals(ExitCodes.NOT_AUDITED, run(bob, "bob", null, initiator, "pair", address));
        assertEquals(ExitCodes.OK, listen.get(WAIT.toSeconds(), TimeUnit.SECONDS), responder::errText);
        assertTrue(initiator.errText().contains(Messages.PAIRED_AUDIT_FAILED.text()), initiator::errText);
        assertFalse(initiator.errText().contains(Messages.AUDIT_UNAVAILABLE.text()), "nothing was exported is untrue");
        assertEquals(1, trusted(bob).size(), "the device was paired");
    }

    @Test
    void anAuditFailureAfterAChangeSaysWhatHappenedAndExitsNotAudited() throws IOException, InterruptedException,
            ExecutionException, TimeoutException, VaultException {
        pair();
        // Bob's audit log is a directory: the item is saved, then its entry cannot be written.
        breakAuditLog(bob);
        LinkedBlockingQueue<String> listening = new LinkedBlockingQueue<>();
        FakeConsoleIo sender = unlocking().line("y");
        CompletableFuture<Integer> share = async(() -> run(alice, "alice", listening::add, sender,
                "share", TITLE, "--to", "pm bob", "--bind", LOOPBACK));
        String address = take(listening);
        FakeConsoleIo receiver = unlocking().line("y");
        assertEquals(ExitCodes.NOT_AUDITED, run(bob, "bob", null, receiver, "receive", address), receiver::errText);
        assertEquals(ExitCodes.OK, share.get(WAIT.toSeconds(), TimeUnit.SECONDS), sender::errText);
        assertTrue(receiver.errText().contains(Messages.RECEIVED_AUDIT_FAILED.text()), receiver::errText);
        assertEquals(1, items(bob).size(), "the message is true: it was received and saved");

        // Alice's log breaks while a window is open: the revoke stands, the window closes.
        FakeConsoleIo second = unlocking().line("y");
        CompletableFuture<Integer> revoked = async(() -> run(alice, "alice", listening::add, second,
                "share", TITLE, "--to", "pm bob", "--bind", LOOPBACK));
        take(listening);
        String id = shareId();
        breakAuditLog(alice);
        FakeConsoleIo revoke = new FakeConsoleIo();
        assertEquals(ExitCodes.NOT_AUDITED, run(alice, "alice", null, revoke, "revoke", id), revoke::errText);
        assertTrue(revoke.errText().contains(Messages.REVOKED_AUDIT_FAILED.text()), revoke::errText);
        assertTrue(revoke.outText().contains(Messages.REVOKED.text()), revoke::outText);
        assertEquals(ExitCodes.NOT_DONE, revoked.get(WAIT.toSeconds(), TimeUnit.SECONDS), second::errText);
        assertTrue(second.errText().contains(Messages.SHARE_CLOSED_AUDIT_FAILED.text()), second::errText);

        // Removing a device is audited first: with no log it is not removed, and says so.
        FakeConsoleIo remove = unlocking();
        assertEquals(ExitCodes.USAGE, run(alice, "alice", null, remove, "devices", "remove", "pm bob"));
        assertTrue(remove.errText().contains(Messages.REMOVE_AUDIT_UNAVAILABLE.text()), remove::errText);
        assertEquals(1, trusted(alice).size(), "the message is true: the device is still paired");
    }

    @Test
    void aRejectedCodePinsNothing() throws InterruptedException, ExecutionException, TimeoutException,
            VaultException {
        LinkedBlockingQueue<String> listening = new LinkedBlockingQueue<>();
        FakeConsoleIo responder = unlocking().line("y").line("y");
        CompletableFuture<Integer> listen = async(() -> run(alice, "alice", listening::add, responder,
                "pair", "--listen", "--bind", LOOPBACK));
        String address = take(listening);
        FakeConsoleIo initiator = unlocking().line("n");
        assertEquals(ExitCodes.NOT_DONE, run(bob, "bob", null, initiator, "pair", address), initiator::errText);
        assertTrue(initiator.outText().contains(Messages.PAIR_CODE.text()));
        assertEquals(List.of(), trusted(bob));
        // The responder keeps its window open for another attempt; this one matches.
        FakeConsoleIo retry = unlocking().line("y");
        assertEquals(ExitCodes.OK, run(bob, "bob", null, retry, "pair", address), retry::errText);
        assertEquals(ExitCodes.OK, listen.get(WAIT.toSeconds(), TimeUnit.SECONDS), responder::errText);
        assertTrue(responder.errText().contains(Messages.PAIR_FAILED.text()), responder::errText);
        assertEquals(1, trusted(alice).size());
        assertEquals(1, trusted(bob).size());
    }

    @Test
    void removingADeviceInAnotherProcessClosesAWindowAlreadyOpenToIt() throws IOException, InterruptedException,
            ExecutionException, TimeoutException, VaultException {
        pair();
        LinkedBlockingQueue<String> listening = new LinkedBlockingQueue<>();
        FakeConsoleIo sender = unlocking().line("y");
        CompletableFuture<Integer> share = async(() -> run(alice, "alice", listening::add, sender,
                "share", TITLE, "--to", "pm bob", "--bind", LOOPBACK));
        String address = take(listening);

        // A second pm process (its own Cli, sharing only the run directory and the vault file).
        FakeConsoleIo remove = unlocking();
        assertEquals(ExitCodes.OK, run(alice, "alice", null, remove, "devices", "remove", "pm bob"), remove::errText);
        assertTrue(remove.outText().contains(Messages.DEVICE_REMOVED.text()), remove::outText);

        FakeConsoleIo receiver = unlocking().line("y");
        assertEquals(ExitCodes.NOT_DONE, run(bob, "bob", null, receiver, "receive", address), receiver::errText);
        assertEquals(ExitCodes.NOT_DONE, share.get(WAIT.toSeconds(), TimeUnit.SECONDS), sender::errText);
        assertTrue(sender.errText().contains(Messages.SHARE_REVOKED.text()), sender::errText);
        assertEquals(List.of(), items(bob), "the removed device got nothing from the window opened before");
        assertFalse(receiver.outText().contains("login: " + TITLE), "not even the offer");
    }

    @Test
    void thePairingLockoutHoldsForTheNextPairInvocation() throws InterruptedException, ExecutionException,
            TimeoutException, VaultException {
        Ticking ticking = new Ticking(NOW);
        clock = ticking;
        LinkedBlockingQueue<String> listening = new LinkedBlockingQueue<>();
        FakeConsoleIo responder = unlocking().line("y").line("y").line("y");
        CompletableFuture<Integer> listen = async(() -> run(alice, "alice", listening::add, responder,
                "pair", "--listen", "--bind", LOOPBACK));
        String address = take(listening);
        for (int i = 0; i <= pm.sharing.pair.Lockout.FREE_FAILURES; i++) {
            FakeConsoleIo wrong = unlocking().line("n");
            assertEquals(ExitCodes.NOT_DONE, run(bob, "bob", null, wrong, "pair", address), wrong::errText);
        }
        String failures = responder.errText();
        // A new pm pair --listen in another process (here on the user's other vault, as the first
        // one still holds alice's) starts locked instead of afresh.
        FakeConsoleIo again = unlocking();
        assertEquals(ExitCodes.NOT_DONE, run(carol, "carol", listening::add, again, "pair", "--listen",
                "--bind", LOOPBACK), again::errText);
        assertTrue(again.errText().contains(Messages.PAIR_LOCKED.text() + "60"), again::errText);
        assertTrue(listening.isEmpty(), "it did not even listen");
        FakeConsoleIo initiator = unlocking().line("y");
        assertEquals(ExitCodes.NOT_DONE, run(bob, "bob", null, initiator, "pair", address));
        assertTrue(initiator.errText().contains(Messages.PAIR_LOCKED.text()), initiator::errText);

        ticking.advance(Pairing.DEFAULT_WINDOW);
        assertEquals(ExitCodes.NOT_DONE, listen.get(WAIT.toSeconds(), TimeUnit.SECONDS), responder::errText);
        assertTrue(failures.contains(Messages.PAIR_FAILED.text()), failures);
        assertEquals(List.of(), trusted(alice));
        assertEquals(List.of(), trusted(bob));
    }

    @Test
    void removalReachesAWindowOpenedUnderAnotherRunDirectory() throws InterruptedException, ExecutionException,
            TimeoutException, VaultException {
        pair();
        // The sender runs with XDG_RUNTIME_DIR set, the remover without it (an ssh, cron or sudo shell).
        assertRemovalCloses(runtime, alice, Env.of(Map.of()));
    }

    @Test
    void removalReachesAWindowOpenedThroughALinkToTheVault() throws IOException, InterruptedException,
            ExecutionException, TimeoutException, VaultException {
        pair();
        // The vault refuses a linked file, so the link is the directory: the sender names the vault
        // as link/vault.pmv, the remover by its real path. No XDG anywhere.
        Path linkDir = Files.createSymbolicLink(tmp.resolve("link"), alice.getParent());
        assertRemovalCloses(Env.of(Map.of()), linkDir.resolve(alice.getFileName()), Env.of(Map.of()));
    }

    @Test
    void aConcurrentPairingNeverWeakensThePersistedLockout() throws IOException, InterruptedException,
            ExecutionException, TimeoutException, VaultException {
        Ticking ticking = new Ticking(NOW);
        clock = ticking;
        Path dave = tmp.resolve("d").resolve("vault.pmv");
        assertEquals(ExitCodes.OK, run(dave, "x", null, new FakeConsoleIo().secret(VAULT_PASSPHRASE)
                .secret(VAULT_PASSPHRASE), "init"));
        // L1 starts first, from a clean state; L2 (the user's other vault) is then locked.
        LinkedBlockingQueue<String> l1 = new LinkedBlockingQueue<>();
        FakeConsoleIo r1 = unlocking().line("y").line("y").line("y").line("y");
        CompletableFuture<Integer> first = async(() -> run(alice, "alice", l1::add, r1,
                "pair", "--listen", "--bind", LOOPBACK));
        String a1 = take(l1);
        LinkedBlockingQueue<String> l2 = new LinkedBlockingQueue<>();
        FakeConsoleIo r2 = unlocking().line("y").line("y").line("y").line("y");
        CompletableFuture<Integer> second = async(() -> run(carol, "carol", l2::add, r2,
                "pair", "--listen", "--bind", LOOPBACK));
        String a2 = take(l2);
        // The attackers are other machines, each with its own run directory (and so its own lockout).
        for (int i = 0; i <= pm.sharing.pair.Lockout.FREE_FAILURES; i++) {
            failOnce(remote("m" + i), a2);
        }
        // L1 still holds its stale clean state; one failure there must not write it back.
        failOnce(remote("m-last"), a1);
        long deadline = System.nanoTime() + WAIT.toNanos();
        while (!r1.errText().contains(Messages.PAIR_FAILED.text()) && System.nanoTime() < deadline) {
            TimeUnit.MILLISECONDS.sleep(20); // L1 saves before it reports the failure
        }
        assertTrue(r1.errText().contains(Messages.PAIR_FAILED.text()), () -> "L1: " + r1.errText());
        Path lockout = tmp.resolve("xdg").resolve("pm").resolve(pm.tui.lan.LanState.LOCKOUT_FILE);
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(lockout));
        String[] stored = Files.readString(lockout).strip().split(" ");
        assertTrue(Integer.parseInt(stored[1]) > pm.sharing.pair.Lockout.FREE_FAILURES, String.join(" ", stored));
        assertTrue(Long.parseLong(stored[2]) > NOW.getEpochSecond(), "the lock L2 set is kept");

        LinkedBlockingQueue<String> l3 = new LinkedBlockingQueue<>();
        FakeConsoleIo again = unlocking();
        assertEquals(ExitCodes.NOT_DONE, run(dave, "dave", l3::add, again, "pair", "--listen", "--bind", LOOPBACK),
                again::errText);
        assertTrue(again.errText().contains(Messages.PAIR_LOCKED.text()), () -> "L3: " + again.errText());
        assertTrue(l3.isEmpty(), "a new listener is still locked");

        ticking.advance(Pairing.DEFAULT_WINDOW);
        assertEquals(ExitCodes.NOT_DONE, first.get(WAIT.toSeconds(), TimeUnit.SECONDS), r1::errText);
        assertEquals(ExitCodes.NOT_DONE, second.get(WAIT.toSeconds(), TimeUnit.SECONDS), r2::errText);
        assertEquals(List.of(), trusted(alice));
        assertEquals(List.of(), trusted(carol));
    }

    // ---- helpers -----------------------------------------------------------------------------

    /**
     * Opens a share to bob from {@code senderVault} in a process with {@code senderEnv}, removes bob
     * from the real vault path in a process with {@code removerEnv}, and checks bob gets nothing.
     */
    private void assertRemovalCloses(Env senderEnv, Path senderVault, Env removerEnv) throws InterruptedException,
            ExecutionException, TimeoutException, VaultException {
        LinkedBlockingQueue<String> listening = new LinkedBlockingQueue<>();
        FakeConsoleIo sender = unlocking().line("y");
        CompletableFuture<Integer> share = async(() -> runEnv(senderEnv, senderVault, "alice", listening::add,
                sender, "share", TITLE, "--to", "pm bob", "--ttl", "10m", "--bind", LOOPBACK));
        String address = listening.poll(WAIT.toSeconds(), TimeUnit.SECONDS);
        if (address == null) {
            fail("the share did not open: " + sender.errText() + sender.outText());
        }
        FakeConsoleIo remove = unlocking();
        assertEquals(ExitCodes.OK, runEnv(removerEnv, alice, "alice", null, remove, "devices", "remove", "pm bob"),
                remove::errText);
        assertTrue(remove.outText().contains(Messages.DEVICE_REMOVED.text()), remove::outText);
        FakeConsoleIo receiver = unlocking().line("y");
        assertEquals(ExitCodes.NOT_DONE, run(bob, "bob", null, receiver, "receive", address), receiver::errText);
        assertEquals(ExitCodes.NOT_DONE, share.get(WAIT.toSeconds(), TimeUnit.SECONDS), sender::errText);
        assertEquals(List.of(), items(bob), "the removed device got nothing from the window opened before");
        assertFalse(receiver.outText().contains("login: " + TITLE), "not even the offer");
    }

    /** The environment of a pm process on another machine called {@code name}. */
    private Env remote(String name) throws IOException {
        return Env.of(Map.of("XDG_RUNTIME_DIR", Files.createDirectory(tmp.resolve("xdg-" + name),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).toString()));
    }

    /** One pairing attempt from bob (environment {@code env}) against {@code address}; bob rejects the code. */
    private void failOnce(Env env, String address) {
        FakeConsoleIo wrong = unlocking().line("n");
        assertEquals(ExitCodes.NOT_DONE, runEnv(env, bob, "bob", null, wrong, "pair", address), wrong::errText);
        assertTrue(wrong.outText().contains(Messages.PAIR_CODE.text()), "a ceremony took place");
    }


    /** Puts a directory where {@code vault}'s audit log belongs, so every append fails. */
    private static void breakAuditLog(Path vault) throws IOException {
        Path log = vault.resolveSibling(AuditLog.FILE_NAME);
        if (Files.exists(log)) {
            Files.move(log, log.resolveSibling(AuditLog.FILE_NAME + ".moved"));
        }
        Files.createDirectory(log);
    }

    private void pair() throws InterruptedException, ExecutionException, TimeoutException {
        LinkedBlockingQueue<String> listening = new LinkedBlockingQueue<>();
        FakeConsoleIo responder = unlocking().line("y");
        CompletableFuture<Integer> listen = async(() -> run(alice, "alice", listening::add, responder,
                "pair", "--listen", "--bind", LOOPBACK));
        String address = take(listening);
        FakeConsoleIo initiator = unlocking().line("y");
        assertEquals(ExitCodes.OK, run(bob, "bob", null, initiator, "pair", address), initiator::errText);
        assertEquals(ExitCodes.OK, listen.get(WAIT.toSeconds(), TimeUnit.SECONDS), responder::errText);
        String code = codeOf(initiator);
        assertEquals(code, codeOf(responder), "both screens showed the same code");
        assertTrue(initiator.outText().contains(Messages.PAIRED.text() + "pm alice"));
        assertTrue(responder.outText().contains(Messages.PAIRED.text() + "pm bob"));
    }

    /** A clock the test moves forward; read from the worker threads too. */
    private static final class Ticking extends Clock {
        private final java.util.concurrent.atomic.AtomicReference<Instant> now;

        Ticking(Instant start) {
            now = new java.util.concurrent.atomic.AtomicReference<>(start);
        }

        void advance(Duration by) {
            now.updateAndGet(t -> t.plus(by));
        }

        @Override
        public Instant instant() {
            return now.get();
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }

    private static String codeOf(FakeConsoleIo io) {
        return io.outText().lines().filter(l -> l.startsWith(Messages.PAIR_CODE.text())).findFirst()
                .orElseThrow(() -> new AssertionError(io.outText()));
    }

    private String shareId() throws IOException, InterruptedException {
        Path run = tmp.resolve("xdg").resolve("pm");
        long deadline = System.nanoTime() + WAIT.toNanos();
        while (System.nanoTime() < deadline) {
            if (Files.isDirectory(run)) {
                try (Stream<Path> files = Files.list(run)) {
                    List<String> ids = files.map(p -> String.valueOf(p.getFileName()))
                            .filter(n -> n.startsWith(LanCommands.MARKER_PREFIX))
                            .map(n -> n.substring(LanCommands.MARKER_PREFIX.length())).toList();
                    if (!ids.isEmpty()) {
                        return ids.get(0);
                    }
                }
            }
            TimeUnit.MILLISECONDS.sleep(20);
        }
        throw new AssertionError("no share marker appeared");
    }

    private static String take(LinkedBlockingQueue<String> queue) throws InterruptedException {
        String value = queue.poll(WAIT.toSeconds(), TimeUnit.SECONDS);
        if (value == null) {
            fail("nothing started listening");
        }
        return value;
    }

    private static <T> CompletableFuture<T> async(java.util.function.Supplier<T> step) {
        return CompletableFuture.supplyAsync(step);
    }

    private static FakeConsoleIo unlocking() {
        return new FakeConsoleIo().secret(VAULT_PASSPHRASE);
    }

    private int run(Path vault, String user, java.util.function.Consumer<String> listening, FakeConsoleIo io,
            String... command) {
        return runEnv(runtime, vault, user, listening, io, command);
    }

    /** As {@link #run}, for a pm process started with the environment {@code env}. */
    private int runEnv(Env env, Path vault, String user, java.util.function.Consumer<String> listening,
            FakeConsoleIo io, String... command) {
        Cli cli = new Cli(Map.of("user.name", user)::get, clock, port -> fail("never launches the TUI"))
                .withEnvironment(env);
        if (listening != null) {
            cli.withLanListener(listening);
        }
        List<String> args = new ArrayList<>(List.of("--vault", vault.toString()));
        args.addAll(List.of(command));
        return cli.run(args.toArray(String[]::new), io,
                (path, creating) -> new FileVaultPort(path, clock, Cli.kdfFor(creating, () -> Argon2Params.FLOOR)));
    }

    /** Opens {@code vault} directly and runs {@code read} on its records. */
    private static <T> T read(Path vault, java.util.function.Function<List<VaultRecord>, T> read)
            throws VaultException {
        FileVaultPort port = new FileVaultPort(vault, Clock.fixed(NOW, ZoneOffset.UTC), Argon2Params.FLOOR);
        try (Session session = port.unlockWithPassphrase(SecretChars.takeOwnership(VAULT_PASSPHRASE.toCharArray()))) {
            return read.apply(session.records());
        }
    }

    private static List<String> items(Path vault) throws VaultException {
        return read(vault, rs -> rs.stream().filter(LoginRecord.class::isInstance).map(VaultRecord::title).toList());
    }

    private static List<TrustedDeviceRecord> trusted(Path vault) throws VaultException {
        return read(vault, rs -> rs.stream().filter(TrustedDeviceRecord.class::isInstance)
                .map(TrustedDeviceRecord.class::cast).toList());
    }

    private static String ownFingerprint(Path vault) throws VaultException {
        return read(vault, rs -> rs.stream().filter(pm.vault.record.DeviceIdentityRecord.class::isInstance)
                .map(pm.vault.record.DeviceIdentityRecord.class::cast)
                .map(r -> pm.tui.lan.Devices.fingerprint(r).orElseThrow()).findFirst().orElseThrow());
    }

    private static <T> T only(List<T> list) {
        assertEquals(1, list.size());
        return list.get(0);
    }

    /** The received login equals the original in every field but its id. */
    private static void assertSameLogin(Path from, Path to) throws VaultException {
        List<String> original = read(from, LanEndToEndTest::login);
        List<String> copy = read(to, LanEndToEndTest::login);
        assertEquals(original.subList(1, original.size()), copy.subList(1, copy.size()));
        assertNotEquals(original.get(0), copy.get(0), "the copy has its own id");
        assertEquals(LOGIN_SECRET, copy.get(3));
    }

    @SuppressWarnings("PMD.CloseResource") // CE-035: records are the session's, closed by read
    private static List<String> login(List<VaultRecord> records) {
        LoginRecord l = records.stream().filter(LoginRecord.class::isInstance).map(LoginRecord.class::cast)
                .findFirst().orElseThrow();
        return List.of(l.id().toString(), l.title(), l.username(),
                l.password().apply(b -> new String(b, StandardCharsets.UTF_8)), l.urls().toString(),
                l.notes(), l.tags().toString());
    }
}
