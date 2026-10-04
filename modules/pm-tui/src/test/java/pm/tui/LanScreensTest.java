package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.googlecode.lanterna.input.KeyType;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.tui.lan.BrowserWindow;
import pm.vault.record.DeviceIdentityRecord;
import pm.vault.record.LoginRecord;
import pm.vault.record.TrustedDeviceRecord;
import pm.vault.record.VaultRecord;

/**
 * The Devices screen and the Share dialog, end to end between two TUIs over loopback (M3.6): pair
 * with Yes on both screens, share the GitHub login to the paired device after approval, receive it
 * after accepting the offer, revoke and lock fail closed. Each harness pumps its own GUI; network
 * steps run on the controller's worker threads, so the test pumps both until the expected state.
 */
@Tag("T-LAN-01")
@Tag("T-LAN-02")
@Tag("T-LAN-08")
class LanScreensTest {
    private static final String VAULT_PASSPHRASE = "lan screens passphrase";
    private static final String RECOVERY = "lan screens recovery";
    private static final Duration WAIT = Duration.ofSeconds(30);

    private TuiHarness alice;
    private TuiHarness bob;

    @BeforeEach
    void open() throws IOException {
        alice = harness();
        bob = harness();
    }

    @AfterEach
    void close() {
        alice.controller.lock();
        bob.controller.lock();
    }

    @Test
    void ctrlDOpensDevicesAndCtrlSSharesTheSelectedItem() {
        alice.ctrl('d');
        DevicesWindow devices = alice.controller.shownForm(DevicesWindow.class);
        assertTrue(alice.screenText().contains(DevicesWindow.TITLE), alice::screenText);
        assertTrue(alice.screenText().contains(DevicesWindow.THIS_DEVICE), alice::screenText);
        assertTrue(devices.statusText().contains(DevicesWindow.NO_DEVICES), devices::statusText);
        alice.press(KeyType.Escape);
        alice.ctrl('s');
        ShareDialog share = alice.controller.shownForm(ShareDialog.class);
        assertTrue(alice.screenText().contains(ShareDialog.NO_DEVICES.substring(0, 40)), alice::screenText);
        share.press(ShareDialog.TO_DEVICE);
        alice.pump();
        assertTrue(alice.screenText().contains(ShareDialog.SELECT_DEVICE), alice::screenText);
        assertFalse(alice.screenText().contains(FakeVaultPort.LOGIN_SECRET));
        long identities = session(alice).records().stream().filter(DeviceIdentityRecord.class::isInstance).count();
        assertEquals(0, identities, "the device identity is created on first use, not by looking");
        alice.press(KeyType.Escape);
        assertFalse(alice.screenText().contains(DevicesWindow.THIS_DEVICE), alice::screenText);
        assertEquals(3, alice.screenText().lines().filter(l -> l.contains("2026-10-01")).count(),
                "the identity is not a dashboard row");
    }

    @Test
    @SuppressWarnings("PMD.CloseResource") // CE-035: records are the fake session's
    void pairShareReceiveAndRevokeBetweenTwoScreens() throws InterruptedException {
        pair();

        // Share the selected login to bob, after approval.
        LoginRecord original = login(alice);
        alice.controller.openShare(original);
        alice.pump();
        ShareDialog share = alice.controller.shownForm(ShareDialog.class);
        share.select(0);
        share.press(ShareDialog.TO_DEVICE);
        alice.pump();
        assertTrue(alice.screenText().contains(ShareDialog.APPROVE));
        share.press(ShareDialog.APPROVE);
        until(() -> share.statusText().contains(ShareDialog.OPEN));
        String address = afterLast(share.statusText(), ShareDialog.OPEN);

        DevicesWindow receiving = devices(bob);
        receiving.address(address);
        receiving.press(DevicesWindow.RECEIVE_BUTTON);
        until(receiving::asking);
        assertTrue(receiving.statusText().contains(DevicesWindow.OFFER_FROM), receiving::statusText);
        receiving.answer(true);
        until(() -> receiving.statusText().contains(DevicesWindow.RECEIVED));
        until(() -> share.statusText().contains(ShareDialog.DELIVERED));
        LoginRecord copy = login(bob);
        assertNotEquals(original.id(), copy.id());
        assertEquals(original.title(), copy.title());
        assertEquals(original.username(), copy.username());
        assertEquals(FakeVaultPort.LOGIN_SECRET, copy.password().apply(b -> new String(b, StandardCharsets.UTF_8)));
        assertEquals(List.of(original.id()), trusted(alice).shared(), "remembered for the rotate checklist");

        // A revoked window sends nothing.
        long before = logins(bob);
        share.press(ShareDialog.TO_DEVICE);
        alice.pump();
        share.press(ShareDialog.APPROVE);
        until(() -> share.statusText().contains(ShareDialog.OPEN) && share.windowOpen());
        String second = afterLast(share.statusText(), ShareDialog.OPEN);
        share.press(ShareDialog.REVOKE_BUTTON);
        until(() -> share.statusText().contains(ShareDialog.REVOKED));
        receiving.address(second);
        receiving.press(DevicesWindow.RECEIVE_BUTTON);
        until(() -> receiving.statusText().contains(DevicesWindow.UNREACHABLE));
        assertEquals(before, logins(bob), "nothing more arrived");

        // Removing the device shows what to rotate and unpins it.
        alice.press(KeyType.Escape);
        DevicesWindow removing = devices(alice);
        removing.select(0);
        removing.press(DevicesWindow.REMOVE_BUTTON);
        alice.pump();
        assertTrue(removing.asking());
        removing.answer(true);
        alice.pump();
        assertTrue(removing.statusText().contains(DevicesWindow.ROTATE), removing::statusText);
        assertTrue(removing.statusText().contains("login: GitHub"), removing::statusText);
        assertTrue(session(alice).records().stream().noneMatch(TrustedDeviceRecord.class::isInstance));
    }

    @Test
    void aBrowserLinkShowsTheWarningsUrlAndFingerprintAndLockRevokesIt() throws InterruptedException {
        alice.controller.openShare(login(alice));
        alice.pump();
        ShareDialog share = alice.controller.shownForm(ShareDialog.class);
        share.press(ShareDialog.BROWSER);
        alice.pump();
        share.press(ShareDialog.APPROVE);
        until(share::windowOpen);
        String status = share.statusText();
        for (String warning : BrowserWindow.WARNINGS) {
            assertTrue(status.contains(warning), warning);
        }
        assertTrue(status.contains(ShareDialog.URL + "https://127.0.0.1:"), status);
        assertTrue(status.contains(ShareDialog.FINGERPRINT), status);
        assertFalse(status.contains(FakeVaultPort.LOGIN_SECRET));
        String url = afterLast(status, ShareDialog.URL);
        int port = Integer.parseInt(url.substring("https://127.0.0.1:".length(), url.indexOf('/', "https://".length())));
        alice.controller.lock();
        alice.pump();
        until(() -> refuses(port));
    }

    @Test
    void aRejectedCodePinsNothingAndADeniedShareSendsNothing() throws InterruptedException {
        DevicesWindow waiting = devices(alice);
        waiting.press(DevicesWindow.PAIR_HERE);
        until(() -> waiting.statusText().contains(DevicesWindow.WAITING));
        DevicesWindow joining = devices(bob);
        joining.address(afterLast(waiting.statusText(), DevicesWindow.WAITING));
        joining.press(DevicesWindow.PAIR_WITH);
        until(() -> waiting.asking() && joining.asking());
        joining.answer(false);
        waiting.answer(true);
        until(() -> joining.statusText().contains(DevicesWindow.NOT_PAIRED)
                || joining.statusText().contains(DevicesWindow.PAIR_FAILED));
        assertTrue(session(bob).records().stream().noneMatch(TrustedDeviceRecord.class::isInstance));
        alice.press(KeyType.Escape);
        assertTrue(session(alice).records().stream().noneMatch(TrustedDeviceRecord.class::isInstance));

        alice.controller.openShare(login(alice));
        alice.pump();
        ShareDialog share = alice.controller.shownForm(ShareDialog.class);
        share.press(ShareDialog.BROWSER);
        alice.pump();
        share.press(ShareDialog.DENY);
        alice.pump();
        assertTrue(share.statusText().contains(ShareDialog.DENIED), share::statusText);
        assertFalse(share.windowOpen());
    }

    @Test
    void anAnswerOnlyReachesTheQuestionOnScreenAndASecondOneWaits() throws InterruptedException {
        pair();
        DevicesWindow w = devices(alice);
        w.select(0);
        w.press(DevicesWindow.REMOVE_BUTTON);
        alice.pump();
        assertTrue(w.statusText().startsWith(DevicesWindow.REMOVE_ASK), w::statusText);

        // A pairing code arrives from a worker while Remove is still asked: it waits its turn.
        String sas = "Same code on both screens? 123 456";
        CompletableFuture<Boolean> confirm = w.queueQuestion(sas);
        alice.pump();
        assertTrue(w.statusText().startsWith(DevicesWindow.REMOVE_ASK), "the code is not shown yet");
        w.answer(true); // the user was looking at Remove, so Yes removes and never confirms the code
        alice.pump();
        assertFalse(confirm.isDone(), "a Yes meant for Remove never confirms a code");
        assertTrue(session(alice).records().stream().noneMatch(TrustedDeviceRecord.class::isInstance));
        assertTrue(w.asking());
        assertEquals(sas, w.statusText(), "the code shows only now");

        // While the code waits, no other question or step can take the Yes and No buttons.
        w.press(DevicesWindow.PAIR_HERE);
        alice.pump();
        assertTrue(alice.screenText().contains(DevicesWindow.ANSWER_FIRST), alice::screenText);
        assertEquals(sas, w.statusText());
        w.answer(false);
        assertFalse(confirm.join(), "No reached the code it was shown with");
        assertFalse(w.asking());

        // A question its step gave up on leaves the queue unanswered.
        CompletableFuture<Boolean> abandoned = w.queueQuestion("first");
        CompletableFuture<Boolean> next = w.queueQuestion("second");
        abandoned.complete(false);
        w.answer(true);
        assertTrue(next.join(), "the answer went to the question still waiting");
    }

    // ---- helpers -----------------------------------------------------------------------------

    private void pair() throws InterruptedException {
        DevicesWindow waiting = devices(alice);
        waiting.press(DevicesWindow.PAIR_HERE);
        until(() -> waiting.statusText().contains(DevicesWindow.WAITING));
        DevicesWindow joining = devices(bob);
        joining.address(afterLast(waiting.statusText(), DevicesWindow.WAITING));
        joining.press(DevicesWindow.PAIR_WITH);
        until(() -> waiting.asking() && joining.asking());
        assertEquals(code(waiting), code(joining), "both screens show the same code");
        waiting.answer(true);
        joining.answer(true);
        until(() -> waiting.statusText().contains(DevicesWindow.PAIRED)
                && joining.statusText().contains(DevicesWindow.PAIRED));
        assertEquals(1, session(alice).records().stream().filter(TrustedDeviceRecord.class::isInstance).count());
        assertEquals(1, session(alice).records().stream().filter(DeviceIdentityRecord.class::isInstance).count(),
                "the device identity is kept in the vault");
        assertTrue(alice.screenText().contains(trusted(alice).fingerprint().substring(0, 8)), alice::screenText);
        alice.press(KeyType.Escape);
        bob.press(KeyType.Escape);
    }

    /** The six-digit code after {@link DevicesWindow#PAIR_CODE}. */
    private static String code(DevicesWindow w) {
        return afterLast(w.statusText(), DevicesWindow.PAIR_CODE);
    }

    /** Whether nothing accepts connections on loopback {@code port} any more. */
    private static boolean refuses(int port) {
        try (SocketChannel s = SocketChannel.open(new InetSocketAddress(InetAddress.getLoopbackAddress(), port))) {
            return !s.isConnected();
        } catch (IOException e) {
            return true;
        }
    }

    private static String afterLast(String text, String prefix) {
        int at = text.lastIndexOf(prefix);
        assertTrue(at >= 0, text);
        String rest = text.substring(at + prefix.length()).strip();
        return rest.split("[\\s,;]", 2)[0];
    }

    private static DevicesWindow devices(TuiHarness h) {
        h.controller.openDevices();
        h.pump();
        return h.controller.shownForm(DevicesWindow.class);
    }

    /** Pumps both GUIs until {@code done}, failing after {@link #WAIT}. */
    private void until(BooleanSupplier done) throws InterruptedException {
        long deadline = System.nanoTime() + WAIT.toNanos();
        while (true) {
            alice.pump();
            bob.pump();
            if (done.getAsBoolean()) {
                return;
            }
            if (System.nanoTime() > deadline) {
                throw new AssertionError("timed out\n" + alice.screenText() + "\n" + bob.screenText());
            }
            TimeUnit.MILLISECONDS.sleep(10);
        }
    }

    private static TuiHarness harness() throws IOException {
        TuiHarness h = new TuiHarness(new FakeVaultPort(VAULT_PASSPHRASE, RECOVERY));
        h.controller.useLanBind(InetAddress.getLoopbackAddress());
        h.unlockWith(VAULT_PASSPHRASE);
        return h;
    }

    private static FakeVaultPort.FakeSession session(TuiHarness h) {
        return h.port.last();
    }

    private static LoginRecord login(TuiHarness h) {
        return session(h).records().stream().filter(LoginRecord.class::isInstance).map(LoginRecord.class::cast)
                .reduce((a, b) -> b).orElseThrow();
    }

    private static long logins(TuiHarness h) {
        return session(h).records().stream().filter(LoginRecord.class::isInstance).count();
    }

    private static TrustedDeviceRecord trusted(TuiHarness h) {
        List<VaultRecord> pinned = session(h).records().stream().filter(TrustedDeviceRecord.class::isInstance)
                .toList();
        assertEquals(1, pinned.size());
        return (TrustedDeviceRecord) pinned.get(0);
    }
}
