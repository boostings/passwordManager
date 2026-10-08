package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TextCharacter;
import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.input.KeyType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.approval.ApprovalBroker;
import pm.approval.ApprovalRequest;
import pm.approval.AuditEvent;
import pm.approval.Decision;
import pm.approval.Grant;
import pm.approval.Outcome;
import pm.approval.PolicyStore;
import pm.approval.ipc.Releaser;
import pm.browser.bridge.Bridge;
import pm.browser.bridge.Origin;
import pm.browser.bridge.PasswordGenerator;
import pm.browser.bridge.VaultPort;
import pm.browser.host.HostException;
import pm.browser.host.Json;
import pm.browser.host.Messages;
import pm.browser.host.Request;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;

/**
 * ADR 0014 §8, SR-113: a browser request becomes a TUI prompt showing the exact origin and the
 * login, rendered terminal-safe; only an approval in the TUI releases a password, once per
 * approval; deny, timeout, a vanished host and a locked vault release nothing.
 */
@Tag("T-EXT-08")
@SuppressWarnings("PMD.DoNotUseThreads") // CE-002: the bridge runs on its own thread, as on a relay worker
class BrowserApprovalTest {
    private static final String UNLOCK_PHRASE = "canary-passphrase";
    private static final String EXTENSION = "abcdefghijklmnopabcdefghijklmnop";
    private static final String GITHUB = "https://github.com";
    private static final long PUMP_LIMIT_NANOS = Duration.ofSeconds(20).toNanos();
    private static final RelayPeers.Peer PEER = BrowserRelay.peer("0123456789abcdef0123456789abcdef");

    /** A broker in this JVM and the browser port the TUI hands over on unlock. */
    private static final class Host implements ApprovalHost {
        final ApprovalBroker core;
        volatile VaultPort vault = GuiThreadBrowserVault.LOCKED;
        final RelayPeers peers = new RelayPeers();
        /** What the broker audits: the user's answers. */
        final List<AuditEvent> audit = new CopyOnWriteArrayList<>();
        /** Runs right after each broker audit entry, before the broker hands out the outcome. */
        volatile Runnable afterAudit = () -> { };

        Host(TuiHarness.ManualClock clock) {
            core = new ApprovalBroker(clock, e -> {
                audit.add(e);
                afterAudit.run();
            }, PolicyStore.inMemory(), "alice");
        }

        @Override
        public Optional<ApprovalBroker> broker() {
            return Optional.of(core);
        }

        @Override
        public void unlocked(Releaser r) {
            core.unlock();
        }

        @Override
        public void browser(VaultPort port) {
            vault = port;
        }

        @Override
        public void locked() {
            vault = GuiThreadBrowserVault.LOCKED;
            core.lock();
        }

        @Override
        public void close() {
            core.lock();
        }

        @Override
        public Optional<String> peer(ApprovalRequest request) {
            return peers.line(request.requestId());
        }

        @Override
        public boolean stillAsked(ApprovalRequest request) {
            return peers.stillAllowed(request.requestId());
        }
    }

    /** Counts what the bridge takes out of the vault. */
    private final class Counting implements VaultPort {
        @Override
        public List<Login> logins() {
            return host.vault.logins();
        }

        @Override
        public SecretBytes password(Grant grant, UUID entry) throws HostException {
            SecretBytes out = host.vault.password(grant, entry);
            released.incrementAndGet();
            return out;
        }

        @Override
        public UUID save(Grant grant, Origin origin, String username, SecretChars password) throws HostException {
            UUID id = host.vault.save(grant, origin, username, password);
            saved.incrementAndGet();
            return id;
        }
    }

    private final TuiHarness.ManualClock clock = new TuiHarness.ManualClock(FakeVaultPort.T0);
    private final Host host = new Host(clock);
    private final AtomicInteger released = new AtomicInteger();
    private final AtomicInteger saved = new AtomicInteger();
    /** Approvals the relay refused after all: "request-id decision", as the relay audits them. */
    private final List<String> overruled = new CopyOnWriteArrayList<>();
    private final ExecutorService relay = Executors.newCachedThreadPool();

    @AfterEach
    void stopRelay() {
        relay.shutdownNow();
    }

    private TuiHarness unlocked() throws IOException {
        return unlocked(new TerminalSize(110, 32));
    }

    private TuiHarness unlocked(TerminalSize size) throws IOException {
        TuiHarness h = new TuiHarness(new FakeVaultPort(UNLOCK_PHRASE, "recovery-unused"), host, clock, size);
        h.unlockWith(UNLOCK_PHRASE);
        assertTrue(h.controller.isUnlocked());
        return h;
    }

    /** Sends {@code json} through a bridge on a relay thread, as {@link BrowserRelay} does. */
    private CompletableFuture<Json.Obj> send(String json, CompletableFuture<Void> gone, Duration wait) {
        return send(json, gone, wait, () -> true);
    }

    /** {@link #send} for an extension that {@code allowed} says is allowlisted, read on every check. */
    private CompletableFuture<Json.Obj> send(String json, CompletableFuture<Void> gone, Duration wait,
            BooleanSupplier allowed) {
        Bridge bridge = new Bridge(EXTENSION, new Counting(),
                new RelayApproval(host.core, wait, gone, PEER, host.peers, allowed,
                        (r, d) -> overruled.add(r.requestId() + " " + d)),
                clock, PasswordGenerator.secure());
        return CompletableFuture.supplyAsync(() -> {
            try (Request request = Messages.decode(json.getBytes(StandardCharsets.UTF_8))) {
                return bridge.handle(request);
            } catch (HostException e) {
                return Messages.error(null, e.getMessage());
            }
        }, relay);
    }

    private CompletableFuture<Json.Obj> fill(TuiHarness h, CompletableFuture<Void> gone) {
        return fill(h, gone, () -> true);
    }

    private CompletableFuture<Json.Obj> fill(TuiHarness h, CompletableFuture<Void> gone, BooleanSupplier allowed) {
        UUID entry = host.vault.logins().get(0).id(); // the test thread is the GUI thread
        CompletableFuture<Json.Obj> reply = send("{\"type\":\"fill\",\"id\":\"r1\",\"origin\":\"https://github.com\","
                + "\"entry\":\"" + entry + "\"}", gone, Duration.ofMinutes(5), allowed);
        pumpUntil(h, () -> !host.core.pending().isEmpty() || reply.isDone());
        return reply;
    }

    /** Runs the GUI thread (this one) until {@code done}: the bridge reaches the session only through it. */
    private static void pumpUntil(TuiHarness h, BooleanSupplier done) {
        long start = System.nanoTime();
        while (!done.getAsBoolean()) {
            if (System.nanoTime() - start > PUMP_LIMIT_NANOS) {
                throw new AssertionError("timed out waiting");
            }
            h.tick();
            Thread.onSpinWait();
        }
        h.tick();
    }

    private static void pastGuard(TuiHarness h) {
        h.clock.advance(ApprovalDialog.INPUT_GUARD.plusMillis(1));
        h.tick();
    }

    private static String text(Json.Obj reply, String member) {
        return ((Json.Str) reply.get(member)).text();
    }

    @Test
    void fillShowsTheExactOriginAndLoginAndApprovingReleasesOnce() throws IOException {
        try (TuiHarness h = unlocked()) {
            CompletableFuture<Json.Obj> reply = fill(h, new CompletableFuture<>());
            String screen = h.screenText();
            assertTrue(screen.contains("\"" + EXTENSION + "\"  (extension)"), screen);
            assertTrue(screen.contains("from " + PEER.line()), "the relay's peer: " + screen);
            assertTrue(screen.contains("wants to fill or save a login in the browser"), screen);
            assertTrue(screen.contains("site " + GITHUB), screen);
            assertTrue(screen.contains("action fill login \"GitHub\", username \"octocat\""), screen);
            assertFalse(screen.contains(ApprovalDialog.LOOKALIKE), "a plain ASCII host gets no warning");
            assertEquals(0, released.get(), "nothing before the user answers");

            pastGuard(h);
            assertTrue(h.screenText().contains(ApprovalDialog.KEYS_ONCE), "only once or deny");
            h.type("y");
            h.press(KeyType.Enter);
            pumpUntil(h, reply::isDone);
            Json.Obj answer = reply.join();
            assertEquals("fill", text(answer, "type"), answer.toString());
            assertEquals(FakeVaultPort.LOGIN_SECRET, text(answer, "password"));
            assertEquals(1, released.get(), "one approval, one release");

            // Approved once only: the next fill prompts again.
            CompletableFuture<Json.Obj> again = fill(h, new CompletableFuture<>());
            assertFalse(again.isDone());
            assertEquals(1, host.core.pending().size());
            host.core.pending().get(0).deny();
            pumpUntil(h, again::isDone);
            assertEquals(1, released.get());
        }
    }

    /**
     * The extension is taken off the allowlist while its prompt is open (as {@code pm browser
     * uninstall --extension-id} does), and the user approves anyway: {@code DENIED_AUTH}, and the
     * approval's grant is dropped unused, so no password leaves.
     */
    @Test
    void anApprovalForAnExtensionTakenOffTheAllowlistReleasesNothing() throws IOException {
        AtomicBoolean listed = new AtomicBoolean(true);
        try (TuiHarness h = unlocked()) {
            CompletableFuture<Json.Obj> reply = fill(h, new CompletableFuture<>(), listed::get);
            assertTrue(h.screenText().contains("site " + GITHUB), "the prompt is shown");
            listed.set(false);
            pastGuard(h);
            h.type("y");
            h.press(KeyType.Enter);
            pumpUntil(h, reply::isDone);
            assertEquals(Decision.DENIED_AUTH.name(), text(reply.join(), "code"), reply.join().toString());
            assertEquals(0, released.get(), "approved, but nothing released");
            assertTrue(host.core.pending().isEmpty());
            // m54c-002: the broker audited the approval, and the refusal is audited after it.
            UUID id = onlyAnswer(Decision.ALLOWED_ONCE);
            assertEquals(List.of(id + " " + Decision.DENIED_AUTH), overruled);
        }
    }

    /** The request id of the one answer the broker audited, which was {@code decision}. */
    private UUID onlyAnswer(Decision decision) {
        List<AuditEvent> answers = host.audit.stream().filter(e -> e.requestId().isPresent()
                && e.decision().isPresent()).toList();
        assertEquals(1, answers.size(), answers::toString);
        assertEquals(Optional.of(decision.name()), answers.get(0).decision());
        return answers.get(0).requestId().orElseThrow();
    }

    /**
     * The host goes away in the very moment the user approves (right after the broker audited the
     * approval): nothing is released, and the refusal is audited after the approval, so the log
     * never shows a release that did not happen. A denial needs no second entry.
     */
    @Test
    void anApprovalThatArrivesAsTheHostGoesIsAuditedAsRefused() throws IOException {
        CompletableFuture<Void> gone = new CompletableFuture<>();
        try (TuiHarness h = unlocked()) {
            CompletableFuture<Json.Obj> reply = fill(h, gone);
            assertTrue(h.screenText().contains("site " + GITHUB), "the prompt is shown");
            host.afterAudit = () -> gone.complete(null);
            pastGuard(h);
            h.type("y");
            h.press(KeyType.Enter);
            pumpUntil(h, reply::isDone);
            assertEquals(Decision.DENIED.name(), text(reply.join(), "code"), reply.join().toString());
            assertEquals(0, released.get(), "approved, but nobody is there to receive it");
            UUID id = onlyAnswer(Decision.ALLOWED_ONCE);
            assertEquals(List.of(id + " " + Decision.DENIED), overruled);
        }
    }

    /**
     * The extension is listed when its request arrives and taken off the allowlist before the
     * dialog shows the prompt: the TUI denies it unseen, and the extension gets {@code DENIED_AUTH}.
     */
    @Test
    void aPromptWhoseExtensionWasTakenOffTheAllowlistIsNeverShown() throws IOException {
        AtomicInteger checks = new AtomicInteger();
        BooleanSupplier listedOnlyAtFirst = () -> checks.getAndIncrement() == 0;
        try (TuiHarness h = unlocked()) {
            int before = h.renderedFrames().size();
            CompletableFuture<Json.Obj> reply = fill(h, new CompletableFuture<>(), listedOnlyAtFirst);
            pumpUntil(h, reply::isDone);
            assertEquals(Decision.DENIED_AUTH.name(), text(reply.join(), "code"), reply.join().toString());
            assertEquals(0, released.get());
            assertTrue(host.core.pending().isEmpty());
            assertTrue(checks.get() >= 2, "checked when asked and again before the dialog: " + checks.get());
            List<String> shown = h.renderedFrames().subList(before, h.renderedFrames().size());
            assertTrue(shown.stream().noneMatch(f -> f.contains("site " + GITHUB) || f.contains(ApprovalDialog.TITLE)),
                    "never shown");
        }
    }

    @Test
    void denyReleasesNothing() throws IOException {
        try (TuiHarness h = unlocked()) {
            CompletableFuture<Json.Obj> reply = fill(h, new CompletableFuture<>());
            pastGuard(h);
            h.type("n");
            pumpUntil(h, reply::isDone);
            assertEquals("error", text(reply.join(), "type"));
            assertEquals(Decision.DENIED.name(), text(reply.join(), "code"));
            assertEquals(0, released.get());
            assertFalse(h.screenText().contains(ApprovalDialog.TITLE));
        }
    }

    @Test
    void anUnansweredPromptTimesOutAndReleasesNothing() throws IOException {
        try (TuiHarness h = unlocked()) {
            CompletableFuture<Json.Obj> reply = fill(h, new CompletableFuture<>());
            h.clock.advance(ApprovalBroker.PROMPT_TIMEOUT);
            host.core.expire();
            pumpUntil(h, reply::isDone);
            assertEquals(Decision.DENIED_TIMEOUT.name(), text(reply.join(), "code"));
            assertEquals(0, released.get());
            assertFalse(h.screenText().contains(ApprovalDialog.TITLE));
        }
    }

    @Test
    void theRelaysOwnWaitEndingWithdrawsThePrompt() throws IOException {
        try (TuiHarness h = unlocked()) {
            UUID entry = host.vault.logins().get(0).id();
            CompletableFuture<Json.Obj> reply = send("{\"type\":\"fill\",\"id\":\"r1\",\"origin\":\"https://github.com\","
                    + "\"entry\":\"" + entry + "\"}", new CompletableFuture<>(), Duration.ofMillis(200));
            pumpUntil(h, reply::isDone);
            assertEquals(Decision.DENIED_TIMEOUT.name(), text(reply.join(), "code"));
            assertTrue(host.core.pending().isEmpty(), "the prompt is denied, not left behind");
            assertEquals(0, released.get());
        }
    }

    @Test
    void theHostGoingAwayMidApprovalCancelsTheGrant() throws IOException {
        try (TuiHarness h = unlocked()) {
            CompletableFuture<Void> gone = new CompletableFuture<>();
            CompletableFuture<Json.Obj> reply = fill(h, gone);
            assertTrue(h.screenText().contains(ApprovalDialog.TITLE));
            gone.complete(null); // Chrome stopped the service worker and with it the native host
            pumpUntil(h, reply::isDone);
            assertEquals(Decision.DENIED.name(), text(reply.join(), "code"));
            assertTrue(host.core.pending().isEmpty());
            assertFalse(h.screenText().contains(ApprovalDialog.TITLE), "the withdrawn prompt closes");
            assertEquals(0, released.get());
        }
    }

    @Test
    void saveStoresTheLoginOnlyAfterApproval() throws IOException {
        try (TuiHarness h = unlocked()) {
            int before = host.vault.logins().size();
            CompletableFuture<Json.Obj> reply = send("{\"type\":\"save\",\"id\":\"s1\",\"origin\":\"https://example.org\","
                    + "\"username\":\"bob\",\"password\":\"correct horse\"}", new CompletableFuture<>(), Duration.ofMinutes(5));
            pumpUntil(h, () -> !host.core.pending().isEmpty());
            String screen = h.screenText();
            assertTrue(screen.contains("site https://example.org"), screen);
            assertTrue(screen.contains("action save a new login, username \"bob\""), screen);
            assertEquals(before, host.vault.logins().size());
            pastGuard(h);
            h.type("y");
            h.press(KeyType.Enter);
            pumpUntil(h, reply::isDone);
            assertEquals("save", text(reply.join(), "type"), reply.join().toString());
            assertEquals(1, saved.get());
            assertEquals(before + 1, host.vault.logins().size());
            assertTrue(host.vault.logins().stream().anyMatch(l -> l.urls().equals(List.of("https://example.org"))));
        }
    }

    @Test
    void lockedOrNoSessionAnswersLocked() throws IOException {
        CompletableFuture<Json.Obj> noTui = send("{\"type\":\"lookup\",\"id\":\"l1\",\"origin\":\"https://github.com\"}",
                new CompletableFuture<>(), Duration.ofMinutes(5));
        assertEquals(Decision.DENIED_LOCKED.name(), text(noTui.join(), "code"));
        try (TuiHarness h = unlocked()) {
            h.timers.fireLatest(); // idle lock
            h.pump();
            CompletableFuture<Json.Obj> reply = send("{\"type\":\"lookup\",\"id\":\"l2\",\"origin\":\"https://github.com\"}",
                    new CompletableFuture<>(), Duration.ofMinutes(5));
            pumpUntil(h, reply::isDone);
            assertEquals(Decision.DENIED_LOCKED.name(), text(reply.join(), "code"));
            assertEquals(0, released.get());
        }
    }

    // ---- the prompt's rendering of hostile text ------------------------------------------------

    private CompletableFuture<Outcome> ask(TuiHarness h, String origin, String display) {
        ApprovalRequest q = new ApprovalRequest(UUID.randomUUID(),
                new ApprovalRequest.Requester(ApprovalRequest.Kind.EXTENSION, EXTENSION),
                ApprovalRequest.Operation.AUTOFILL,
                new ApprovalRequest.Scope(origin, "save", Optional.empty(), List.of()),
                Duration.ZERO, new ApprovalRequest.Display(List.of(), Optional.of(display), ApprovalRequest.Effect.WRITE_FILE),
                h.clock.instant());
        CompletableFuture<Outcome> f = host.core.withToken(t -> host.core.submit(q, t, Optional.empty()));
        h.tick();
        return f;
    }

    @Test
    void anInternationalisedHostIsShownVerbatimWithAWarning() throws IOException {
        try (TuiHarness h = unlocked()) {
            String origin = "https://xn--pple-43d.com"; // "аpple.com" with a Cyrillic a
            CompletableFuture<Outcome> f = ask(h, origin, origin + " - save a new login, username \"bob\"");
            String screen = h.screenText();
            assertTrue(screen.contains("site " + origin), screen);
            assertTrue(screen.contains(ApprovalDialog.LOOKALIKE), screen);
            pastGuard(h);
            h.type("n");
            assertEquals(Decision.DENIED, f.join().decision());
        }
    }

    @Test
    void escapesAndBidiControlsInTheRequestAreNeverWrittenRaw() throws IOException {
        try (TuiHarness h = unlocked()) {
            String origin = "https://evil.example\u009b2J\u202emoc.knab";
            String action = "fill login \"Bank\u009d0;pwned\u009c\u2028\", username \"x\"";
            CompletableFuture<Outcome> f = ask(h, origin, origin + " - " + action);
            String screen = h.screenText();
            assertTrue(screen.contains("site https://evil.example" + DisplaySafe.REPLACEMENT + "2J"
                    + DisplaySafe.REPLACEMENT + "moc.knab"), screen);
            assertTrue(screen.contains(ApprovalDialog.LOOKALIKE), "a non-ASCII origin is flagged");
            assertTrue(screen.contains("action fill login \"Bank" + DisplaySafe.REPLACEMENT + "0;pwned"
                    + DisplaySafe.REPLACEMENT + DisplaySafe.REPLACEMENT + "\""), screen);
            assertTrue(screen.chars().noneMatch(c -> c == 0x9b || c == 0x9c || c == 0x9d || c == 0x202e || c == 0x2028),
                    "no control or bidi character reaches the terminal");
            pastGuard(h);
            h.press(KeyType.Escape);
            assertEquals(Decision.DENIED, f.join().decision());
        }
    }

    @Test
    void aLongActionIsWrappedNotCut() {
        String words = "generate a password, save it as a new login (username \"someone-with-a-long-name@example.org\") and fill it";
        List<String> lines = ApprovalDialog.wrap(words, ApprovalDialog.MAX_ARG_COLUMNS);
        assertTrue(lines.size() > 1);
        assertTrue(lines.stream().allMatch(l -> ApprovalDialog.columns(l) <= ApprovalDialog.MAX_ARG_COLUMNS));
        assertEquals(words.replace(" ", ""), String.join("", lines).replace(" ", ""));
    }

    // ---- M5.4 review: shown in full or not at all ---------------------------------------------

    /** An origin of exactly {@code length} characters, every position distinguishable from its neighbours. */
    private static String origin(int length) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder("https://");
        for (int i = 0; sb.length() < length; i++) {
            sb.append(alphabet.charAt(i % alphabet.length()));
        }
        return sb.toString();
    }

    /** The origin as the screen shows it: the "site" line and its continuation lines, joined. */
    private static Optional<String> shownOrigin(String screen) {
        List<String> rows = List.of(screen.split("\n"));
        for (int r = 0; r < rows.size(); r++) {
            int c0 = rows.get(r).indexOf("site https://");
            if (c0 < 0) {
                continue;
            }
            StringBuilder sb = new StringBuilder(cell(rows.get(r), c0 + 5));
            for (int next = r + 1; next < rows.size(); next++) {
                String row = rows.get(next);
                if (row.length() <= c0 + 5 || !row.substring(c0, c0 + 5).isBlank() || row.charAt(c0 + 5) == ' ') {
                    break;
                }
                sb.append(cell(row, c0 + 5));
            }
            return Optional.of(sb.toString());
        }
        return Optional.empty();
    }

    private static String cell(String row, int from) {
        int end = row.indexOf(' ', from);
        return row.substring(from, end < 0 ? row.length() : end);
    }

    @Test
    void aLongOriginIsShownWholeAndInOrderOrTheRequestIsDenied() throws IOException {
        for (TerminalSize size : List.of(new TerminalSize(80, 24), new TerminalSize(110, 30))) {
            for (int length : List.of(56, 79, 88, 254)) {
                String origin = origin(length);
                try (TuiHarness h = unlocked(size)) {
                    CompletableFuture<Outcome> f = ask(h, origin, origin + " - save a new login, username \"bob\"");
                    String screen = h.screenText();
                    String where = size + " origin " + length + ":\n" + screen;
                    if (screen.contains(ApprovalDialog.TOO_SMALL_TITLE)) {
                        assertEquals(Decision.DENIED, f.join().decision(), where);
                    } else {
                        assertEquals(Optional.of(origin), shownOrigin(screen), where);
                        assertTrue(screen.contains("action save a new login, username \"bob\""), where);
                        pastGuard(h);
                        h.type("n");
                        assertEquals(Decision.DENIED, f.join().decision());
                    }
                    // Every one of these fits: the check above is not vacuous.
                    assertFalse(screen.contains(ApprovalDialog.TOO_SMALL_TITLE), where);
                }
            }
        }
    }

    @Test
    void aPromptThatFitsExactlyIsShownAndOneRowLessIsDenied() throws IOException {
        String origin = origin(254);
        // 80 columns: the origin takes four lines; with the other lines, the blank, the status,
        // the countdown, the border and the margins the prompt needs 17 rows.
        try (TuiHarness h = unlocked(new TerminalSize(80, 17))) {
            CompletableFuture<Outcome> f = ask(h, origin, origin + " - use a login");
            assertEquals(Optional.of(origin), shownOrigin(h.screenText()), h.screenText());
            assertTrue(h.screenText().contains("action use a login"), h.screenText());
            pastGuard(h);
            h.type("n");
            assertEquals(Decision.DENIED, f.join().decision());
        }
        try (TuiHarness h = unlocked(new TerminalSize(80, 16))) {
            CompletableFuture<Outcome> f = ask(h, origin, origin + " - use a login");
            assertEquals(Decision.DENIED, f.join().decision(), "one row short: denied, never cut");
            assertTrue(h.screenText().contains(ApprovalDialog.TOO_SMALL_TITLE), h.screenText());
        }
    }

    @Test
    void aTerminalTooSmallDeniesWithANoticeThatStaysUntilClosed() throws IOException {
        try (TuiHarness h = unlocked(new TerminalSize(56, 20))) {
            CompletableFuture<Outcome> f = ask(h, GITHUB, GITHUB + " - use a login");
            assertEquals(Decision.DENIED, f.join().decision(), "denied at once, before any key");
            assertTrue(host.core.pending().isEmpty());
            String screen = h.screenText();
            assertTrue(screen.contains(ApprovalDialog.TOO_SMALL_TITLE), screen);
            assertTrue(screen.contains("(56×20)"), "says how big the terminal is: " + screen);
            assertTrue(screen.contains("Enter or Esc to close"), screen);
            assertFalse(screen.contains("site " + GITHUB), "nothing of the request is shown cut");
            h.tick();
            h.type("y");
            assertTrue(h.screenText().contains(ApprovalDialog.TOO_SMALL_TITLE), "the notice stays; y does nothing");
            h.press(KeyType.Enter);
            assertFalse(h.screenText().contains(ApprovalDialog.TOO_SMALL_TITLE), h.screenText());
        }
    }

    @Test
    void aTerminalThatShrinksUnderAnOpenPromptDeniesIt() throws IOException {
        try (TuiHarness h = unlocked(new TerminalSize(110, 30))) {
            CompletableFuture<Outcome> f = ask(h, GITHUB, GITHUB + " - use a login");
            assertTrue(h.screenText().contains("site " + GITHUB));
            h.terminal.setTerminalSize(new TerminalSize(56, 20));
            h.tick();
            h.tick();
            assertEquals(Decision.DENIED, f.join().decision());
            assertTrue(h.screenText().contains(ApprovalDialog.TOO_SMALL_TITLE), h.screenText());
            h.press(KeyType.Escape);
            assertFalse(h.screenText().contains(ApprovalDialog.TOO_SMALL_TITLE));
        }
    }

    @Test
    void aBrowserPromptOffersOnlyOnceOrDenyAndNamesAnUnknownSender() throws IOException {
        try (TuiHarness h = unlocked()) {
            CompletableFuture<Outcome> f = ask(h, GITHUB, GITHUB + " - use a login");
            assertTrue(h.screenText().contains(ApprovalDialog.UNKNOWN_SENDER), "not registered by the relay");
            pastGuard(h);
            assertTrue(h.screenText().contains(ApprovalDialog.KEYS_ONCE));
            assertFalse(h.screenText().contains(ApprovalDialog.KEYS));
            h.type("s");
            h.press(KeyType.Enter, KeyType.Enter);
            h.type("p");
            h.press(KeyType.Enter, KeyType.Enter);
            assertFalse(f.isDone(), "s and p do nothing for a browser request");
            assertEquals(1, host.core.pending().size());
            h.type("n");
            assertEquals(Decision.DENIED, f.join().decision());
        }
    }

    @Test
    void wideCharactersAreWrappedByColumnsAndStayInsideTheBorder() throws IOException {
        String name = "用".repeat(64);
        String action = "fill login \"GitHub\", username \"" + name + "\"";
        List<String> lines = ApprovalDialog.wrap(action, 65);
        assertTrue(lines.stream().allMatch(l -> ApprovalDialog.columns(l) <= 65), lines.toString());
        assertEquals(action.replace(" ", ""), String.join("", lines).replace(" ", ""));
        assertEquals(128, ApprovalDialog.columns(name), "two columns each");
        try (TuiHarness h = unlocked(new TerminalSize(80, 24))) {
            CompletableFuture<Outcome> f = ask(h, GITHUB, GITHUB + " - " + action);
            Window dialog = h.activeWindow();
            assertEquals(ApprovalDialog.TITLE, dialog.getTitle());
            int left = dialog.getPosition().getColumn();
            int right = left + dialog.getDecoratedSize().getColumns();
            assertTrue(left >= 0 && right <= 80, "the dialog fits the terminal: " + left + ".." + right);
            String shown = cells(h);
            int names = shown.split("用", -1).length - 1;
            assertEquals(64, names, "every character of the username is on screen:\n" + shown);
            assertTrue(shown.contains("用\""), "with its closing quote:\n" + shown);
            pastGuard(h);
            h.type("n");
            assertEquals(Decision.DENIED, f.join().decision());
        }
    }

    /** The screen's characters, a wide character once (its second column skipped). */
    private static String cells(TuiHarness h) {
        StringBuilder sb = new StringBuilder();
        TerminalSize size = h.terminal.getTerminalSize();
        for (int row = 0; row < size.getRows(); row++) {
            int col = 0;
            while (col < size.getColumns()) {
                TextCharacter c = h.terminal.getCharacter(col, row);
                sb.append(c.getCharacterString());
                col += c.isDoubleWidth() ? 2 : 1;
            }
            sb.append('\n');
        }
        return sb.toString();
    }
}
