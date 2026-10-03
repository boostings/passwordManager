package pm.browser.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.approval.ApprovalBroker;
import pm.approval.ApprovalRequest;
import pm.approval.Decision;
import pm.approval.Grant;
import pm.approval.Outcome;
import pm.approval.PendingApproval;
import pm.approval.PolicyStore;
import pm.browser.host.HostException;
import pm.browser.host.Json;
import pm.browser.host.Request;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;

/**
 * The bridge against a real {@link ApprovalBroker}: nothing is released without a grant for that
 * exact request (SR-302, SR-307), and logins match exact origins only (SR-300, SR-306).
 */
@Tag("T-EXT-03")
class BridgeTest {
    private static final String EXT = "abcdefghijklmnopabcdefghijklmnop";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-03T12:00:00Z"), ZoneOffset.UTC);
    private static final String SITE = "https://example.com";
    private static final UUID MAIN = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID SECOND = UUID.fromString("00000000-0000-4000-8000-000000000002");
    private static final UUID OTHER_SITE = UUID.fromString("00000000-0000-4000-8000-000000000003");

    private ApprovalBroker broker;
    private final List<ApprovalRequest> prompts = new ArrayList<>();
    private Consumer<PendingApproval> user = PendingApproval::deny;
    private FakeVault vault;

    @BeforeEach
    void setUp() {
        broker = new ApprovalBroker(CLOCK, e -> { }, PolicyStore.inMemory(), "alice");
        broker.setPromptListener(() -> {
            List<PendingApproval> waiting = broker.pending();
            PendingApproval last = waiting.get(waiting.size() - 1);
            prompts.add(last.request());
            user.accept(last);
        });
        broker.unlock();
        vault = new FakeVault();
        vault.add(MAIN, "Example", "alice@example.com", "s3cret-é", "https://example.com/login");
        vault.add(SECOND, "Example 2", "bob", "other", "https://EXAMPLE.com:443/");
        vault.add(OTHER_SITE, "Evil", "mallory", "evil", "https://example.com.evil.net/");
    }

    private Bridge bridge() {
        return bridge(ApprovalPort.inProcess(broker, Duration.ofSeconds(5)));
    }

    private Bridge bridge(ApprovalPort port) {
        return (Bridge) Bridge.factory(vault, port, CLOCK, new PasswordGenerator(PasswordGeneratorTest.bytes(7)))
                .forCaller(EXT);
    }

    private static String str(Json.Obj o, String name) {
        return assertInstanceOf(Json.Str.class, o.get(name)).text();
    }

    private static HostException refused(Bridge bridge, Request request) {
        return assertThrows(HostException.class, () -> bridge.handle(request));
    }

    // ---- release only with approval -----------------------------------------------------------

    @Test
    void fillReleasesThePasswordOnlyAfterTheUserApproves() throws HostException {
        user = PendingApproval::approveOnce;
        Json.Obj reply = bridge().handle(new Request.Fill("r1", "https://Example.com:443", MAIN));
        assertEquals("fill", str(reply, "type"));
        assertEquals("r1", str(reply, "id"));
        assertEquals(SITE, str(reply, "origin"));
        assertEquals("alice@example.com", str(reply, "username"));
        assertEquals("s3cret-é", str(reply, "password"));
        assertEquals(1, vault.released);
        assertTrue(vault.lastGrant().isUsed());

        ApprovalRequest asked = prompts.get(0);
        assertEquals(ApprovalRequest.Operation.AUTOFILL, asked.operation());
        assertEquals(new ApprovalRequest.Requester(ApprovalRequest.Kind.EXTENSION, EXT), asked.requester());
        assertEquals(ApprovalRequest.Scope.profile(SITE, "fill-1d7tmz9j2abdrls1"), asked.scope());
        assertEquals(new ApprovalRequest.Display(List.of(),
                Optional.of(SITE + " - fill login \"Example\", username \"alice@example.com\""),
                ApprovalRequest.Effect.SEND), asked.display());
        assertFalse(asked.display().origin().orElseThrow().contains("s3cret"));
        assertEquals(Duration.ZERO, asked.duration());
        assertEquals(CLOCK.instant(), asked.created());
        assertEquals(asked, vault.lastGrant().request());
    }

    @Test
    void aDenyingBrokerReleasesNothing() {
        user = PendingApproval::deny;
        Bridge bridge = bridge();
        assertEquals("DENIED", refused(bridge, new Request.Fill("r1", SITE, MAIN)).getMessage());
        try (SecretChars pw = SecretChars.takeOwnership("hunter2!".toCharArray())) {
            HostException save = refused(bridge, new Request.Save("r2", SITE, "u", pw));
            assertEquals(HostException.Code.DENIED, save.code());
        }
        assertEquals("DENIED", refused(bridge,
                new Request.Generate("r3", SITE, "", new Request.Policy(8, true, true, true, true))).getMessage());
        assertEquals(3, prompts.size());
        assertEquals(0, vault.released);
        assertEquals(0, vault.saved.size());
    }

    @Test
    void aLockedVaultReleasesNothingAndShowsNoPrompt() {
        broker.lock();
        user = PendingApproval::approveOnce;
        Bridge bridge = bridge();
        assertEquals("DENIED_LOCKED", refused(bridge, new Request.Fill("r1", SITE, MAIN)).getMessage());
        assertEquals("DENIED_LOCKED", refused(bridge, new Request.Lookup("r2", SITE)).getMessage());
        assertEquals(0, vault.listed);
        assertTrue(prompts.isEmpty());
    }

    @Test
    void aSessionPolicyCoversOneExtensionOneOriginOneActionAndOneLogin() throws HostException {
        user = PendingApproval::approveForSession;
        Bridge bridge = bridge();
        bridge.handle(new Request.Fill("r1", SITE, MAIN));
        user = PendingApproval::deny;
        Json.Obj again = bridge.handle(new Request.Fill("r2", SITE, MAIN));
        assertEquals("s3cret-é", str(again, "password"));
        assertEquals(Decision.ALLOWED_SESSION, vault.lastGrant().decision());
        assertEquals(1, prompts.size());
        // another login on the same origin is a different release and prompts again
        assertEquals("DENIED", refused(bridge, new Request.Fill("r2b", SITE, SECOND)).getMessage());
        assertEquals(2, prompts.size());

        vault.add(UUID.randomUUID(), "Other port", "x", "y", "https://example.com:8443/");
        UUID port = vault.logins().get(3).id();
        assertEquals("DENIED", refused(bridge, new Request.Fill("r3", "https://example.com:8443", port)).getMessage());
        try (SecretChars pw = SecretChars.takeOwnership("hunter2!".toCharArray())) {
            assertEquals("DENIED", refused(bridge, new Request.Save("r4", SITE, "u", pw)).getMessage());
        }
        Bridge otherExtension = (Bridge) Bridge.factory(vault, ApprovalPort.inProcess(broker, Duration.ofSeconds(5)),
                CLOCK, PasswordGenerator.secure()).forCaller("ponmlkjihgfedcbaponmlkjihgfedcba");
        assertEquals("DENIED", refused(otherExtension, new Request.Fill("r5", SITE, MAIN)).getMessage());
        assertEquals(5, prompts.size());

        broker.lock();
        broker.unlock();
        assertEquals("DENIED", refused(bridge, new Request.Fill("r6", SITE, MAIN)).getMessage());
    }

    @Test
    void saveStoresUnderTheCanonicalOriginAfterApproval() throws HostException {
        user = PendingApproval::approveOnce;
        try (SecretChars pw = SecretChars.takeOwnership("n3w-pass".toCharArray())) {
            Json.Obj reply = bridge().handle(new Request.Save("r1", "HTTPS://Example.com", "carol", pw));
            assertEquals("save", str(reply, "type"));
            assertEquals(vault.saved.get(0).toString(), str(reply, "entry"));
        }
        assertEquals(ApprovalRequest.Effect.WRITE_FILE, prompts.get(0).display().effect());
        assertEquals("save", prompts.get(0).scope().profile());
        assertEquals(Optional.of(SITE + " - save a new login, username \"carol\""), prompts.get(0).display().origin());
        assertEquals(SITE, vault.savedOrigins.get(0).text());
        assertTrue(vault.lastGrant().isUsed());
    }

    @Test
    void generateStoresTheNewLoginBeforeReleasingIt() throws HostException {
        user = PendingApproval::approveOnce;
        Json.Obj reply = bridge().handle(
                new Request.Generate("r1", "HTTPS://Example.com", "dave", new Request.Policy(8, true, false, false, false)));
        assertEquals("generate", str(reply, "type"));
        assertEquals(SITE, str(reply, "origin"));
        assertEquals("hhhhhhhh", str(reply, "password")); // byte 7 -> 'h'
        assertEquals(vault.saved.get(0).toString(), str(reply, "entry"));
        assertEquals(List.of("dave"), vault.savedUsernames);
        assertEquals(List.of("hhhhhhhh"), vault.savedSecrets);
        assertEquals(SITE, vault.savedOrigins.get(0).text());
        assertTrue(vault.lastGrant().isUsed());
        ApprovalRequest asked = prompts.get(0);
        assertEquals("generate", asked.scope().profile());
        assertEquals(ApprovalRequest.Effect.WRITE_FILE, asked.display().effect());
        assertEquals(Optional.of(SITE + " - generate a password, save it as a new login (username \"dave\") and fill it"),
                asked.display().origin());
    }

    @Test
    void generateReleasesNothingIfTheSaveFailsOrIsNotConsumed() {
        user = PendingApproval::approveOnce;
        Request.Policy policy = new Request.Policy(8, true, false, false, false);
        vault.failSave = true;
        assertEquals(HostException.Code.INTERNAL, refused(bridge(), new Request.Generate("r1", SITE, "", policy)).code());
        vault.failSave = false;
        vault.consume = false;
        assertEquals(HostException.Code.INTERNAL, refused(bridge(), new Request.Generate("r2", SITE, "", policy)).code());
    }

    @Test
    void promptTextIsBoundedAndFreeOfControlCharacters() {
        assertEquals("a?b", Bridge.shown("a\u0007b"));
        assertEquals("x".repeat(64), Bridge.shown("x".repeat(65)));
        assertEquals("\uD83D\uDE00", Bridge.shown("\uD83D\uDE00"));
        assertEquals("fill-x4oje6upltidsaifvrxwsx23", Bridge.fillProfile(UUID.fromString("0f8b6c1e-2a3d-4e5f-8a9b-0c1d2e3f4a5b")));
        assertEquals("fill-f5lxx1zz5pnorynqglhzmsp33", Bridge.fillProfile(new UUID(-1L, -1L)));
        assertEquals("fill-0", Bridge.fillProfile(new UUID(0L, 0L)));
        assertFalse(Bridge.fillProfile(MAIN).equals(Bridge.fillProfile(SECOND)));
    }

    @Test
    void aLoginWithControlCharactersStillPromptsSafely() throws HostException {
        user = PendingApproval::approveOnce;
        UUID odd = UUID.fromString("00000000-0000-4000-8000-000000000009");
        vault.add(odd, "Tab\there\u001b[2J", "line\nbreak", "pw", SITE);
        bridge().handle(new Request.Fill("r1", SITE, odd));
        assertEquals(Optional.of(SITE + " - fill login \"Tab?here?[2J\", username \"line?break\""),
                prompts.get(0).display().origin());
    }

    // ---- exact origins ------------------------------------------------------------------------

    @Test
    void lookupReturnsMetadataForExactlyThatOrigin() throws HostException {
        Json.Obj reply = bridge().handle(new Request.Lookup("r1", "https://example.com"));
        assertEquals("lookup", str(reply, "type"));
        assertEquals(SITE, str(reply, "origin"));
        List<Json> entries = assertInstanceOf(Json.Arr.class, reply.get("entries")).items();
        assertEquals(2, entries.size());
        Json.Obj first = assertInstanceOf(Json.Obj.class, entries.get(0));
        assertEquals(java.util.Set.of("entry", "title", "username"), first.names());
        assertEquals(MAIN.toString(), str(first, "entry"));
        assertTrue(prompts.isEmpty());
        assertEquals(0, vault.released);
    }

    @Test
    void confusableOriginsMatchNothingAndPromptNothing() throws HostException {
        user = PendingApproval::approveOnce;
        Bridge bridge = bridge();
        for (String near : List.of("https://a.example.com", "http://example.com", "https://example.com:8443",
                "https://xn--xample-2of.com", "https://127.0.0.1", "https://com", "https://evil.net")) {
            Json.Obj reply = bridge.handle(new Request.Lookup("r", near));
            assertEquals(0, assertInstanceOf(Json.Arr.class, reply.get("entries")).items().size(), near);
            assertEquals(HostException.Code.NOT_FOUND, refused(bridge, new Request.Fill("r", near, MAIN)).code());
        }
        for (String bad : List.of("https://example.com.", "https://user@example.com", "https://example.com/",
                "example.com", "https://0x7f.0.0.1")) {
            assertEquals(HostException.Code.BAD_ORIGIN, refused(bridge, new Request.Fill("r", bad, MAIN)).code());
            assertEquals(HostException.Code.BAD_ORIGIN, refused(bridge, new Request.Lookup("r", bad)).code());
        }
        assertEquals(HostException.Code.NOT_FOUND,
                refused(bridge, new Request.Fill("r", SITE, OTHER_SITE)).code());
        assertEquals(HostException.Code.NOT_FOUND,
                refused(bridge, new Request.Fill("r", SITE, UUID.randomUUID())).code());
        assertTrue(prompts.isEmpty());
        assertEquals(0, vault.released);
    }

    @Test
    void lookupIsCappedAndSkipsUnusableUrls() throws HostException {
        for (int i = 0; i < Bridge.MAX_LOOKUP + 5; i++) {
            vault.add(UUID.randomUUID(), "t" + i, "u", "p", "not a url", SITE + "/" + i);
        }
        vault.add(UUID.randomUUID(), "bare", "u", "p", "example.com");
        Json.Obj reply = bridge().handle(new Request.Lookup("r1", SITE));
        assertEquals(Bridge.MAX_LOOKUP, assertInstanceOf(Json.Arr.class, reply.get("entries")).items().size());
    }

    // ---- ports that break their contract ----------------------------------------------------

    @Test
    void aVaultThatDoesNotConsumeTheGrantReleasesNothing() throws HostException {
        user = PendingApproval::approveOnce;
        vault.consume = false;
        assertEquals(HostException.Code.INTERNAL, refused(bridge(), new Request.Fill("r1", SITE, MAIN)).code());
        assertTrue(vault.handedOut.get(0).isClosed());
        try (SecretChars pw = SecretChars.takeOwnership("n3w-pass".toCharArray())) {
            assertEquals(HostException.Code.INTERNAL, refused(bridge(), new Request.Save("r2", SITE, "u", pw)).code());
        }
    }

    @Test
    void aGrantForAnotherRequestOrAnUsedGrantIsRefused() {
        user = PendingApproval::approveOnce;
        ApprovalPort real = ApprovalPort.inProcess(broker, Duration.ofSeconds(5));
        ApprovalPort swapped = new ApprovalPort() {
            @Override
            public boolean isUnlocked() {
                return true;
            }

            @Override
            public Outcome approve(ApprovalRequest request) {
                return real.approve(new ApprovalRequest(UUID.randomUUID(), request.requester(), request.operation(),
                        ApprovalRequest.Scope.profile("https://elsewhere.example", "fill"), request.duration(),
                        request.display(), request.created()));
            }
        };
        assertEquals(HostException.Code.INTERNAL, refused(bridge(swapped), new Request.Fill("r1", SITE, MAIN)).code());
        ApprovalPort used = new ApprovalPort() {
            @Override
            public boolean isUnlocked() {
                return true;
            }

            @Override
            public Outcome approve(ApprovalRequest request) {
                Outcome o = real.approve(request);
                o.grant().orElseThrow().consume();
                return o;
            }
        };
        assertEquals(HostException.Code.INTERNAL, refused(bridge(used), new Request.Fill("r2", SITE, MAIN)).code());
        assertEquals(0, vault.released);
    }

    @Test
    void helloIsAnsweredWithoutTheVault() throws HostException {
        broker.lock();
        Json.Obj reply = bridge().handle(new Request.Hello("h"));
        assertEquals("hello", str(reply, "type"));
        assertEquals(0, vault.listed);
    }

    // ---- the in-process broker port -------------------------------------------------------------

    @Test
    @SuppressWarnings("PMD.DoNotUseThreads") // CE-025: sets and clears the test thread's interrupt flag only
    void theBrokerPortTimesOutAndHonoursInterrupts() {
        user = p -> { };
        ApprovalRequest q = new ApprovalRequest(UUID.randomUUID(),
                new ApprovalRequest.Requester(ApprovalRequest.Kind.EXTENSION, EXT), ApprovalRequest.Operation.AUTOFILL,
                ApprovalRequest.Scope.profile(SITE, "fill"), Duration.ZERO,
                new ApprovalRequest.Display(List.of(), Optional.of(SITE), ApprovalRequest.Effect.SEND), CLOCK.instant());
        ApprovalPort port = ApprovalPort.inProcess(broker, Duration.ZERO);
        assertTrue(port.isUnlocked());
        assertEquals(Decision.DENIED_TIMEOUT, port.approve(q).decision());

        ApprovalRequest q2 = new ApprovalRequest(UUID.randomUUID(), q.requester(), q.operation(), q.scope(),
                q.duration(), q.display(), q.created());
        Thread.currentThread().interrupt();
        assertEquals(Decision.DENIED_TIMEOUT, ApprovalPort.inProcess(broker, Duration.ofSeconds(5)).approve(q2).decision());
        assertTrue(Thread.interrupted());

        broker.lock();
        assertFalse(port.isUnlocked());
        assertEquals(Decision.DENIED_LOCKED, port.approve(q).decision());
    }

    @Test
    void onlyDenialsBecomeDenialReplies() {
        assertEquals("DENIED_BUSY", HostException.denied(Decision.DENIED_BUSY).getMessage());
        assertThrows(IllegalArgumentException.class, () -> {
            throw HostException.denied(Decision.ALLOWED_ONCE);
        });
    }

    /** An in-memory vault that records what the bridge asked for. */
    private static final class FakeVault implements VaultPort {
        private final List<Login> all = new ArrayList<>();
        private final Map<UUID, String> secrets = new HashMap<>();
        final List<UUID> saved = new ArrayList<>();
        final List<Origin> savedOrigins = new ArrayList<>();
        final List<String> savedUsernames = new ArrayList<>();
        final List<String> savedSecrets = new ArrayList<>();
        boolean failSave;
        final List<Grant> grants = new ArrayList<>();
        final List<SecretBytes> handedOut = new ArrayList<>();
        boolean consume = true;
        int released;
        int listed;

        Grant lastGrant() {
            return grants.get(grants.size() - 1);
        }

        void add(UUID id, String title, String username, String secret, String... urls) {
            all.add(new Login(id, title, username, List.of(urls)));
            secrets.put(id, secret);
        }

        @Override
        public List<Login> logins() {
            listed++;
            return List.copyOf(all);
        }

        @Override
        public SecretBytes password(Grant grant, UUID entry) {
            grants.add(grant);
            if (consume) {
                grant.consume();
                released++;
            }
            SecretBytes out = SecretBytes.copyOf(secrets.get(entry).getBytes(StandardCharsets.UTF_8));
            handedOut.add(out);
            return out;
        }

        @Override
        public UUID save(Grant grant, Origin origin, String username, SecretChars secret) throws HostException {
            if (failSave) {
                throw new HostException(HostException.Code.INTERNAL);
            }
            grants.add(grant);
            savedUsernames.add(username);
            secret.withChars(c -> savedSecrets.add(String.valueOf(c)));
            if (consume) {
                grant.consume();
            }
            UUID id = UUID.randomUUID();
            saved.add(id);
            savedOrigins.add(origin);
            return id;
        }
    }
}
