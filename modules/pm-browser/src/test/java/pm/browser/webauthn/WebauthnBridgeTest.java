package pm.browser.webauthn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.LongFunction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import pm.approval.ApprovalBroker;
import pm.approval.ApprovalRequest;
import pm.approval.Decision;
import pm.approval.Grant;
import pm.approval.PendingApproval;
import pm.approval.PolicyStore;
import pm.browser.bridge.ApprovalPort;
import pm.browser.bridge.Bridge;
import pm.browser.bridge.PasskeyPort;
import pm.browser.bridge.PasswordGenerator;
import pm.browser.bridge.VaultPort;
import pm.browser.host.Base64Url;
import pm.browser.host.HostException;
import pm.browser.host.Json;
import pm.browser.host.Request;
import pm.crypto.Argon2Params;
import pm.crypto.CryptoException;
import pm.crypto.Hash;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.crypto.passkey.Es256;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.CreatedVault;
import pm.vault.PasskeyException;
import pm.vault.Vault;
import pm.vault.VaultBackups;
import pm.vault.VaultException;
import pm.vault.VaultService;
import pm.vault.record.LoginRecord;
import pm.vault.record.PasskeyRecord;
import pm.vault.record.VaultRecord;

/**
 * {@code webauthn.create} and {@code webauthn.get} end to end: a real {@link ApprovalBroker}, a
 * real vault behind {@link VaultPasskeys}, replies checked as a relying party would (SR-115 to
 * SR-119). Includes the counter monotonicity acceptance test: N sign-ins give strictly
 * increasing counters, and restoring an older backup cannot lower them.
 */
@Tag("T-PK-04")
final class WebauthnBridgeTest {
    private static final String EXT = "abcdefghijklmnopabcdefghijklmnop";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-04T12:00:00Z"), ZoneOffset.UTC);
    private static final String PHRASE = "correct horse battery staple";
    private static final String ORIGIN = "https://login.example.com";
    private static final String RP = "example.com";
    private static final String USER = Base64Url.encode("user-1".getBytes(StandardCharsets.UTF_8));
    private static final int SIGNINS = 5;

    @TempDir
    Path dir;

    private ApprovalBroker broker;
    private final List<ApprovalRequest> prompts = new ArrayList<>();
    private Consumer<PendingApproval> user = PendingApproval::approveOnce;
    private VaultFileStore store;
    private Vault vault;

    @BeforeEach
    void setUp() throws StorageException, VaultException {
        broker = new ApprovalBroker(CLOCK, e -> { }, PolicyStore.inMemory(), "alice");
        broker.setPromptListener(() -> {
            List<PendingApproval> waiting = broker.pending();
            PendingApproval last = waiting.get(waiting.size() - 1);
            prompts.add(last.request());
            user.accept(last);
        });
        broker.unlock();
        store = VaultFileStore.open(dir.resolve("vault.pmv"));
        VaultService service = new VaultService(store, CLOCK, Argon2Params.FLOOR);
        try (SecretChars pw = passphrase(); CreatedVault created = service.create(pw)) {
            created.vault().save();
        }
        vault = unlock(service);
    }

    @AfterEach
    void tearDown() throws StorageException {
        vault.close();
        store.close();
    }

    private static SecretChars passphrase() {
        return SecretChars.takeOwnership(PHRASE.toCharArray());
    }

    private static Vault unlock(VaultService service) throws VaultException {
        try (SecretChars pw = passphrase()) {
            return service.unlockWithPassphrase(pw);
        }
    }

    private Bridge bridge(PasskeyPort port) {
        return (Bridge) Bridge.factory(NO_LOGINS, ApprovalPort.inProcess(broker, Duration.ofSeconds(5)), CLOCK,
                PasswordGenerator.secure(), port).forCaller(EXT);
    }

    private Bridge bridge() {
        return bridge(new VaultPasskeys(vault));
    }

    private static String clientData(String type, String origin) {
        return Base64Url.encode(("{\"type\":\"" + type + "\",\"challenge\":\"Y2hhbGxlbmdl\",\"origin\":\"" + origin
                + "\",\"crossOrigin\":false}").getBytes(StandardCharsets.UTF_8));
    }

    private static Request.WebauthnCreate create(String origin, String rpId, String name, List<Long> algorithms,
            List<String> exclude, Request.UserVerification uv) {
        return new Request.WebauthnCreate("c1", origin, rpId, clientData(ClientData.CREATE, origin),
                new Request.User(USER, name, "Alice A"), algorithms, exclude, uv);
    }

    private static Request.WebauthnCreate create(String rpId) {
        return create(ORIGIN, rpId, "alice", List.of(-8L, -7L), List.of(), Request.UserVerification.PREFERRED);
    }

    private static Request.WebauthnGet get(String rpId, List<String> allow, Optional<String> credential) {
        return new Request.WebauthnGet("g1", ORIGIN, rpId, clientData(ClientData.GET, ORIGIN), allow, credential,
                Request.UserVerification.DISCOURAGED);
    }

    private static Request.WebauthnGet get() {
        return get(RP, List.of(), Optional.empty());
    }

    private static String str(Json.Obj o, String name) {
        return assertInstanceOf(Json.Str.class, o.get(name)).text();
    }

    private static byte[] bytes(Json.Obj o, String name) throws HostException {
        return Base64Url.decode(str(o, name));
    }

    private static HostException refused(Bridge bridge, Request request) {
        return assertThrows(HostException.class, () -> bridge.handle(request));
    }

    private static String profile(UUID id) {
        byte[] bits = ByteBuffer.allocate(16).putLong(id.getMostSignificantBits())
                .putLong(id.getLeastSignificantBits()).array();
        return "pk-" + new BigInteger(1, bits).toString(36);
    }

    /** Signs in once and checks the reply as a relying party: returns the counter. */
    private long signIn(Bridge bridge, byte[] cose, byte[] credentialId) throws HostException, CryptoException {
        Json.Obj reply = bridge.handle(get());
        assertEquals("webauthn.get", str(reply, "type"));
        assertEquals(ORIGIN, str(reply, "origin"));
        assertEquals(RP, str(reply, "rpId"));
        assertArrayEquals(credentialId, bytes(reply, "credentialId"));
        assertArrayEquals("user-1".getBytes(StandardCharsets.UTF_8), bytes(reply, "userHandle"));
        byte[] authData = bytes(reply, "authenticatorData");
        AuthenticatorData parsed = AuthenticatorData.parse(authData);
        assertTrue(parsed.isFor(RP));
        assertEquals(AuthenticatorData.ASSERTION_FLAGS, parsed.flags());
        byte[] cdh = Hash.sha256(Base64Url.decode(clientData(ClientData.GET, ORIGIN)));
        assertTrue(Es256.verify(cose, authData, cdh, bytes(reply, "signature")));
        return parsed.signCount();
    }

    // ---- create -------------------------------------------------------------------------------

    @Test
    void createEnrollsAfterApprovalAndAnswersWithANoneAttestation() throws HostException {
        Json.Obj reply = bridge().handle(create(RP));
        assertEquals("webauthn.create", str(reply, "type"));
        assertEquals("c1", str(reply, "id"));
        assertEquals(ORIGIN, str(reply, "origin"));
        assertEquals(RP, str(reply, "rpId"));
        assertEquals(new Json.Num(Es256.COSE_ALG), reply.get("publicKeyAlgorithm"));
        byte[] authData = bytes(reply, "authenticatorData");
        Map<?, ?> attestation = assertInstanceOf(Map.class, TestCbor.decode(bytes(reply, "attestationObject")));
        assertEquals("none", attestation.get("fmt"));
        assertEquals(Map.of(), attestation.get("attStmt"));
        assertArrayEquals(authData, assertInstanceOf(byte[].class, attestation.get("authData")));
        AuthenticatorData parsed = AuthenticatorData.parse(authData);
        assertTrue(parsed.isFor(RP));
        assertEquals(AuthenticatorData.REGISTRATION_FLAGS, parsed.flags());
        assertEquals(0, parsed.signCount());
        assertArrayEquals(bytes(reply, "credentialId"), parsed.credentialId());
        assertArrayEquals(bytes(reply, "publicKey"), parsed.cosePublicKey());

        ApprovalRequest asked = prompts.get(0);
        assertEquals(ApprovalRequest.Scope.profile(ORIGIN, "passkey-create"), asked.scope());
        assertEquals(new ApprovalRequest.Display(List.of(),
                Optional.of(ORIGIN + " - create a passkey for \"example.com\", account \"alice\""),
                ApprovalRequest.Effect.WRITE_FILE), asked.display());
        List<PasskeyPort.Passkey> held = new VaultPasskeys(vault).passkeys();
        assertEquals(1, held.size());
        assertEquals(RP, held.get(0).rpId());
        assertEquals("alice", held.get(0).accountName());
    }

    @Test
    void aDeniedCreateEnrollsNothing() throws HostException {
        user = PendingApproval::deny;
        assertEquals(HostException.Code.DENIED, refused(bridge(), create(RP)).code());
        assertEquals(1, prompts.size());
        assertTrue(new VaultPasskeys(vault).passkeys().isEmpty());
    }

    @Test
    void createRefusalsHappenBeforeAnyPrompt() throws HostException {
        Bridge bridge = bridge();
        // An RP ID the origin may not use, and client data for another origin or ceremony.
        assertEquals(HostException.Code.BAD_RP_ID, refused(bridge, create("other.com")).code());
        assertEquals(HostException.Code.BAD_RP_ID, refused(bridge, create("www.login.example.com")).code());
        assertEquals(HostException.Code.BAD_RP_ID, refused(bridge, create("com")).code());
        assertEquals(HostException.Code.BAD_CLIENT_DATA, refused(bridge, new Request.WebauthnCreate("c", ORIGIN, RP,
                clientData(ClientData.CREATE, "https://example.com"), new Request.User(USER, "alice", ""), List.of(),
                List.of(), Request.UserVerification.PREFERRED)).code());
        assertEquals(HostException.Code.BAD_CLIENT_DATA, refused(bridge, new Request.WebauthnCreate("c", ORIGIN, RP,
                clientData(ClientData.GET, ORIGIN), new Request.User(USER, "alice", ""), List.of(),
                List.of(), Request.UserVerification.PREFERRED)).code());
        assertEquals(HostException.Code.UNSUPPORTED_ALGORITHM, refused(bridge,
                create(ORIGIN, RP, "alice", List.of(-257L), List.of(), Request.UserVerification.PREFERRED)).code());
        assertEquals(HostException.Code.UV_REQUIRED, refused(bridge,
                create(ORIGIN, RP, "alice", List.of(), List.of(), Request.UserVerification.REQUIRED)).code());
        assertEquals(HostException.Code.BAD_FIELD, refused(bridge,
                create(ORIGIN, RP, Character.toString(0x200b) + Character.toString(0x202e), List.of(), List.of(),
                        Request.UserVerification.PREFERRED)).code());
        assertTrue(prompts.isEmpty());
        assertTrue(new VaultPasskeys(vault).passkeys().isEmpty());
    }

    /**
     * WebAuthn L3 §6.3.2 step 3 (fix round, item 5): an excluded credential is reported only after
     * the user consented; a denial answers DENIED, as for any create, so the page cannot probe the
     * vault without a prompt.
     */
    @Test
    void anExcludedCredentialIsReportedOnlyAfterTheUserConsents() throws HostException {
        Bridge bridge = bridge();
        String first = str(bridge.handle(create(RP)), "credentialId");
        String other = str(bridge.handle(create("login.example.com")), "credentialId");
        assertEquals(HostException.Code.EXCLUDED, refused(bridge, create(ORIGIN, RP, "bob", List.of(),
                List.of(first), Request.UserVerification.PREFERRED)).code());
        assertEquals(3, prompts.size());
        assertEquals(2, new VaultPasskeys(vault).passkeys().size());
        user = PendingApproval::deny;
        assertEquals(HostException.Code.DENIED, refused(bridge, create(ORIGIN, RP, "bob", List.of(),
                List.of(first), Request.UserVerification.PREFERRED)).code());
        assertEquals(4, prompts.size());
        assertEquals(2, new VaultPasskeys(vault).passkeys().size());
        user = PendingApproval::approveOnce;
        // Excluding a credential held for another RP ID, or an unknown one, does not refuse.
        bridge.handle(create(ORIGIN, RP, "bob", List.of(), List.of(other, "AQID"),
                Request.UserVerification.DISCOURAGED));
        assertEquals(5, prompts.size());
        assertEquals(3, new VaultPasskeys(vault).passkeys().size());
    }

    /**
     * Fix round, items 1 and 2: enrollment always prompts. A session answer counts once, so three
     * creates need three prompts, each offering no standing grant.
     */
    @Test
    void everyEnrollmentPromptsEvenAfterASessionAnswer() throws HostException {
        user = PendingApproval::approveForSession;
        Bridge bridge = bridge();
        for (String name : List.of("alice", "bob", "carol")) {
            bridge.handle(create(ORIGIN, RP, name, List.of(), List.of(), Request.UserVerification.PREFERRED));
        }
        assertEquals(3, prompts.size());
        assertEquals(3, new VaultPasskeys(vault).passkeys().size());
        user = PendingApproval::deny;
        assertEquals(HostException.Code.DENIED, refused(bridge, create(RP)).code());
        assertEquals(4, prompts.size());
        assertEquals(3, new VaultPasskeys(vault).passkeys().size());
        assertOnlyPasskeyPrompts();
    }

    private void assertOnlyPasskeyPrompts() {
        for (ApprovalRequest asked : prompts) {
            assertEquals(ApprovalRequest.Operation.PASSKEY, asked.operation());
            assertFalse(asked.allowsStandingGrant());
        }
        assertTrue(broker.temporaryPolicies().isEmpty());
    }

    // ---- get ----------------------------------------------------------------------------------

    @Test
    void countersStrictlyIncreaseAndARestoreCannotLowerThem()
            throws HostException, CryptoException, VaultException, StorageException {
        Json.Obj created = bridge().handle(create(RP));
        byte[] cose = bytes(created, "publicKey");
        byte[] credentialId = bytes(created, "credentialId");
        long last = signIn(bridge(), cose, credentialId);
        assertEquals(1, last);
        VaultBackups backups = new VaultBackups(CLOCK);
        Path backup = backups.create(vault, dir.resolve("backups"), 1).file();
        for (int i = 0; i < SIGNINS; i++) {
            long next = signIn(bridge(), cose, credentialId);
            assertTrue(next > last, next + " after " + last);
            last = next;
        }
        assertEquals(1 + SIGNINS, last);

        // Put the older backup back over the vault, then sign in again.
        vault.close();
        store.close();
        try (SecretChars pw = passphrase()) {
            assertTrue(backups.restore(backup, dir.resolve("vault.pmv"), pw, true).replacedExisting());
        }
        store = VaultFileStore.open(dir.resolve("vault.pmv"));
        vault = unlock(new VaultService(store, CLOCK, Argon2Params.FLOOR));
        long afterRestore = signIn(bridge(), cose, credentialId);
        assertTrue(afterRestore > last, afterRestore + " after " + last);

        ApprovalRequest asked = prompts.get(prompts.size() - 1);
        UUID id = new VaultPasskeys(vault).passkeys().get(0).id();
        assertEquals(ApprovalRequest.Scope.profile(ORIGIN, profile(id)), asked.scope());
        assertEquals(new ApprovalRequest.Display(List.of(),
                Optional.of(ORIGIN + " - sign in to \"example.com\" with a passkey, account \"alice\""),
                ApprovalRequest.Effect.SEND), asked.display());
    }

    /**
     * Fix round, item 1: a sign-in always prompts. After an "s" answer the next get prompts again,
     * and each assertion carries flags 0x19 (UP, BE, BS) and a higher counter.
     */
    @Test
    void aSessionAnswerCountsOnceSoTheNextGetPromptsAgain() throws HostException, CryptoException {
        Bridge bridge = bridge();
        Json.Obj created = bridge.handle(create(RP));
        user = PendingApproval::approveForSession;
        long last = 0;
        for (int i = 1; i <= SIGNINS; i++) {
            long next = signIn(bridge, bytes(created, "publicKey"), bytes(created, "credentialId"));
            assertTrue(next > last, next + " after " + last);
            last = next;
            assertEquals(1 + i, prompts.size());
        }
        assertEquals(0x19, AuthenticatorData.ASSERTION_FLAGS);
        assertOnlyPasskeyPrompts();
    }

    /**
     * Fix round, item 1: a policy answer stores no policy, so after the broker locks and unlocks
     * (and without either) a get still prompts.
     */
    @Test
    void aPolicyAnswerLeavesNoPolicySoAGetAfterLockAndUnlockPrompts() throws HostException, CryptoException {
        Bridge bridge = bridge();
        Json.Obj created = bridge.handle(create(RP));
        byte[] cose = bytes(created, "publicKey");
        byte[] credentialId = bytes(created, "credentialId");
        user = pending -> pending.approveForPolicy(Duration.ofHours(24));
        assertEquals(1, signIn(bridge, cose, credentialId));
        assertEquals(2, prompts.size());
        assertTrue(broker.temporaryPolicies().isEmpty());
        broker.lock();
        broker.unlock();
        assertEquals(2, signIn(bridge, cose, credentialId));
        assertEquals(3, prompts.size());
        assertEquals(3, signIn(bridge, cose, credentialId));
        assertEquals(4, prompts.size());
        assertOnlyPasskeyPrompts();
    }

    @Test
    void aDeniedGetSignsNothing() throws HostException, CryptoException {
        Json.Obj created = bridge().handle(create(RP));
        user = PendingApproval::deny;
        assertEquals(HostException.Code.DENIED, refused(bridge(), get()).code());
        user = PendingApproval::approveOnce;
        // The counter did not move for the denied request.
        assertEquals(1, signIn(bridge(), bytes(created, "publicKey"), bytes(created, "credentialId")));
    }

    @Test
    void theCredentialIsChosenFromTheAllowListAndTheRpId() throws HostException {
        // A login in the same vault is not a passkey and is never listed.
        vault.put(new LoginRecord(UUID.randomUUID(), "Example", "alice",
                SecretBytes.copyOf("pw".getBytes(StandardCharsets.UTF_8)), List.of("https://example.com"), "",
                List.of(), CLOCK.instant(), CLOCK.instant(), CLOCK.instant()));
        Bridge bridge = bridge();
        String a = str(bridge.handle(create(RP)), "credentialId");
        String b = str(bridge.handle(create(ORIGIN, RP, "bob", List.of(), List.of(), Request.UserVerification.PREFERRED)),
                "credentialId");
        String sub = str(bridge.handle(create("login.example.com")), "credentialId");
        prompts.clear();

        // Two passkeys for the RP ID and none named: the extension must choose.
        assertEquals(HostException.Code.AMBIGUOUS, refused(bridge, get()).code());
        // The allow list narrows it to one.
        assertEquals(a, str(bridge.handle(get(RP, List.of(a), Optional.empty())), "credentialId"));
        // A named credential: must be allowed, held, and for this RP ID.
        assertEquals(b, str(bridge.handle(get(RP, List.of(), Optional.of(b))), "credentialId"));
        assertEquals(b, str(bridge.handle(get(RP, List.of(a, b), Optional.of(b))), "credentialId"));
        assertEquals(HostException.Code.NOT_ALLOWED, refused(bridge, get(RP, List.of(a), Optional.of(b))).code());
        assertEquals(HostException.Code.NOT_FOUND, refused(bridge, get(RP, List.of(), Optional.of(sub))).code());
        assertEquals(HostException.Code.NOT_FOUND, refused(bridge, get(RP, List.of(), Optional.of("AQID"))).code());
        // Nothing allowed is held; and an allow list naming another RP ID's credential.
        assertEquals(HostException.Code.NOT_FOUND, refused(bridge, get(RP, List.of("AQID"), Optional.empty())).code());
        assertEquals(HostException.Code.NOT_FOUND, refused(bridge, get(RP, List.of(sub), Optional.empty())).code());
        assertEquals(sub, str(bridge.handle(get("login.example.com", List.of(), Optional.empty())), "credentialId"));
        assertEquals(4, prompts.size());
    }

    @Test
    void getRefusalsHappenBeforeAnyPrompt() throws HostException {
        Bridge bridge = bridge();
        bridge.handle(create(RP));
        prompts.clear();
        assertEquals(HostException.Code.BAD_RP_ID, refused(bridge, get("evil.com", List.of(), Optional.empty())).code());
        assertEquals(HostException.Code.BAD_CLIENT_DATA, refused(bridge, new Request.WebauthnGet("g", ORIGIN, RP,
                clientData(ClientData.GET, "https://evil.com"), List.of(), Optional.empty(),
                Request.UserVerification.PREFERRED)).code());
        assertEquals(HostException.Code.UV_REQUIRED, refused(bridge, new Request.WebauthnGet("g", ORIGIN, RP,
                clientData(ClientData.GET, ORIGIN), List.of(), Optional.empty(),
                Request.UserVerification.REQUIRED)).code());
        assertEquals(HostException.Code.BAD_RP_ID, refused(bridge, new Request.WebauthnGet("g",
                "http://login.example.com", RP, clientData(ClientData.GET, "http://login.example.com"), List.of(),
                Optional.empty(), Request.UserVerification.PREFERRED)).code());
        assertTrue(prompts.isEmpty());
    }

    // ---- locked, unsupported and misbehaving ports --------------------------------------------

    @Test
    void lockedBrokerOrVaultReleasesNothing() throws HostException {
        bridge().handle(create(RP));
        prompts.clear();
        broker.lock();
        assertEquals("DENIED_LOCKED", refused(bridge(), get()).getMessage());
        assertEquals("DENIED_LOCKED", refused(bridge(), create(RP)).getMessage());
        broker.unlock();
        vault.close();
        assertEquals("DENIED_LOCKED", refused(bridge(), get()).getMessage());
        assertEquals("DENIED_LOCKED", refused(bridge(), create(RP)).getMessage());
        assertTrue(prompts.isEmpty());
    }

    @Test
    void aBridgeWithoutPasskeysRefusesWebauthn() {
        assertEquals(HostException.Code.UNKNOWN_TYPE, refused(bridge(PasskeyPort.NONE), get()).code());
        assertEquals(HostException.Code.UNKNOWN_TYPE, refused(bridge(PasskeyPort.NONE), create(RP)).code());
        assertThrows(HostException.class, () -> PasskeyPort.NONE.create(null, RP, new byte[1], "a", "a"));
        assertThrows(HostException.class,
                () -> PasskeyPort.NONE.sign(null, UUID.randomUUID(), new byte[32], c -> new byte[0]));
        assertTrue(prompts.isEmpty());
    }

    @Test
    void portRefusalsAndUnconsumedGrantsAnswerNothing() {
        FakePort exhausted = new FakePort(true, new HostException(HostException.Code.COUNTER_EXHAUSTED));
        assertEquals(HostException.Code.COUNTER_EXHAUSTED, refused(bridge(exhausted), get()).code());
        FakePort lazy = new FakePort(false, null);
        assertEquals(HostException.Code.INTERNAL, refused(bridge(lazy), get()).code());
        assertEquals(HostException.Code.INTERNAL, refused(bridge(lazy), create(RP)).code());
        assertEquals(3, prompts.size());
    }

    /** VaultPasskeys passes only codes to the browser, and consumes grants before acting. */
    @Test
    void vaultRefusalsMapToReplyCodes() {
        assertEquals("DENIED_LOCKED", VaultPasskeys.map(failure(PasskeyException.Code.LOCKED)).getMessage());
        assertEquals(HostException.Code.NOT_FOUND, VaultPasskeys.map(failure(PasskeyException.Code.NOT_FOUND)).code());
        assertEquals(HostException.Code.COUNTER_EXHAUSTED,
                VaultPasskeys.map(failure(PasskeyException.Code.COUNTER_EXHAUSTED)).code());
        assertEquals(HostException.Code.BAD_FIELD, VaultPasskeys.map(failure(PasskeyException.Code.BAD_INPUT)).code());
        for (PasskeyException.Code code : List.of(PasskeyException.Code.REENTRANT, PasskeyException.Code.SAVE_FAILED,
                PasskeyException.Code.BAD_KEY)) {
            assertEquals(HostException.Code.INTERNAL, VaultPasskeys.map(failure(code)).code());
        }
    }

    @Test
    void vaultPasskeysRefusesUnknownPasskeysAndBadNames() throws HostException {
        Bridge bridge = bridge();
        bridge.handle(create(RP));
        VaultPasskeys port = new VaultPasskeys(vault);
        Grant grant = lastGrant();
        assertEquals(HostException.Code.NOT_FOUND, assertThrows(HostException.class,
                () -> port.sign(grant, UUID.randomUUID(), new byte[32], c -> new byte[37])).code());
        assertEquals(HostException.Code.BAD_FIELD, assertThrows(HostException.class,
                () -> port.create(lastGrant(), RP, new byte[0], "alice", "")).code());
        assertFalse(port.passkeys().isEmpty());
    }

    // ---- the port checks its grant (ticket 004) -----------------------------------------------

    /**
     * First probe: a 1-hour policy answer to an autofill request on the passkey's own origin and
     * profile makes the next such grant silent. The port refuses it for a sign-in and for an
     * enrollment: no signature, no new passkey, counter unchanged, grant unused, and no prompt.
     */
    @Test
    void thePortRefusesASilentAutofillGrantForTheSamePasskey() throws HostException {
        bridge().handle(create(RP));
        VaultPasskeys port = new VaultPasskeys(vault);
        UUID id = port.passkeys().get(0).id();
        user = pending -> pending.approveForPolicy(Duration.ofHours(1));
        grant(ApprovalRequest.Operation.AUTOFILL, ORIGIN, profile(id));
        grant(ApprovalRequest.Operation.AUTOFILL, ORIGIN, PasskeyPort.createProfile());
        int asked = prompts.size();
        Grant silent = grant(ApprovalRequest.Operation.AUTOFILL, ORIGIN, profile(id));
        Grant silentEnroll = grant(ApprovalRequest.Operation.AUTOFILL, ORIGIN, PasskeyPort.createProfile());
        assertEquals(asked, prompts.size(), "the policy answers both without a prompt");
        assertEquals(Decision.ALLOWED_POLICY, silent.decision());

        assertEquals(HostException.Code.GRANT_MISMATCH,
                code(() -> port.sign(silent, id, new byte[32], c -> AuthenticatorData.assertion(RP, c))));
        assertEquals(HostException.Code.GRANT_MISMATCH,
                code(() -> port.create(silentEnroll, RP, new byte[] {1}, "mallory", "")));
        assertFalse(silent.isUsed());
        assertFalse(silentEnroll.isUsed());
        assertEquals(0, counter(id));
        assertEquals(1, port.passkeys().size());
        assertEquals(asked, prompts.size());
    }

    /**
     * Second probe: a sign-in grant for passkey A cannot sign with passkey B or enroll, and a
     * passkey grant on an origin that may not use the RP ID (or no origin at all) does nothing.
     * The grant for A still signs with A afterwards.
     */
    @Test
    void thePortRefusesAGrantForAnotherPasskeyOrOrigin() throws HostException {
        bridge().handle(create(RP));
        bridge().handle(create(ORIGIN, RP, "bob", List.of(-7L), List.of(), Request.UserVerification.PREFERRED));
        VaultPasskeys port = new VaultPasskeys(vault);
        UUID a = port.passkeys().get(0).id();
        UUID b = port.passkeys().get(1).id();
        Grant forA = grant(ApprovalRequest.Operation.PASSKEY, ORIGIN, PasskeyPort.signInProfile(a));
        assertEquals(profile(a), forA.request().scope().profile());

        assertEquals(HostException.Code.GRANT_MISMATCH,
                code(() -> port.sign(forA, b, new byte[32], c -> AuthenticatorData.assertion(RP, c))));
        assertEquals(HostException.Code.GRANT_MISMATCH,
                code(() -> port.create(forA, RP, new byte[] {1}, "carol", "")));
        Grant elsewhere = grant(ApprovalRequest.Operation.PASSKEY, "https://login.example.net",
                PasskeyPort.signInProfile(a));
        assertEquals(HostException.Code.GRANT_MISMATCH,
                code(() -> port.sign(elsewhere, a, new byte[32], c -> AuthenticatorData.assertion(RP, c))));
        Grant enrollElsewhere = grant(ApprovalRequest.Operation.PASSKEY, "https://example.org",
                PasskeyPort.createProfile());
        assertEquals(HostException.Code.GRANT_MISMATCH,
                code(() -> port.create(enrollElsewhere, RP, new byte[] {1}, "carol", "")));
        Grant noOrigin = grant(ApprovalRequest.Operation.PASSKEY, "app", PasskeyPort.createProfile());
        assertEquals(HostException.Code.GRANT_MISMATCH,
                code(() -> port.create(noOrigin, RP, new byte[] {1}, "carol", "")));
        for (Grant refused : List.of(forA, elsewhere, enrollElsewhere, noOrigin)) {
            assertFalse(refused.isUsed());
        }
        assertEquals(0, counter(a));
        assertEquals(0, counter(b));
        assertEquals(2, port.passkeys().size());

        assertEquals(1, port.sign(forA, a, new byte[32], c -> AuthenticatorData.assertion(RP, c)).signCount());
        assertTrue(forA.isUsed());
        assertEquals(1, counter(a));
        assertEquals(0, counter(b));
    }

    /** With no Public Suffix List the port cannot check a grant's origin, so it refuses. */
    @Test
    void thePortRefusesEveryGrantWithoutAPublicSuffixList() throws HostException {
        VaultPasskeys port = new VaultPasskeys(vault, RpId.from(() -> {
            throw new IOException("gone");
        }));
        Grant enroll = grant(ApprovalRequest.Operation.PASSKEY, ORIGIN, PasskeyPort.createProfile());
        assertEquals(HostException.Code.PSL_UNAVAILABLE,
                code(() -> port.create(enroll, RP, new byte[] {1}, "alice", "")));
        assertFalse(enroll.isUsed());
        assertTrue(port.passkeys().isEmpty());
    }

    /** A grant for {@code operation} on {@code origin} and {@code profile}, answered by {@link #user}. */
    private Grant grant(ApprovalRequest.Operation operation, String origin, String profile) {
        return ApprovalPort.inProcess(broker, Duration.ofSeconds(5)).approve(new ApprovalRequest(UUID.randomUUID(),
                new ApprovalRequest.Requester(ApprovalRequest.Kind.EXTENSION, EXT), operation,
                ApprovalRequest.Scope.profile(origin, profile), Duration.ZERO,
                new ApprovalRequest.Display(List.of(), Optional.of(origin + " - probe"), ApprovalRequest.Effect.SEND),
                CLOCK.instant())).grant().orElseThrow();
    }

    /** The saved counter of passkey {@code id}. */
    private long counter(UUID id) {
        for (VaultRecord record : vault.records()) {
            if (record.id().equals(id)) {
                try (PasskeyRecord view = PasskeyRecord.class.cast(record)) {
                    return view.signCount();
                }
            }
        }
        throw new AssertionError(id);
    }

    private static HostException.Code code(Executable call) {
        return assertThrows(HostException.class, call).code();
    }

    /** A fresh grant for a request like the first one prompted. */
    private Grant lastGrant() {
        ApprovalRequest asked = prompts.get(0);
        return ApprovalPort.inProcess(broker, Duration.ofSeconds(5)).approve(new ApprovalRequest(UUID.randomUUID(),
                asked.requester(), asked.operation(), asked.scope(), asked.duration(), asked.display(),
                CLOCK.instant())).grant().orElseThrow();
    }

    private static PasskeyException failure(PasskeyException.Code code) {
        return new PasskeyException(code, null);
    }

    /** A port holding one passkey for {@link #RP} that may skip consuming the grant, or fail. */
    private static final class FakePort implements PasskeyPort {
        private final boolean consume;
        private final HostException failure;

        FakePort(boolean consume, HostException failure) {
            this.consume = consume;
            this.failure = failure;
        }

        @Override
        public List<Passkey> passkeys() {
            return List.of(new Passkey(UUID.randomUUID(), RP, new byte[] {1}, new byte[] {2}, "alice"));
        }

        @Override
        public Created create(Grant grant, String rpId, byte[] userHandle, String accountName, String displayName) {
            return new Created(UUID.randomUUID(), new byte[] {1}, new byte[0]);
        }

        @Override
        public Signed sign(Grant grant, UUID id, byte[] clientDataHash, LongFunction<byte[]> authenticatorData)
                throws HostException {
            if (consume) {
                grant.consume();
            }
            if (failure != null) {
                throw failure;
            }
            return new Signed(1, authenticatorData.apply(1), new byte[] {3});
        }
    }

    /** No logins: these tests use only the WebAuthn actions. */
    private static final VaultPort NO_LOGINS = new VaultPort() {
        @Override
        public List<Login> logins() {
            return List.of();
        }

        @Override
        public SecretBytes password(Grant grant, UUID entry) throws HostException {
            throw new HostException(HostException.Code.NOT_FOUND);
        }

        @Override
        public UUID save(Grant grant, pm.browser.bridge.Origin origin, String username, SecretChars password)
                throws HostException {
            throw new HostException(HostException.Code.NOT_FOUND);
        }
    };
}
