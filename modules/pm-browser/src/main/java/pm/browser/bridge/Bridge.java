package pm.browser.bridge;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import pm.approval.ApprovalRequest;
import pm.approval.ApprovalRequest.Effect;
import pm.approval.Decision;
import pm.approval.Grant;
import pm.approval.Outcome;
import pm.browser.host.Handler;
import pm.browser.host.Base64Url;
import pm.browser.host.HostException;
import pm.browser.host.Json;
import pm.browser.host.Messages;
import pm.browser.host.Request;
import pm.browser.webauthn.AttestationObject;
import pm.browser.webauthn.AuthenticatorData;
import pm.browser.webauthn.ClientData;
import pm.browser.webauthn.RpId;
import pm.crypto.ConstantTime;
import pm.crypto.Csprng;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.crypto.passkey.Es256;
import pm.vault.record.PasskeyRecord;

/**
 * Answers the extension's requests (ADR 0014 §6). Every origin is canonicalised first and logins
 * match only on exact {@link Origin} equality. {@code lookup} returns metadata; {@code fill},
 * {@code save} and {@code generate} each submit one {@link ApprovalRequest} and release nothing
 * unless the broker returns a {@link Grant} for exactly that request, which the vault port then
 * consumes (SR-302, SR-307).
 *
 * <p>Each request is {@code AUTOFILL} by requester {@code (EXTENSION, extension id)} with scope
 * project = the canonical origin and no record ids. The profile is the action: {@code save},
 * {@code generate}, or for a fill {@code fill-} followed by the login id in base 36, so a
 * session or temporary policy the user grants covers one extension, one origin, one action and
 * (for fills) one login, and nothing else. The prompt's display line names the origin
 * and the login or username concerned, never a password.
 *
 * <p>{@code generate} stores the new password as a login before releasing it, under the same
 * grant, so a generated password can never exist only in the page.
 *
 * <p>{@code webauthn.create} and {@code webauthn.get} (M6.3, ADR 0016 M6.3 addendum) make pm a
 * WebAuthn authenticator for the extension. Before any prompt, the RP ID is checked against the
 * origin ({@link RpId}), the client data against the type and origin ({@link ClientData}), and
 * a get's credential choice against the vault. Both ask under operation {@code PASSKEY}, which
 * always prompts: a session or policy answer counts once and leaves nothing behind, because the
 * authenticator data claims user presence for every use. Enrollment asks under profile
 * {@code passkey-create}; a sign-in asks under {@code pk-} followed by the passkey's record id in
 * base 36. The display line names the origin, the RP ID and the account. A create whose
 * {@code excludeCredentials} names a passkey the vault holds for the RP ID is refused only after
 * the user approved it (WebAuthn L3 §6.3.2 step 3). Keys stay in the vault ({@link PasskeyPort}).
 */
public final class Bridge implements Handler {
    /** Most logins one {@code lookup} returns. */
    public static final int MAX_LOOKUP = 64;

    private static final String ACTION_FILL = "fill";
    private static final String ACTION_SAVE = "save";
    private static final String ACTION_GENERATE = "generate";
    private static final String ACTION_LOOKUP = "lookup";
    private static final String FILL_PROFILE_PREFIX = "fill-";
    private static final String TYPE_WEBAUTHN_CREATE = "webauthn.create";
    private static final String TYPE_WEBAUTHN_GET = "webauthn.get";
    /** The profile of a passkey enrollment on an origin. */
    static final String ACTION_PASSKEY_CREATE = "passkey-create";
    /** {@code pk-} and the passkey record id in base 36: one profile per passkey. */
    static final String PASSKEY_GET_PROFILE_PREFIX = "pk-";
    /** A get naming no credential needs exactly this many candidates. */
    private static final int ONLY_CANDIDATE = 1;
    private static final int UUID_BYTES = 16;
    /** Longest title or username shown in a prompt, in code points. */
    private static final int MAX_SHOWN = 64;
    private static final int SUBSTITUTE = '?';

    private final String extensionId;
    private final VaultPort vault;
    private final ApprovalPort approvals;
    private final Clock clock;
    private final PasswordGenerator generator;
    private final PasskeyPort passkeys;
    private final RpId rpIds;

    /** A bridge for requests from extension {@code extensionId}, without passkeys. */
    public Bridge(String extensionId, VaultPort vault, ApprovalPort approvals, Clock clock,
            PasswordGenerator generator) {
        this(extensionId, vault, approvals, clock, generator, PasskeyPort.NONE);
    }

    /** A bridge for requests from extension {@code extensionId}, with WebAuthn over {@code passkeys}. */
    public Bridge(String extensionId, VaultPort vault, ApprovalPort approvals, Clock clock,
            PasswordGenerator generator, PasskeyPort passkeys) {
        this(extensionId, vault, approvals, clock, generator, passkeys, RpId.vendored());
    }

    /**
     * A bridge with WebAuthn over {@code passkeys}, checking RP IDs with {@code rpIds} (the
     * vendored list in production; a damaged one in tests).
     */
    public Bridge(String extensionId, VaultPort vault, ApprovalPort approvals, Clock clock,
            PasswordGenerator generator, PasskeyPort passkeys, RpId rpIds) {
        this.rpIds = Objects.requireNonNull(rpIds, "rpIds");
        this.extensionId = Objects.requireNonNull(extensionId, "extensionId");
        this.vault = Objects.requireNonNull(vault, "vault");
        this.approvals = Objects.requireNonNull(approvals, "approvals");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.generator = Objects.requireNonNull(generator, "generator");
        this.passkeys = Objects.requireNonNull(passkeys, "passkeys");
    }

    /** A factory making one bridge per allowlisted caller, without passkeys. */
    public static Handler.Factory factory(VaultPort vault, ApprovalPort approvals, Clock clock,
            PasswordGenerator generator) {
        return factory(vault, approvals, clock, generator, PasskeyPort.NONE);
    }

    /** A factory making one bridge per allowlisted caller, with WebAuthn over {@code passkeys}. */
    public static Handler.Factory factory(VaultPort vault, ApprovalPort approvals, Clock clock,
            PasswordGenerator generator, PasskeyPort passkeys) {
        return factory(vault, approvals, clock, generator, passkeys, RpId.vendored());
    }

    /** A factory making one bridge per allowlisted caller, checking RP IDs with {@code rpIds}. */
    public static Handler.Factory factory(VaultPort vault, ApprovalPort approvals, Clock clock,
            PasswordGenerator generator, PasskeyPort passkeys, RpId rpIds) {
        return id -> new Bridge(id, vault, approvals, clock, generator, passkeys, rpIds);
    }

    @Override
    public Json.Obj handle(Request request) throws HostException {
        return switch (request) {
            case Request.Hello hello -> Messages.hello(hello);
            case Request.Lookup lookup -> lookup(lookup);
            case Request.Fill fill -> fill(fill);
            case Request.Save save -> save(save);
            case Request.Generate generate -> generate(generate);
            case Request.WebauthnCreate create -> webauthnCreate(create);
            case Request.WebauthnGet get -> webauthnGet(get);
        };
    }

    /** The canonical origin of {@code text}, once the vault is known to be unlocked. */
    private Origin unlockedOrigin(String text) throws HostException {
        if (!approvals.isUnlocked()) {
            throw HostException.denied(Decision.DENIED_LOCKED);
        }
        return Origin.parse(text);
    }

    private Json.Obj lookup(Request.Lookup request) throws HostException {
        Origin origin = unlockedOrigin(request.origin());
        List<Json> entries = new ArrayList<>();
        for (VaultPort.Login login : vault.logins()) {
            if (entries.size() < MAX_LOOKUP && registeredFor(login, origin)) {
                Map<String, Json> entry = new LinkedHashMap<>();
                entry.put("entry", Json.Str.of(login.id().toString()));
                entry.put("title", Json.Str.of(login.title()));
                entry.put("username", Json.Str.of(login.username()));
                entries.add(new Json.Obj(entry));
            }
        }
        Map<String, Json> reply = Messages.reply(ACTION_LOOKUP, request.id());
        reply.put("origin", Json.Str.of(origin.text()));
        reply.put("entries", new Json.Arr(entries));
        return new Json.Obj(reply);
    }

    private Json.Obj fill(Request.Fill request) throws HostException {
        Origin origin = unlockedOrigin(request.origin());
        VaultPort.Login login = vault.logins().stream()
                .filter(l -> l.id().equals(request.entry()) && registeredFor(l, origin))
                .findFirst()
                .orElseThrow(() -> new HostException(HostException.Code.NOT_FOUND));
        Grant grant = approve(origin, fillProfile(login.id()), Effect.SEND,
                "fill login \"" + shown(login.title()) + "\", username \"" + shown(login.username()) + "\"");
        Json.Str secret;
        try (SecretBytes released = vault.password(grant, login.id())) {
            requireConsumed(grant);
            secret = Json.Str.ofUtf8(released);
        }
        Map<String, Json> reply = Messages.reply(ACTION_FILL, request.id());
        reply.put("origin", Json.Str.of(origin.text()));
        reply.put("username", Json.Str.of(login.username()));
        reply.put("password", secret);
        return new Json.Obj(reply);
    }

    private Json.Obj save(Request.Save request) throws HostException {
        Origin origin = unlockedOrigin(request.origin());
        Grant grant = approve(origin, ACTION_SAVE, Effect.WRITE_FILE,
                "save a new login, username \"" + shown(request.username()) + "\"");
        UUID saved = vault.save(grant, origin, request.username(), request.password());
        requireConsumed(grant);
        Map<String, Json> reply = Messages.reply(ACTION_SAVE, request.id());
        reply.put("entry", Json.Str.of(saved.toString()));
        return new Json.Obj(reply);
    }

    private Json.Obj generate(Request.Generate request) throws HostException {
        Origin origin = unlockedOrigin(request.origin());
        Grant grant = approve(origin, ACTION_GENERATE, Effect.WRITE_FILE,
                "generate a password, save it as a new login (username \""
                        + shown(request.username()) + "\") and fill it");
        Json.Str secret;
        UUID saved;
        try (SecretChars generated = generator.generate(request.policy())) {
            // Stored first: if the save fails, nothing is released, so the page never holds a
            // password that pm does not.
            saved = vault.save(grant, origin, request.username(), generated);
            requireConsumed(grant);
            secret = Json.Str.of(generated);
        }
        Map<String, Json> reply = Messages.reply(ACTION_GENERATE, request.id());
        reply.put("origin", Json.Str.of(origin.text()));
        reply.put("entry", Json.Str.of(saved.toString()));
        reply.put("password", secret);
        return new Json.Obj(reply);
    }

    /**
     * {@code webauthn.create} (ADR 0016 M6.3 addendum, SR-115 to SR-119): checks the RP ID against
     * the origin, the client data, the algorithms, user verification and the user fields, asks the
     * broker, then refuses with {@code EXCLUDED} if the vault holds an excluded credential for the
     * RP ID (so the page learns that only after consent), else has the vault generate and save
     * the passkey and answers with the {@code none} attestation object. Nothing is enrolled
     * without a grant for exactly this request.
     */
    private Json.Obj webauthnCreate(Request.WebauthnCreate request) throws HostException {
        Origin origin = unlockedOrigin(request.origin());
        String rpId = rpIds.validate(origin, request.rpId());
        ClientData.hash(Base64Url.decode(request.clientDataJson()), ClientData.CREATE, origin);
        if (!request.algorithms().isEmpty() && !request.algorithms().contains((long) Es256.COSE_ALG)) {
            throw new HostException(HostException.Code.UNSUPPORTED_ALGORITHM);
        }
        refuseRequiredVerification(request.userVerification());
        List<byte[]> excluded = decodeAll(request.excludeCredentials());
        // Read before the prompt, so a locked vault or a host without passkeys asks nothing; the
        // answer is acted on only after the user consented (WebAuthn L3 §6.3.2 step 3).
        boolean holdsExcluded = false;
        for (PasskeyPort.Passkey held : passkeys.passkeys()) {
            holdsExcluded |= held.rpId().equals(rpId) && contains(excluded, held.credentialId());
        }
        String name = PasskeyRecord.displaySafe(request.user().name());
        String displayName = PasskeyRecord.displaySafe(request.user().displayName());
        if (name.isEmpty()) {
            throw new HostException(HostException.Code.BAD_FIELD);
        }
        byte[] userHandle = Base64Url.decode(request.user().id());
        Grant grant = approve(ApprovalRequest.Operation.PASSKEY, origin, ACTION_PASSKEY_CREATE, Effect.WRITE_FILE,
                "create a passkey for \"" + rpId + "\", account \"" + shown(name) + "\"");
        if (holdsExcluded) {
            // The user consented to this create; nothing is enrolled.
            grant.consume();
            throw new HostException(HostException.Code.EXCLUDED);
        }
        PasskeyPort.Created created = passkeys.create(grant, rpId, userHandle, name, displayName);
        requireConsumed(grant);
        byte[] authenticatorData = AuthenticatorData.registration(rpId, created.credentialId(),
                created.cosePublicKey());
        Map<String, Json> reply = Messages.reply(TYPE_WEBAUTHN_CREATE, request.id());
        reply.put("origin", Json.Str.of(origin.text()));
        reply.put("rpId", Json.Str.of(rpId));
        reply.put("credentialId", Json.Str.of(Base64Url.encode(created.credentialId())));
        reply.put("attestationObject", Json.Str.of(Base64Url.encode(AttestationObject.none(authenticatorData))));
        reply.put("authenticatorData", Json.Str.of(Base64Url.encode(authenticatorData)));
        reply.put("publicKey", Json.Str.of(Base64Url.encode(created.cosePublicKey())));
        reply.put("publicKeyAlgorithm", new Json.Num(Es256.COSE_ALG));
        return new Json.Obj(reply);
    }

    /**
     * {@code webauthn.get} (ADR 0016 M6.3 addendum, SR-117 to SR-119): checks the RP ID, client
     * data and user verification, picks the passkey (the one named, which must be held for this
     * RP ID and allowed; or the only one held for this RP ID and allowed), asks the broker for that
     * passkey on this origin, then has the vault advance and save the counter and sign
     * authenticator data carrying that counter.
     */
    private Json.Obj webauthnGet(Request.WebauthnGet request) throws HostException {
        Origin origin = unlockedOrigin(request.origin());
        String rpId = rpIds.validate(origin, request.rpId());
        byte[] clientDataHash = ClientData.hash(Base64Url.decode(request.clientDataJson()), ClientData.GET, origin);
        refuseRequiredVerification(request.userVerification());
        List<byte[]> allowed = decodeAll(request.allowCredentials());
        List<PasskeyPort.Passkey> candidates = new ArrayList<>();
        for (PasskeyPort.Passkey held : passkeys.passkeys()) {
            if (held.rpId().equals(rpId) && (allowed.isEmpty() || contains(allowed, held.credentialId()))) {
                candidates.add(held);
            }
        }
        PasskeyPort.Passkey chosen = choose(candidates, request.credential(), allowed);
        Grant grant = approve(ApprovalRequest.Operation.PASSKEY, origin, profile(PASSKEY_GET_PROFILE_PREFIX,
                chosen.id()), Effect.SEND,
                "sign in to \"" + rpId + "\" with a passkey, account \"" + shown(chosen.accountName()) + "\"");
        PasskeyPort.Signed signed = passkeys.sign(grant, chosen.id(), clientDataHash,
                count -> AuthenticatorData.assertion(rpId, count));
        requireConsumed(grant);
        Map<String, Json> reply = Messages.reply(TYPE_WEBAUTHN_GET, request.id());
        reply.put("origin", Json.Str.of(origin.text()));
        reply.put("rpId", Json.Str.of(rpId));
        reply.put("credentialId", Json.Str.of(Base64Url.encode(chosen.credentialId())));
        reply.put("authenticatorData", Json.Str.of(Base64Url.encode(signed.authenticatorData())));
        reply.put("signature", Json.Str.of(Base64Url.encode(signed.signature())));
        reply.put("userHandle", Json.Str.of(Base64Url.encode(chosen.userHandle())));
        return new Json.Obj(reply);
    }

    /**
     * The passkey a get request signs with: the one it names, if held for the RP ID and in a
     * non-empty allow list; else the only candidate.
     */
    private static PasskeyPort.Passkey choose(List<PasskeyPort.Passkey> candidates, Optional<String> named,
            List<byte[]> allowed) throws HostException {
        if (named.isPresent()) {
            byte[] wanted = Base64Url.decode(named.get());
            if (!allowed.isEmpty() && !contains(allowed, wanted)) {
                throw new HostException(HostException.Code.NOT_ALLOWED);
            }
            return candidates.stream().filter(c -> ConstantTime.equals(c.credentialId(), wanted)).findFirst()
                    .orElseThrow(() -> new HostException(HostException.Code.NOT_FOUND));
        }
        if (candidates.isEmpty()) {
            throw new HostException(HostException.Code.NOT_FOUND);
        }
        if (candidates.size() > ONLY_CANDIDATE) {
            throw new HostException(HostException.Code.AMBIGUOUS);
        }
        return candidates.get(0);
    }

    private static void refuseRequiredVerification(Request.UserVerification uv) throws HostException {
        if (uv == Request.UserVerification.REQUIRED) {
            throw new HostException(HostException.Code.UV_REQUIRED);
        }
    }

    private static List<byte[]> decodeAll(List<String> texts) throws HostException {
        List<byte[]> out = new ArrayList<>();
        for (String text : texts) {
            out.add(Base64Url.decode(text));
        }
        return out;
    }

    private static boolean contains(List<byte[]> ids, byte[] id) {
        return ids.stream().anyMatch(candidate -> ConstantTime.equals(candidate, id));
    }

    /**
     * One broker request for {@code profile} on {@code origin}; returns its grant or throws the
     * denial. The display line is {@code "<origin> - <what>"}: {@code Display} has no separate
     * subject field, and the broker never matches on the display (ADR 0014 §6).
     */
    private Grant approve(Origin origin, String profile, Effect effect, String what) throws HostException {
        return approve(ApprovalRequest.Operation.AUTOFILL, origin, profile, effect, what);
    }

    /**
     * {@link #approve(Origin, String, Effect, String)} under {@code operation}. Passkey requests
     * use {@code PASSKEY}, which the broker never lets a session or temporary policy cover.
     */
    private Grant approve(ApprovalRequest.Operation operation, Origin origin, String profile, Effect effect,
            String what) throws HostException {
        ApprovalRequest asked = new ApprovalRequest(Csprng.uuid(),
                new ApprovalRequest.Requester(ApprovalRequest.Kind.EXTENSION, extensionId),
                operation,
                new ApprovalRequest.Scope(origin.text(), profile, Optional.empty(), List.of()),
                Duration.ZERO,
                new ApprovalRequest.Display(List.of(), Optional.of(origin.text() + " - " + what), effect),
                clock.instant());
        Outcome outcome = approvals.approve(asked);
        if (!outcome.decision().allowed()) {
            throw HostException.denied(outcome.decision());
        }
        Grant grant = outcome.grant().orElseThrow();
        if (!grant.request().equals(asked) || grant.isUsed()) {
            throw new HostException(HostException.Code.INTERNAL);
        }
        return grant;
    }

    /**
     * {@code fill-} and all 128 bits of the login id in base 36 (at most 25 digits): a valid profile
     * name of at most 30 characters, and a different one for every login.
     */
    static String fillProfile(UUID login) {
        return profile(FILL_PROFILE_PREFIX, login);
    }

    /** {@code prefix} and all 128 bits of {@code record} in base 36: one profile per record. */
    static String profile(String prefix, UUID record) {
        byte[] bits = ByteBuffer.allocate(UUID_BYTES)
                .putLong(record.getMostSignificantBits())
                .putLong(record.getLeastSignificantBits())
                .array();
        return prefix + new BigInteger(1, bits).toString(Character.MAX_RADIX);
    }

    /** Vault text for a prompt: at most {@link #MAX_SHOWN} code points, control characters replaced. */
    static String shown(String text) {
        StringBuilder out = new StringBuilder();
        text.codePoints().limit(MAX_SHOWN)
                .forEach(c -> out.appendCodePoint(Character.isISOControl(c) ? SUBSTITUTE : c));
        return out.toString();
    }

    private static void requireConsumed(Grant grant) throws HostException {
        if (!grant.isUsed()) {
            throw new HostException(HostException.Code.INTERNAL);
        }
    }

    private static boolean registeredFor(VaultPort.Login login, Origin origin) {
        return login.urls().stream().map(Origin::ofUrl).flatMap(Optional::stream).anyMatch(origin::equals);
    }
}
