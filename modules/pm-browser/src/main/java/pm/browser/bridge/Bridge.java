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
import pm.browser.host.HostException;
import pm.browser.host.Json;
import pm.browser.host.Messages;
import pm.browser.host.Request;
import pm.crypto.Csprng;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;

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
 */
public final class Bridge implements Handler {
    /** Most logins one {@code lookup} returns. */
    public static final int MAX_LOOKUP = 64;

    private static final String ACTION_FILL = "fill";
    private static final String ACTION_SAVE = "save";
    private static final String ACTION_GENERATE = "generate";
    private static final String ACTION_LOOKUP = "lookup";
    private static final String FILL_PROFILE_PREFIX = "fill-";
    private static final int UUID_BYTES = 16;
    /** Longest title or username shown in a prompt, in code points. */
    private static final int MAX_SHOWN = 64;
    private static final int SUBSTITUTE = '?';

    private final String extensionId;
    private final VaultPort vault;
    private final ApprovalPort approvals;
    private final Clock clock;
    private final PasswordGenerator generator;

    /** A bridge for requests from extension {@code extensionId}. */
    public Bridge(String extensionId, VaultPort vault, ApprovalPort approvals, Clock clock,
            PasswordGenerator generator) {
        this.extensionId = Objects.requireNonNull(extensionId, "extensionId");
        this.vault = Objects.requireNonNull(vault, "vault");
        this.approvals = Objects.requireNonNull(approvals, "approvals");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.generator = Objects.requireNonNull(generator, "generator");
    }

    /** A factory making one bridge per allowlisted caller. */
    public static Handler.Factory factory(VaultPort vault, ApprovalPort approvals, Clock clock,
            PasswordGenerator generator) {
        return id -> new Bridge(id, vault, approvals, clock, generator);
    }

    @Override
    public Json.Obj handle(Request request) throws HostException {
        return switch (request) {
            case Request.Hello hello -> Messages.hello(hello);
            case Request.Lookup lookup -> lookup(lookup);
            case Request.Fill fill -> fill(fill);
            case Request.Save save -> save(save);
            case Request.Generate generate -> generate(generate);
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
     * One broker request for {@code profile} on {@code origin}; returns its grant or throws the
     * denial. The display line is {@code "<origin> - <what>"}: {@code Display} has no separate
     * subject field, and the broker never matches on the display (ADR 0014 §6).
     */
    private Grant approve(Origin origin, String profile, Effect effect, String what) throws HostException {
        ApprovalRequest asked = new ApprovalRequest(Csprng.uuid(),
                new ApprovalRequest.Requester(ApprovalRequest.Kind.EXTENSION, extensionId),
                ApprovalRequest.Operation.AUTOFILL,
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
        byte[] bits = ByteBuffer.allocate(UUID_BYTES)
                .putLong(login.getMostSignificantBits())
                .putLong(login.getLeastSignificantBits())
                .array();
        return FILL_PROFILE_PREFIX + new BigInteger(1, bits).toString(Character.MAX_RADIX);
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
