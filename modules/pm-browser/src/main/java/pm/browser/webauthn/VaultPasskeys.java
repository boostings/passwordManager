package pm.browser.webauthn;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.LongFunction;
import pm.approval.ApprovalRequest;
import pm.approval.Decision;
import pm.approval.Grant;
import pm.browser.bridge.Origin;
import pm.browser.bridge.PasskeyPort;
import pm.browser.host.HostException;
import pm.vault.PasskeyAssertion;
import pm.vault.PasskeyCreated;
import pm.vault.PasskeyException;
import pm.vault.Vault;
import pm.vault.record.PasskeyRecord;
import pm.vault.record.VaultRecord;

/**
 * {@link PasskeyPort} over an open {@link Vault} (ADR 0016 M6.3 addendum, SR-115, SR-119): keys
 * are generated and used only inside the vault ({@link Vault#createPasskey},
 * {@link Vault#signWithPasskey}); this class passes public material through and consumes each
 * grant before the vault acts on it. It first checks that the grant is for this very action
 * (operation {@code PASSKEY}, the enrollment or this passkey's profile, an origin that may use the
 * RP ID) and refuses any other with {@code GRANT_MISMATCH}, so a caller other than the bridge
 * cannot spend an autofill grant, or another passkey's grant, on a passkey.
 */
public final class VaultPasskeys implements PasskeyPort {
    private static final Map<PasskeyException.Code, HostException.Code> CODES =
            new EnumMap<>(PasskeyException.Code.class);

    static {
        CODES.put(PasskeyException.Code.NOT_FOUND, HostException.Code.NOT_FOUND);
        CODES.put(PasskeyException.Code.COUNTER_EXHAUSTED, HostException.Code.COUNTER_EXHAUSTED);
        CODES.put(PasskeyException.Code.BAD_INPUT, HostException.Code.BAD_FIELD);
    }

    private final Vault vault;
    private final RpId rpIds;

    /** A port over {@code vault}, which the caller keeps open and closes; RP IDs use {@link RpId#vendored()}. */
    public VaultPasskeys(Vault vault) {
        this(vault, RpId.vendored());
    }

    /** A port over {@code vault} that checks a grant's origin against RP IDs with {@code rpIds}. */
    public VaultPasskeys(Vault vault, RpId rpIds) {
        this.vault = Objects.requireNonNull(vault, "vault");
        this.rpIds = Objects.requireNonNull(rpIds, "rpIds");
    }

    @Override
    public List<Passkey> passkeys() throws HostException {
        List<VaultRecord> records;
        try {
            records = vault.records();
        } catch (IllegalStateException e) {
            throw HostException.denied(Decision.DENIED_LOCKED);
        }
        List<Passkey> out = new ArrayList<>();
        for (VaultRecord record : records) {
            if (record instanceof PasskeyRecord) {
                try (PasskeyRecord view = PasskeyRecord.class.cast(record)) {
                    out.add(new Passkey(view.id(), view.rpId(), view.credentialId(), view.userHandle(),
                            view.accountName()));
                }
            }
        }
        return out;
    }

    @Override
    public Created create(Grant grant, String rpId, byte[] userHandle, String accountName, String displayName)
            throws HostException {
        requireGrant(grant, PasskeyPort.createProfile(), rpId);
        grant.consume();
        try {
            PasskeyCreated created = vault.createPasskey(rpId, rpId, userHandle, accountName, displayName);
            return new Created(created.id(), created.credentialId(), created.cosePublicKey());
        } catch (PasskeyException e) {
            throw map(e);
        }
    }

    @Override
    public Signed sign(Grant grant, UUID id, byte[] clientDataHash, LongFunction<byte[]> authenticatorData)
            throws HostException {
        requireGrant(grant, PasskeyPort.signInProfile(id), rpIdOf(id));
        grant.consume();
        try {
            PasskeyAssertion assertion = vault.signWithPasskey(id, clientDataHash,
                    persisted -> authenticatorData.apply(persisted.signCount()));
            return new Signed(assertion.signCount(), assertion.authenticatorData(), assertion.signature());
        } catch (PasskeyException e) {
            throw map(e);
        }
    }

    /** The RP ID of passkey {@code id}; {@code NOT_FOUND} if the vault holds none. */
    private String rpIdOf(UUID id) throws HostException {
        for (Passkey held : passkeys()) {
            if (held.id().equals(id)) {
                return held.rpId();
            }
        }
        throw new HostException(HostException.Code.NOT_FOUND);
    }

    /**
     * Refuses {@code grant}, leaving it unused, unless it is for exactly this action: operation
     * {@code PASSKEY} (never covered by a session or temporary policy), {@code profile} (the
     * enrollment profile, or this passkey's sign-in profile), and an origin that may use
     * {@code rpId}. The bridge asks for such a grant; this check keeps any other caller of the port
     * from creating or signing under a grant the user gave for something else (SR-119).
     *
     * @throws HostException {@code GRANT_MISMATCH}, or {@code PSL_UNAVAILABLE} if the RP ID cannot
     *     be checked
     */
    private void requireGrant(Grant grant, String profile, String rpId) throws HostException {
        ApprovalRequest asked = grant.request();
        if (asked.operation() != ApprovalRequest.Operation.PASSKEY || !asked.scope().profile().equals(profile)) {
            throw new HostException(HostException.Code.GRANT_MISMATCH);
        }
        try {
            rpIds.validate(Origin.parse(asked.scope().project()), rpId);
        } catch (HostException e) {
            throw e.code() == HostException.Code.PSL_UNAVAILABLE ? e
                    : new HostException(HostException.Code.GRANT_MISMATCH);
        }
    }

    /**
     * The reply code for a vault refusal: {@code DENIED_LOCKED}, {@code NOT_FOUND},
     * {@code COUNTER_EXHAUSTED}, {@code BAD_FIELD}, otherwise {@code INTERNAL}. Only the code
     * reaches the browser, never the cause.
     */
    static HostException map(PasskeyException e) {
        if (e.code() == PasskeyException.Code.LOCKED) {
            return HostException.denied(Decision.DENIED_LOCKED);
        }
        return new HostException(CODES.getOrDefault(e.code(), HostException.Code.INTERNAL));
    }
}
