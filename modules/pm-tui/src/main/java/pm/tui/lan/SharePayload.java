package pm.tui.lan;

import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import pm.crypto.Csprng;
import pm.crypto.SecretBytes;
import pm.sharing.share.Shares;
import pm.sharing.wire.Message;
import pm.tui.Session;
import pm.vault.VaultException;
import pm.vault.record.DeviceRecord;
import pm.vault.record.LoginRecord;
import pm.vault.record.PasskeyRecord;
import pm.vault.record.ProjectRecord;
import pm.vault.record.RecordCodec;
import pm.vault.record.RecordException;
import pm.vault.record.SshKeyRecord;
import pm.vault.record.TrustedDeviceRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/**
 * What a share carries (lan-share.md §6): one item as a record-set payload in the vault's own
 * record codec, a summary of names and counts for the receiver's prompt, and on the receiving side
 * the checks before anything reaches the vault. Device records are never shared.
 */
public final class SharePayload {
    private static final char REPLACEMENT = '?';
    private static final String ELLIPSIS = "...";

    private SharePayload() {
    }

    /**
     * An item ready to offer.
     *
     * @param kind {@code SECRET} for a login, Wi-Fi network or SSH key, {@code PROJECT} for a project
     * @param summary names and counts only, never a value
     * @param payload the encoded record set; owned by this value
     */
    public record Prepared(Message.Kind kind, String summary, SecretBytes payload) implements AutoCloseable {
        /** Checks the fields. */
        public Prepared {
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(summary, "summary");
            Objects.requireNonNull(payload, "payload");
        }

        /** Wipes the payload. */
        @Override
        public void close() {
            payload.close();
        }
    }

    /**
     * Encodes {@code item} for a paired device. The item stays owned by the caller.
     *
     * @throws LanException {@code NOT_SHAREABLE} for sharing state, a passkey (vault-only, SR-086),
     *     or an item too large for one frame
     */
    public static Prepared prepare(VaultRecord item) throws LanException {
        if (DeviceRecord.isInternal(item) || item instanceof PasskeyRecord) {
            throw new LanException(LanException.Code.NOT_SHAREABLE);
        }
        SecretBytes payload = RecordCodec.encodePayload(List.of(item));
        if (payload.length() > Message.MAX_PAYLOAD) {
            payload.close();
            throw new LanException(LanException.Code.NOT_SHAREABLE);
        }
        return new Prepared(kindOf(item), summary(item), payload);
    }

    /** The kind a share of {@code item} has on the wire. */
    public static Message.Kind kindOf(VaultRecord item) {
        return item instanceof ProjectRecord ? Message.Kind.PROJECT : Message.Kind.SECRET;
    }

    /** {@code login: Bank}, with unsafe characters replaced and the length bounded; never a value. */
    public static String summary(VaultRecord item) {
        // Class.cast, not pattern variables: the item is the caller's, and a local of an
        // AutoCloseable type would have to be closed here.
        String counts = item instanceof ProjectRecord
                ? " (" + ProjectRecord.class.cast(item).variables().size() + " variables)" : "";
        String head = typeName(item) + ": ";
        int room = Message.ShareOffer.MAX_SUMMARY - head.length() - counts.length();
        return head + safe(item.title(), room) + counts;
    }

    /** The user-facing name of the item's type. */
    public static String typeName(VaultRecord item) {
        if (item instanceof LoginRecord) {
            return "login";
        }
        if (item instanceof WifiRecord) {
            return "wifi";
        }
        if (item instanceof SshKeyRecord) {
            return "ssh-key";
        }
        if (item instanceof ProjectRecord) {
            return "project";
        }
        if (item instanceof PasskeyRecord) {
            return "passkey";
        }
        return "device";
    }

    /**
     * The text a browser share shows (ADR 0010 Amendment 2): a login's or Wi-Fi network's password,
     * or an SSH private key. A project has many values and goes only to a paired device.
     *
     * @return a new secret; the caller closes it
     * @throws LanException {@code NOT_SHAREABLE} for a project, sharing state or an empty secret
     */
    @SuppressWarnings("PMD.CloseResource") // CE-035: the value is the record's, owned by the session (ADR 0008)
    public static SecretBytes browserText(VaultRecord item) throws LanException {
        SecretBytes value;
        if (item instanceof LoginRecord) {
            value = LoginRecord.class.cast(item).password();
        } else if (item instanceof WifiRecord) {
            value = WifiRecord.class.cast(item).password();
        } else if (item instanceof SshKeyRecord) {
            value = SshKeyRecord.class.cast(item).privateKey();
        } else {
            throw new LanException(LanException.Code.NOT_SHAREABLE);
        }
        if (value.length() == 0) {
            throw new LanException(LanException.Code.NOT_SHAREABLE);
        }
        return value.apply(SecretBytes::copyOf);
    }

    /**
     * Applies a received payload (lan-share.md §6 step 5): exactly one record, of the kind and with
     * the summary (type, title and, for a project, variable count) of the offer the user accepted,
     * never sharing state, and for a project no title the vault already has. A login, Wi-Fi network
     * or SSH key whose title the vault already has is added beside it as a separate item. The record
     * gets a fresh id, so a share can never overwrite an existing item. In the same save, the share
     * id is recorded on the sender's trust entry (the replay guard, SR-204) until the offer
     * expires. If the sender is no longer paired, the share was applied before, or anything does
     * not match, nothing is added. The caller keeps and wipes {@code payload}.
     *
     * @param accepted the offer the user accepted
     * @param senderFingerprint the pinned sender's fingerprint, as TLS proved it
     * @return whether the item is now in the vault; on false the vault is as it was
     */
    public static boolean apply(Session session, Message.ShareOffer accepted, String senderFingerprint,
            byte[] payload, Instant now) {
        Objects.requireNonNull(accepted, "accepted");
        Objects.requireNonNull(now, "now");
        String shareId = HexFormat.of().formatHex(accepted.shareId().toByteArray());
        Optional<TrustedDeviceRecord> sender = Devices.trusted(session).stream()
                .filter(d -> d.fingerprint().equals(senderFingerprint)).findFirst();
        if (sender.isEmpty() || sender.get().hasReceived(shareId, now)) {
            return false;
        }
        List<VaultRecord> decoded;
        try (SecretBytes plaintext = SecretBytes.copyOf(payload)) {
            decoded = RecordCodec.decodePayload(plaintext);
        } catch (RecordException e) {
            return false;
        }
        if (decoded.size() != 1 || !acceptable(session, accepted, decoded.get(0))) {
            decoded.forEach(VaultRecord::close);
            return false;
        }
        Instant latest = now.plus(Shares.MAX_TTL);
        Instant offered = Instant.ofEpochSecond(Math.max(0, accepted.expires()));
        TrustedDeviceRecord guarded = sender.get().withReceived(shareId, offered.isAfter(latest) ? latest : offered, now);
        return store(session, withNewId(decoded.get(0), Csprng.uuid()), sender.get(), guarded);
    }

    private static boolean acceptable(Session session, Message.ShareOffer accepted, VaultRecord r) {
        if (DeviceRecord.isInternal(r) || kindOf(r) != accepted.kind() || !summary(r).equals(accepted.summary())) {
            return false;
        }
        return !(r instanceof ProjectRecord) || session.records().stream()
                .noneMatch(other -> other instanceof ProjectRecord && other.title().equals(r.title()));
    }

    /**
     * Hands {@code r} and the sender's updated entry to the session and saves once; on a failed
     * save both are taken back.
     */
    private static boolean store(Session session, VaultRecord r, TrustedDeviceRecord sender,
            TrustedDeviceRecord guarded) {
        UUID id = r.id();
        session.put(r);
        session.put(guarded);
        try {
            session.save();
            return true;
        } catch (VaultException e) {
            session.remove(id);
            session.put(sender);
            return false;
        }
    }

    /** The same item under {@code id}; the secrets move to the new record, the old one is dropped. */
    static VaultRecord withNewId(VaultRecord r, UUID id) {
        if (r instanceof LoginRecord) {
            LoginRecord l = LoginRecord.class.cast(r);
            return new LoginRecord(id, l.title(), l.username(), l.password(), l.urls(), l.notes(), l.tags(),
                    l.created(), l.updated(), l.lastUsed());
        }
        if (r instanceof WifiRecord) {
            WifiRecord w = WifiRecord.class.cast(r);
            return new WifiRecord(id, w.title(), w.ssid(), w.security(), w.password(), w.hidden(), w.notes(),
                    w.created(), w.updated());
        }
        if (r instanceof SshKeyRecord) {
            SshKeyRecord s = SshKeyRecord.class.cast(r);
            return new SshKeyRecord(id, s.title(), s.keyType(), s.privateKey(), s.publicKey(), s.fingerprint(),
                    s.comment(), s.hosts(), s.created(), s.updated());
        }
        ProjectRecord p = ProjectRecord.class.cast(r);
        return new ProjectRecord(id, p.title(), p.canonicalPath(), p.gitRemote(), p.variables(), p.config(),
                p.created(), p.updated());
    }

    /** {@code text} with unsafe code points replaced, cut to {@code max} UTF-16 units. */
    static String safe(String text, int max) {
        StringBuilder sb = new StringBuilder();
        text.codePoints().forEach(cp -> {
            int type = Character.getType(cp);
            boolean unsafe = Character.isISOControl(cp) || type == Character.FORMAT
                    || type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR;
            sb.appendCodePoint(unsafe ? REPLACEMENT : cp);
        });
        if (sb.length() <= max) {
            return sb.isEmpty() ? String.valueOf(REPLACEMENT) : sb.toString();
        }
        int cut = max - ELLIPSIS.length();
        if (Character.isHighSurrogate(sb.charAt(cut - 1))) {
            cut--;
        }
        return sb.substring(0, cut) + ELLIPSIS;
    }
}
