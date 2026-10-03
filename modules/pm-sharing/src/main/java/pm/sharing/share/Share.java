package pm.sharing.share;

import java.time.Instant;
import java.util.Objects;
import pm.crypto.DeviceIdentity;
import pm.sharing.wire.Message;
import pm.sharing.wire.Octets;

/**
 * One share window on the sender (lan-share.md §6 step 1): what is sent, to which pinned device,
 * until when, and whether it may be taken once only.
 *
 * @param id the share id, 16 random bytes
 * @param target the receiving device's raw public key
 * @param kind a secret or a project
 * @param summary names and counts for the receiver's prompt, never values
 * @param payload the CBOR record set
 * @param expires end of the window, whole seconds
 * @param oneUse whether the window closes after the first send
 */
public record Share(Octets id, Octets target, Message.Kind kind, String summary, Octets payload, Instant expires,
        boolean oneUse) {
    /** Validates the fields; the wire limits apply. */
    public Share {
        if (Objects.requireNonNull(id, "id").length() != Message.SHARE_ID_BYTES
                || Objects.requireNonNull(target, "target").length() != DeviceIdentity.PUBLIC_KEY_BYTES) {
            throw new IllegalArgumentException("BAD_ID");
        }
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(summary, "summary");
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(expires, "expires");
        // Same checks as the messages that will carry it, so a bad share fails here, not mid-session.
        new Message.ShareOffer(0, id, kind, summary, expires.getEpochSecond(), oneUse);
        new Message.ShareData(0, id, payload);
    }

    /** Whether the window is still open at {@code now}. */
    public boolean openAt(Instant now) {
        return now.isBefore(expires);
    }

    /** The offer message for this share. */
    Message.ShareOffer offer(long seq) {
        return new Message.ShareOffer(seq, id, kind, summary, expires.getEpochSecond(), oneUse);
    }
}
