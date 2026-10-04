package pm.vault.record;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;
import pm.crypto.DeviceIdentity;

/**
 * One entry of the trust list (lan-share.md §5 step 5, §8): a paired device's pinned Ed25519 key,
 * the name it gave, its fingerprint and when it was paired. Removing the record revokes the device:
 * from then on its handshakes fail at the pinning trust manager (SR-205). The record is internal
 * ({@link DeviceRecord}) and never listed or shared.
 *
 * @param id record identity
 * @param title the peer's device name: 1 to 32 characters, no control or format characters
 * @param publicKey the raw 32-byte public key as 64 lowercase hex digits; the payload stores the
 *     raw bytes
 * @param fingerprint {@link DeviceIdentity#fingerprint} of the key; must match it
 * @param shared ids of the items offered to this device, oldest first, at most
 *     {@value #MAX_SHARED}; the "rotate these secrets" checklist when it is removed (lan-share.md §8)
 * @param received the shares applied from this device that have not expired yet, oldest first, at
 *     most {@value #MAX_RECEIVED}, no repeated id: the replay guard of lan-share.md §6 step 5
 *     (SR-204), kept in the vault so it holds across processes
 * @param created when the device was paired, whole seconds
 * @param updated last change, whole seconds
 */
public record TrustedDeviceRecord(
        UUID id,
        String title,
        String publicKey,
        String fingerprint,
        List<UUID> shared,
        List<Received> received,
        Instant created,
        Instant updated
) implements DeviceRecord {
    /** Most item ids kept in {@link #shared}; the oldest are dropped first. */
    public static final int MAX_SHARED = 1_024;
    /** Most entries kept in {@link #received}; the oldest are dropped first. */
    public static final int MAX_RECEIVED = 1_024;
    private static final Pattern KEY_HEX = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern SHARE_ID_HEX = Pattern.compile("[0-9a-f]{32}");

    /**
     * One applied share.
     *
     * @param shareId the share id as 32 lowercase hex digits
     * @param expires when the sender's window closed, whole seconds; after it the entry is dropped
     */
    public record Received(String shareId, Instant expires) {
        /** Checks the fields. */
        public Received {
            if (!SHARE_ID_HEX.matcher(Objects.requireNonNull(shareId, "shareId")).matches()) {
                throw new IllegalArgumentException("shareId is not 32 lowercase hex digits");
            }
            expires = FieldRules.instant(expires, "expires");
        }
    }

    /**
     * Validates every field.
     *
     * @throws NullPointerException if a component is null
     * @throws IllegalArgumentException if the name is invalid, the key is not 64 lowercase hex
     *     digits, the fingerprint is not the key's, {@code shared} or {@code received} is too long
     *     or repeats an id, or an instant is out of range
     */
    public TrustedDeviceRecord {
        Objects.requireNonNull(id, "id");
        title = DeviceRecord.checkName(title);
        if (!KEY_HEX.matcher(Objects.requireNonNull(publicKey, "publicKey")).matches()) {
            throw new IllegalArgumentException("publicKey is not a raw Ed25519 key");
        }
        String expected = DeviceIdentity.fingerprint(HexFormat.of().parseHex(publicKey));
        if (!expected.equals(Objects.requireNonNull(fingerprint, "fingerprint"))) {
            throw new IllegalArgumentException("fingerprint does not match publicKey");
        }
        shared = List.copyOf(Objects.requireNonNull(shared, "shared"));
        if (shared.size() > MAX_SHARED || new HashSet<>(shared).size() != shared.size()) {
            throw new IllegalArgumentException("shared is too long or repeats an id");
        }
        received = List.copyOf(Objects.requireNonNull(received, "received"));
        if (received.size() > MAX_RECEIVED
                || received.stream().map(Received::shareId).distinct().count() != received.size()) {
            throw new IllegalArgumentException("received is too long or repeats an id");
        }
        created = FieldRules.instant(created, "created");
        updated = FieldRules.instant(updated, "updated");
    }

    /** A record pinning {@code rawKey} under {@code name}, paired at {@code pairedAt}. */
    public static TrustedDeviceRecord of(UUID id, String name, byte[] rawKey, Instant pairedAt) {
        return new TrustedDeviceRecord(id, name, HexFormat.of().formatHex(rawKey),
                DeviceIdentity.fingerprint(rawKey), List.of(), List.of(), pairedAt, pairedAt);
    }

    /**
     * This device with {@code item} recorded as offered to it at {@code now}. An id already listed
     * moves to the end; past {@value #MAX_SHARED} the oldest is dropped.
     */
    public TrustedDeviceRecord withShared(UUID item, Instant now) {
        Objects.requireNonNull(item, "item");
        List<UUID> ids = new ArrayList<>(shared);
        ids.remove(item);
        ids.add(item);
        if (ids.size() > MAX_SHARED) {
            ids.remove(0);
        }
        return new TrustedDeviceRecord(id, title, publicKey, fingerprint, ids, received, created, now);
    }

    /** Whether share {@code shareId} from this device was applied and its window is still open at {@code now}. */
    public boolean hasReceived(String shareId, Instant now) {
        return received.stream().anyMatch(r -> r.shareId().equals(shareId) && r.expires().isAfter(now));
    }

    /**
     * This device with share {@code shareId} recorded as applied until {@code expires}. Entries that
     * expired by {@code now} are dropped; past {@value #MAX_RECEIVED} the oldest is dropped.
     */
    public TrustedDeviceRecord withReceived(String shareId, Instant expires, Instant now) {
        Received entry = new Received(shareId, expires);
        List<Received> kept = new ArrayList<>(received.stream()
                .filter(r -> r.expires().isAfter(now) && !r.shareId().equals(shareId)).toList());
        kept.add(entry);
        if (kept.size() > MAX_RECEIVED) {
            kept.remove(0);
        }
        return new TrustedDeviceRecord(id, title, publicKey, fingerprint, shared, kept, created, now);
    }

    /** This device under a new name (re-pairing), keeping its history. */
    public TrustedDeviceRecord renamed(String name, Instant now) {
        return new TrustedDeviceRecord(id, name, publicKey, fingerprint, shared, received, now, now);
    }

    /** The raw public key, a new array. */
    public byte[] rawPublicKey() {
        return HexFormat.of().parseHex(publicKey);
    }

    /** When the device was paired. */
    public Instant pairedAt() {
        return created;
    }

    @Override
    public void close() {
        // no secrets: the key is public
    }
}
