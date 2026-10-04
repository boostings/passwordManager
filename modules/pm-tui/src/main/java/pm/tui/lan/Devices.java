package pm.tui.lan;

import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;
import pm.crypto.Csprng;
import pm.crypto.DeviceIdentity;
import pm.crypto.SecretBytes;
import pm.sharing.pair.PairedDevice;
import pm.sharing.share.ReceivedShares;
import pm.sharing.wire.Octets;
import pm.tui.Session;
import pm.vault.VaultException;
import pm.vault.record.DeviceIdentityRecord;
import pm.vault.record.DeviceRecord;
import pm.vault.record.TrustedDeviceRecord;
import pm.vault.record.VaultRecord;

/**
 * This install's identity and the trust list, kept as vault records (lan-share.md §1, §5 step 5,
 * §8) so they are encrypted with everything else and never written to a plain file. Shared by the
 * CLI and the TUI; every method works on an unlocked {@link Session}.
 */
public final class Devices {
    /** Name used when none can be derived from the OS user. */
    public static final String FALLBACK_NAME = "pm device";
    private static final char REPLACEMENT = '?';

    private Devices() {
    }

    /**
     * This install's identity, created and saved in the vault on first use.
     *
     * @param defaultName the name a new identity announces; made valid if it is not
     * @return the identity, open; the caller closes it
     * @throws CryptoException the stored identity does not parse, or a new one cannot be generated
     * @throws VaultException a new identity could not be saved
     */
    @SuppressWarnings("PMD.CloseResource") // CE-035: the stored record is the session's; the returned Local is the caller's
    public static Local local(Session session, String defaultName, Clock clock)
            throws CryptoException, VaultException {
        Objects.requireNonNull(clock, "clock");
        Optional<DeviceIdentityRecord> stored = identityRecord(session);
        if (stored.isPresent()) {
            DeviceIdentityRecord r = stored.get();
            return new Local(DeviceIdentity.restore(r.privateKey(), r.certificateDer()), r.title());
        }
        Instant now = clock.instant();
        DeviceIdentity created = DeviceIdentity.generate(now);
        String name = deviceName(defaultName);
        try {
            // The vault owns the record, and with it the key copy, from here (ADR 0008).
            session.put(identityRecord(name, created.privateKeyPkcs8(), created.certificate(), now));
            session.save();
            return new Local(created, name);
        } catch (VaultException | RuntimeException e) {
            created.close();
            throw e;
        }
    }

    /**
     * This install's identity announced as {@code name} from now on; the key stays the same, so
     * paired devices keep trusting it. Creates the identity if there is none yet.
     *
     * @return the identity, open; the caller closes it
     */
    public static Local rename(Session session, String name, Clock clock) throws CryptoException, VaultException {
        Local current = local(session, name, clock);
        String wanted = deviceName(name);
        if (current.name().equals(wanted)) {
            return current;
        }
        try {
            DeviceIdentityRecord stored = identityRecord(session).orElseThrow();
            session.put(renamedRecord(stored, wanted, current.identity().privateKeyPkcs8(), clock.instant()));
            session.save();
            return new Local(current.identity(), wanted);
        } catch (VaultException | RuntimeException e) {
            current.close();
            throw e;
        }
    }

    /** {@code stored} under {@code name}, around {@code key}, which it owns; on failure the key is closed. */
    private static DeviceIdentityRecord renamedRecord(DeviceIdentityRecord stored, String name, SecretBytes key,
            Instant now) {
        try {
            return new DeviceIdentityRecord(stored.id(), name, key, stored.certificate(), stored.created(), now);
        } catch (IllegalArgumentException e) {
            key.close();
            throw e;
        }
    }

    /** A record around {@code key}, which it owns; on failure the key is closed here. */
    private static DeviceIdentityRecord identityRecord(String name, SecretBytes key, byte[] certificate, Instant now) {
        try {
            return DeviceIdentityRecord.of(Csprng.uuid(), name, key, certificate, now);
        } catch (IllegalArgumentException e) {
            key.close();
            throw e;
        }
    }

    /** The stored identity record, if this vault has one. */
    public static Optional<DeviceIdentityRecord> identityRecord(Session session) {
        return session.records().stream().filter(DeviceIdentityRecord.class::isInstance)
                .map(DeviceIdentityRecord.class::cast).findFirst();
    }

    /** The fingerprint of the stored identity, or empty if it does not parse. */
    public static Optional<String> fingerprint(DeviceIdentityRecord stored) {
        try (DeviceIdentity identity = DeviceIdentity.restore(stored.privateKey(), stored.certificateDer())) {
            return Optional.of(DeviceIdentity.fingerprint(identity.publicKey()));
        } catch (CryptoException e) {
            return Optional.empty();
        }
    }

    /** The trust list, by name then fingerprint. The records stay owned by the session. */
    public static List<TrustedDeviceRecord> trusted(Session session) {
        return session.records().stream().filter(TrustedDeviceRecord.class::isInstance)
                .map(TrustedDeviceRecord.class::cast)
                .sorted(Comparator.comparing(TrustedDeviceRecord::title).thenComparing(TrustedDeviceRecord::fingerprint))
                .toList();
    }

    /**
     * The paired device called {@code query}, or whose fingerprint it is (spaces optional, any case).
     *
     * @throws LanException {@code NO_SUCH_DEVICE}, or {@code AMBIGUOUS_DEVICE} if two share the name
     */
    public static TrustedDeviceRecord find(Session session, String query) throws LanException {
        String compact = compact(query);
        List<TrustedDeviceRecord> byFingerprint = trusted(session).stream()
                .filter(d -> compact(d.fingerprint()).equals(compact)).toList();
        if (!byFingerprint.isEmpty()) {
            return byFingerprint.get(0); // one record per key (pin), so one per fingerprint
        }
        List<TrustedDeviceRecord> byName = trusted(session).stream().filter(d -> d.title().equals(query)).toList();
        if (byName.stream().skip(1).findAny().isPresent()) {
            throw new LanException(LanException.Code.AMBIGUOUS_DEVICE);
        }
        return byName.stream().findFirst().orElseThrow(() -> new LanException(LanException.Code.NO_SUCH_DEVICE));
    }

    /** The paired device whose pinned key is {@code rawKey}, if any. */
    public static Optional<TrustedDeviceRecord> byKey(Session session, byte[] rawKey) {
        return trusted(session).stream().filter(d -> ConstantTime.equals(d.rawPublicKey(), rawKey)).findFirst();
    }

    /**
     * Pins {@code paired} (lan-share.md §5 step 5) and saves the vault. Pairing a key that is already
     * pinned replaces its name and pairing time, keeping one entry per key.
     *
     * @return the stored record, owned by the session
     */
    public static TrustedDeviceRecord pin(Session session, PairedDevice paired, Instant now) throws VaultException {
        byte[] key = paired.publicKey().toByteArray();
        String name = deviceName(paired.name());
        TrustedDeviceRecord record = byKey(session, key).map(d -> d.renamed(name, now))
                .orElseGet(() -> TrustedDeviceRecord.of(Csprng.uuid(), name, key, now));
        session.put(record);
        session.save();
        return record;
    }

    /**
     * Records that {@code item} was offered to {@code device} and saves the vault, so removing the
     * device later lists it for rotation (lan-share.md §8). Called when the window opens: an offer
     * that is never taken still appears, which errs on the side of rotating. The device's current
     * entry is read again first, so a list shown earlier can neither undo a later change nor pin a
     * device that was removed since.
     *
     * @return the updated record, owned by the session; empty if the device is no longer paired,
     *     in which case nothing was changed
     */
    public static Optional<TrustedDeviceRecord> recordShare(Session session, TrustedDeviceRecord device, UUID item,
            Instant now) throws VaultException {
        Optional<TrustedDeviceRecord> current = byKey(session, device.rawPublicKey());
        if (current.isEmpty()) {
            return Optional.empty();
        }
        TrustedDeviceRecord updated = current.get().withShared(item, now);
        session.put(updated);
        session.save();
        return Optional.of(updated);
    }

    /**
     * The replay guard for a receive (SR-204): every share id applied from any paired device whose
     * window has not closed by {@code now}, as kept in the vault.
     */
    public static ReceivedShares receivedShares(Session session, Instant now) {
        ReceivedShares seen = new ReceivedShares();
        trusted(session).forEach(d -> d.received().stream().filter(r -> r.expires().isAfter(now))
                .forEach(r -> seen.add(Octets.copyOf(HexFormat.of().parseHex(r.shareId())))));
        return seen;
    }

    /**
     * The "rotate these secrets" checklist for {@code device} (lan-share.md §8): the items still in
     * the vault that were offered to it, oldest first. Items deleted since are not listed.
     */
    public static List<VaultRecord> sharedWith(Session session, TrustedDeviceRecord device) {
        List<VaultRecord> records = session.records();
        return device.shared().stream()
                .flatMap(id -> records.stream().filter(r -> r.id().equals(id) && !isInternal(r)).limit(1))
                .toList();
    }

    /**
     * Unpins {@code device} and saves the vault (lan-share.md §8): from now on its handshakes fail.
     * Secrets already sent stay with it; the caller shows the rotate checklist.
     *
     * @return whether it was pinned
     */
    public static boolean remove(Session session, TrustedDeviceRecord device) throws VaultException {
        boolean removed = session.remove(device.id());
        if (removed) {
            session.save();
        }
        return removed;
    }

    /** Pins exactly the devices in {@code trusted}, compared in constant time. */
    public static Predicate<byte[]> pinnedIn(List<TrustedDeviceRecord> trusted) {
        List<byte[]> keys = trusted.stream().map(TrustedDeviceRecord::rawPublicKey).toList();
        return peer -> keys.stream().anyMatch(k -> ConstantTime.equals(k, peer));
    }

    /**
     * A valid device name from {@code wanted}: unsafe characters become {@code ?}, the text is cut to
     * {@link DeviceRecord#MAX_NAME_CHARS}, and an empty result becomes {@link #FALLBACK_NAME}.
     */
    public static String deviceName(String wanted) {
        StringBuilder sb = new StringBuilder();
        Objects.requireNonNull(wanted, "wanted").strip().codePoints().forEach(cp -> {
            int type = Character.getType(cp);
            boolean unsafe = Character.isISOControl(cp) || type == Character.FORMAT
                    || type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR
                    || type == Character.SURROGATE;
            if (sb.length() + Character.charCount(cp) <= DeviceRecord.MAX_NAME_CHARS) {
                sb.appendCodePoint(unsafe ? REPLACEMENT : cp);
            }
        });
        return sb.isEmpty() ? FALLBACK_NAME : sb.toString();
    }

    /** Whether {@code record} is sharing state rather than an item. */
    public static boolean isInternal(VaultRecord record) {
        return DeviceRecord.isInternal(record);
    }

    private static String compact(String fingerprint) {
        return fingerprint.replace(" ", "").toLowerCase(Locale.ROOT);
    }
}
