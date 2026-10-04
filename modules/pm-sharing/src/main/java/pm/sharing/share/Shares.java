package pm.sharing.share;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;
import java.util.function.Supplier;
import pm.crypto.ConstantTime;
import pm.crypto.Csprng;
import pm.sharing.wire.Message;
import pm.sharing.wire.Octets;

/**
 * The sender's share windows (lan-share.md §6, SR-204). Expiry is enforced here whatever the
 * receiver does; a one-use share is consumed when its data is released, before it is sent, so a
 * lost acknowledgement can never lead to a second copy. Revoking a device revokes its windows, and
 * a device that the {@code admits} check refuses (removed from the trust list, perhaps by another
 * process) gets no offer and no data: the check runs again just before the data is released.
 * Shared by the listener thread and the UI, so guarded by a lock.
 */
public final class Shares {
    /** Window length when none is chosen. */
    public static final Duration DEFAULT_TTL = Duration.ofMinutes(10);
    /** Longest window. */
    public static final Duration MAX_TTL = Duration.ofHours(24);

    private enum Status { OPEN, USED, REVOKED }

    private final ReentrantLock guard = new ReentrantLock();
    private final Map<Octets, Share> shares = new LinkedHashMap<>();
    private final Map<Octets, Status> status = new LinkedHashMap<>();
    private final Predicate<byte[]> admits;

    /** No windows; every target stays admitted. */
    public Shares() {
        this(peer -> true);
    }

    /**
     * No windows.
     *
     * @param admits whether a target device is still trusted; asked before an offer and again
     *     before data is released, and a refusal revokes that device's windows
     */
    public Shares(Predicate<byte[]> admits) {
        this.admits = Objects.requireNonNull(admits, "admits");
    }

    /**
     * Opens a window for {@code target}.
     *
     * @param ttl between 1 s and {@link #MAX_TTL}
     */
    public Share open(byte[] target, Message.Kind kind, String summary, byte[] payload, Duration ttl, boolean oneUse,
            Instant now) {
        Objects.requireNonNull(ttl, "ttl");
        if (ttl.toSeconds() < 1 || ttl.compareTo(MAX_TTL) > 0) {
            throw new IllegalArgumentException("BAD_TTL");
        }
        Instant expires = now.plus(ttl).truncatedTo(ChronoUnit.SECONDS);
        Share share = new Share(Octets.copyOf(Csprng.bytes(Message.SHARE_ID_BYTES)), Octets.copyOf(target), kind,
                summary, Octets.copyOf(payload), expires, oneUse);
        return locked(() -> {
            shares.put(share.id(), share);
            status.put(share.id(), Status.OPEN);
            return share;
        });
    }

    /** The oldest open window for {@code peer} at {@code now}, if any. */
    public Optional<Share> offerFor(byte[] peer, Instant now) {
        return locked(() -> shares.values().stream()
                .filter(s -> isOpen(s, now) && ConstantTime.equals(s.target().toByteArray(), peer))
                .findFirst()).filter(s -> admitted(peer));
    }

    /** Whether any window is open at {@code now}; the listener closes when none is (SR-207). */
    public boolean anyOpen(Instant now) {
        return locked(() -> shares.values().stream().anyMatch(s -> isOpen(s, now)));
    }

    /**
     * Releases the data of share {@code id} to {@code peer}. A one-use share is used from here on.
     *
     * @throws ShareException {@code UNKNOWN} for an id that is not this peer's, otherwise
     *     {@code REVOKED}, {@code USED} or {@code EXPIRED}
     */
    public Share claim(Octets id, byte[] peer, Instant now) throws ShareException {
        Claim c = locked(() -> claimLocked(id, peer, now));
        if (c.refusal() != null) {
            throw new ShareException(c.refusal());
        }
        return c.share();
    }

    private record Claim(Share share, ShareException.Code refusal) {}

    private Claim claimLocked(Octets id, byte[] peer, Instant now) {
        Share share = shares.get(id);
        if (share == null || !ConstantTime.equals(share.target().toByteArray(), peer)) {
            return new Claim(null, ShareException.Code.UNKNOWN);
        }
        if (!admits.test(peer)) {
            status.replace(id, Status.OPEN, Status.REVOKED);
            return new Claim(null, ShareException.Code.REVOKED);
        }
        Status st = status.get(id);
        if (st == Status.REVOKED) {
            return new Claim(null, ShareException.Code.REVOKED);
        }
        if (st == Status.USED) {
            return new Claim(null, ShareException.Code.USED);
        }
        if (!share.openAt(now)) {
            return new Claim(null, ShareException.Code.EXPIRED);
        }
        if (share.oneUse()) {
            status.put(id, Status.USED);
        }
        return new Claim(share, null);
    }

    /** Revokes one window; true if it was open. */
    public boolean revoke(Octets id) {
        return locked(() -> status.replace(id, Status.OPEN, Status.REVOKED));
    }

    /** Revokes every window for {@code device} (lan-share.md §8); returns how many were open. */
    public int revokeDevice(byte[] device) {
        return locked(() -> {
            int n = 0;
            for (Share s : shares.values()) {
                if (ConstantTime.equals(s.target().toByteArray(), device)
                        && status.replace(s.id(), Status.OPEN, Status.REVOKED)) {
                    n++;
                }
            }
            return n;
        });
    }

    /** Asks {@code admits}; a refused device has its windows revoked. */
    private boolean admitted(byte[] peer) {
        if (admits.test(peer)) {
            return true;
        }
        revokeDevice(peer);
        return false;
    }

    private boolean isOpen(Share s, Instant now) {
        return status.get(s.id()) == Status.OPEN && s.openAt(now);
    }

    private <T> T locked(Supplier<T> body) {
        guard.lock();
        try {
            return body.get();
        } finally {
            guard.unlock();
        }
    }
}
