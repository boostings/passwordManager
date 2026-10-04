package pm.tui.lan;

import java.io.IOException;
import java.net.InetAddress;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;
import pm.sharing.share.Share;
import pm.sharing.share.ShareEvents;
import pm.sharing.share.ShareException;
import pm.sharing.share.ShareServer;
import pm.sharing.share.Shares;
import pm.vault.record.TrustedDeviceRecord;

/**
 * One open share window on the sending device (lan-share.md §6, SR-207): a one-use offer of one
 * item to one paired device, served by its own listener that only that device can reach. The
 * listener closes, freeing the port, after the delivery, at expiry, or on {@link #revoke()}. The
 * payload copy is wiped by {@link #close()}. The window does not rely on the trust list it was
 * opened with: {@code stillTrusted} is asked again when the device connects and just before the
 * data is released, so a device removed meanwhile, in this or another process, gets nothing
 * (SR-205, {@link LanState}).
 */
public final class SendWindow implements AutoCloseable {
    /** Where the window stands. */
    public enum Outcome {
        /** Still waiting for the receiver. */
        OPEN,
        /** The receiver applied the item. */
        DELIVERED,
        /** The window ran out first. */
        EXPIRED,
        /** The sender revoked it first. */
        REVOKED
    }

    private final Shares shares;
    private final Share share;
    private final String target;
    private final InetAddress bound;
    private final Events events;
    private final ShareServer server;
    private final Local self;
    private final byte[] targetKey;
    private final Predicate<byte[]> stillTrusted;

    private SendWindow(Local self, Shares shares, Share share, TrustedDeviceRecord target, InetAddress address,
            Events events, ShareServer server, Predicate<byte[]> stillTrusted) {
        this.self = self;
        this.targetKey = target.rawPublicKey();
        this.stillTrusted = stillTrusted;
        this.shares = shares;
        this.share = share;
        this.target = target.title();
        this.bound = address;
        this.events = events;
        this.server = server;
    }

    /**
     * Opens a window offering {@code item} to {@code target} for {@code ttl}, listening on
     * {@code address}. The window takes ownership of {@code self} (closed with the window, or here
     * on failure), so the vault can lock while it waits; the caller keeps {@code item}, and the
     * window holds its own copy of the payload.
     *
     * @param stillTrusted whether a device key is still on the trust list now, typically
     *     {@link LanState#stillTrusted()}; asked at every connection and before the data goes
     * @throws LanException {@code BAD_TTL}, {@code NOT_SHAREABLE} if the item does not fit an offer,
     *     {@code NO_SUCH_DEVICE} if the target is already removed, or {@code NETWORK} if the port
     *     could not be opened
     */
    public static SendWindow open(Local self, TrustedDeviceRecord target, SharePayload.Prepared item, Duration ttl,
            Clock clock, InetAddress address, Predicate<byte[]> stillTrusted) throws LanException {
        Objects.requireNonNull(self, "self");
        try {
            return start(self, target, item, ttl, clock, address, stillTrusted);
        } catch (LanException | RuntimeException e) {
            self.close();
            throw e;
        }
    }

    private static SendWindow start(Local self, TrustedDeviceRecord target, SharePayload.Prepared item,
            Duration ttl, Clock clock, InetAddress address, Predicate<byte[]> stillTrusted) throws LanException {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(stillTrusted, "stillTrusted");
        Objects.requireNonNull(item, "item");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(address, "address");
        if (ttl.toSeconds() < 1 || ttl.compareTo(Shares.MAX_TTL) > 0) {
            throw new LanException(LanException.Code.BAD_TTL);
        }
        byte[] targetKey = target.rawPublicKey();
        if (!stillTrusted.test(targetKey)) {
            throw new LanException(LanException.Code.NO_SUCH_DEVICE);
        }
        Shares shares = new Shares(stillTrusted);
        Instant now = clock.instant();
        Share share;
        try {
            // Shares copies the bytes; the copy lives until close() wipes it.
            share = item.payload().apply(bytes -> shares.open(targetKey, item.kind(), item.summary(), bytes, ttl,
                    true, now));
        } catch (IllegalArgumentException e) {
            throw new LanException(LanException.Code.NOT_SHAREABLE, e);
        }
        Predicate<byte[]> onlyTarget = peer -> ConstantTime.equals(targetKey, peer) && stillTrusted.test(peer);
        Events events = new Events();
        try {
            ShareServer server = ShareServer.open(self.identity(), self.name(), onlyTarget, shares, clock, address,
                    events);
            return new SendWindow(self, shares, share, target, address, events, server, stillTrusted);
        } catch (IOException | CryptoException e) {
            share.payload().wipe();
            throw new LanException(LanException.Code.NETWORK, e);
        }
    }

    /** The share id, 32 lowercase hex digits, for {@code pm revoke}. */
    public String id() {
        return HexFormat.of().formatHex(share.id().toByteArray());
    }

    /** The device the item goes to. */
    public String targetName() {
        return target;
    }

    /** What the receiver will be asked to accept. */
    public String summary() {
        return share.summary();
    }

    /** When the window closes. */
    public Instant expires() {
        return share.expires();
    }

    /** {@code address:port} for the receiver to type. */
    public String address() {
        return LanAddress.show(bound, server.port());
    }

    /** The listening port. */
    public int port() {
        return server.port();
    }

    /** How many connections were turned away (unpinned, wrong device, or no open window). */
    public int refusals() {
        return events.refusals.get();
    }

    /**
     * Revokes the window (lan-share.md §8): no handshake succeeds from now on and the port closes.
     * A transfer already under way is cut off before the receiver applies anything.
     *
     * @return whether it was still open
     */
    public boolean revoke() {
        boolean wasOpen = shares.revoke(share.id());
        if (wasOpen) {
            events.revoked.set(true);
        }
        server.close();
        return wasOpen;
    }

    /**
     * Waits up to {@code timeout} for the window to close. A window whose device was removed
     * meanwhile (in any process) is revoked here.
     *
     * @return {@link Outcome#OPEN} if it is still open, otherwise how it ended
     */
    public Outcome await(Duration timeout) throws InterruptedException {
        if (server.awaitClosed(timeout)) {
            return ended();
        }
        if (!stillTrusted.test(targetKey)) {
            events.revoked.set(true);
            revoke();
            return ended();
        }
        return Outcome.OPEN;
    }

    /** Where the window stands now. */
    public Outcome outcome() {
        return server.isOpen() ? Outcome.OPEN : ended();
    }

    private Outcome ended() {
        if (events.wasDelivered.get()) {
            return Outcome.DELIVERED;
        }
        // A removed device's window counts as revoked even when the listener closed on its own.
        return events.revoked.get() || !stillTrusted.test(targetKey) ? Outcome.REVOKED : Outcome.EXPIRED;
    }

    /** Closes the listener, wipes this window's payload copy and forgets the identity. */
    @Override
    public void close() {
        try (self) {
            shares.revoke(share.id());
            server.close();
            share.payload().wipe();
        }
    }

    /** Listener reports; no values, only what happened. */
    private static final class Events implements ShareEvents {
        private final AtomicBoolean wasDelivered = new AtomicBoolean();
        private final AtomicBoolean revoked = new AtomicBoolean();
        private final AtomicInteger refusals = new AtomicInteger();

        @Override
        public void delivered(Share s) {
            wasDelivered.set(true);
        }

        @Override
        public void failed(Share s, ShareException.Code code) {
            // The receiver declined or could not apply; the window stays open until it ends.
        }

        @Override
        public void refused() {
            refusals.incrementAndGet();
        }

        @Override
        public void closed() {
            // await() and outcome() read the listener's state directly.
        }
    }
}
