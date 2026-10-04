package pm.tui.lan;

import java.io.IOException;
import java.net.InetAddress;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;
import pm.crypto.WebIdentity;
import pm.sharing.share.Shares;
import pm.sharing.web.WebEvents;
import pm.sharing.web.WebServer;
import pm.sharing.web.WebShare;
import pm.vault.record.VaultRecord;

/**
 * A browser-only share (lan-share.md §7, ADR 0010 Amendment 2): one value behind a one-time HTTPS
 * page with a throwaway certificate, the key only in the link's fragment. It closes after the one
 * ciphertext fetch, at expiry, or on {@link #revoke()}; {@link #close()} wipes the key.
 */
public final class BrowserWindow implements AutoCloseable {
    /**
     * What the sender must be told before the link is given out (ADR 0010 Amendment 2). Front ends
     * show every line, in this order.
     */
    public static final List<String> WARNINGS = List.of(
            "Residual risk: someone on this network who can answer for this address can serve a fake page"
                    + " that keeps the key. Paired sharing (pm pair, then pm share --to) has no such risk"
                    + " and is the default.",
            "Keep the window short: the value is exposed for as long as the link works.",
            "Ask the recipient to open the link in a private (incognito) window, then close it.",
            "The browser will warn about the certificate: check that its SHA-256 fingerprint matches the"
                    + " one shown here before continuing.",
            "A chat app's link preview can fetch the page, but only the recipient's browser fetches the"
                    + " data: a preview does not use up the share.");

    private final WebShare share;
    private final WebServer server;
    private final String fingerprint;
    private final String link;
    private final Events events;

    private BrowserWindow(WebShare share, WebServer server, String fingerprint, String url, Events events) {
        this.share = share;
        this.server = server;
        this.fingerprint = fingerprint;
        this.link = url;
        this.events = events;
    }

    /**
     * Opens a page for {@code item}'s value for {@code ttl} on {@code address}.
     *
     * @throws LanException {@code NOT_SHAREABLE} (a project, or an empty value), {@code BAD_TTL},
     *     or {@code NETWORK}
     */
    public static BrowserWindow open(VaultRecord item, Duration ttl, Clock clock, InetAddress address)
            throws LanException {
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(address, "address");
        if (ttl.toSeconds() < 1 || ttl.compareTo(Shares.MAX_TTL) > 0) {
            throw new LanException(LanException.Code.BAD_TTL);
        }
        Instant now = clock.instant();
        WebShare share;
        try (SecretBytes text = SharePayload.browserText(item)) {
            share = WebShare.seal(text, ttl, now);
        } catch (CryptoException e) {
            throw new LanException(LanException.Code.NOT_SHAREABLE, e);
        }
        try {
            Duration validity = ttl.plusHours(1).compareTo(WebIdentity.MAX_VALIDITY) > 0
                    ? WebIdentity.MAX_VALIDITY : ttl.plusHours(1);
            WebIdentity web = WebIdentity.generate(now, validity, address);
            Events events = new Events();
            WebServer server = WebServer.open(share, web, clock, address, events);
            return new BrowserWindow(share, server, web.fingerprint(), share.url(address, server.port()), events);
        } catch (IOException | CryptoException e) {
            share.close();
            throw new LanException(LanException.Code.NETWORK, e);
        }
    }

    /** The link, which carries the key: show it to the sender only, never log it. */
    public String url() {
        return link;
    }

    /** The certificate's SHA-256 fingerprint, colon-separated hex, for the recipient to compare. */
    public String certificateFingerprint() {
        return fingerprint;
    }

    /** The share id, 32 lowercase hex digits. */
    public String id() {
        return share.id();
    }

    /** When the link stops working. */
    public Instant expires() {
        return share.expires();
    }

    /** Whether something has fetched the page (a link preview counts). */
    public boolean pageOpened() {
        return events.pageOpened.get();
    }

    /** Revokes the link now: the listener closes and any fetch in progress is cut off. */
    public void revoke() {
        events.revoked.set(!events.dataDelivered.get());
        server.close();
    }

    /**
     * Waits up to {@code timeout} for the window to close.
     *
     * @return {@link SendWindow.Outcome#OPEN} if it is still open, otherwise how it ended
     */
    public SendWindow.Outcome await(Duration timeout) throws InterruptedException {
        return server.awaitClosed(timeout) ? ended() : SendWindow.Outcome.OPEN;
    }

    /** Where the window stands now. */
    public SendWindow.Outcome outcome() {
        return server.isOpen() ? SendWindow.Outcome.OPEN : ended();
    }

    private SendWindow.Outcome ended() {
        if (events.dataDelivered.get()) {
            return SendWindow.Outcome.DELIVERED;
        }
        return events.revoked.get() ? SendWindow.Outcome.REVOKED : SendWindow.Outcome.EXPIRED;
    }

    /** Closes the listener and wipes the key. */
    @Override
    public void close() {
        server.close();
        share.close();
    }

    private static final class Events implements WebEvents {
        private final AtomicBoolean pageOpened = new AtomicBoolean();
        private final AtomicBoolean dataDelivered = new AtomicBoolean();
        private final AtomicBoolean revoked = new AtomicBoolean();

        @Override
        public void opened() {
            pageOpened.set(true);
        }

        @Override
        public void delivered() {
            dataDelivered.set(true);
        }

        @Override
        public void closed() {
            // await() and outcome() read the listener's state directly.
        }
    }
}
