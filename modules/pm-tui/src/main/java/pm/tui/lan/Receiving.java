package pm.tui.lan;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import pm.crypto.CryptoException;
import pm.sharing.net.Lan;
import pm.sharing.net.PeerLink;
import pm.sharing.share.OfferPrompt;
import pm.sharing.share.ReceiveSession;
import pm.sharing.share.ReceivedShares;
import pm.sharing.share.ShareApplier;
import pm.sharing.share.ShareClient;
import pm.sharing.share.ShareException;
import pm.sharing.wire.Message;
import pm.vault.record.TrustedDeviceRecord;

/**
 * Receives one share from a paired device (lan-share.md §6 steps 3 to 5): connects to the sender's
 * window, pinning only the trust list, shows the offer, and applies the item only if the user
 * accepts it. A device that is not on the trust list fails the handshake before any message.
 */
public final class Receiving {
    private Receiving() {
    }

    /** Applies a payload once the user accepted its offer; all of it or nothing. */
    @FunctionalInterface
    public interface Applier {
        /**
         * Applies {@code payload}.
         *
         * @param accepted the offer the user accepted, which the payload must match
         * @param senderFingerprint the pinned sender, as TLS proved it
         * @param payload the record set; the caller wipes it afterwards
         * @return true only if the item is now in the vault
         */
        boolean apply(Message.ShareOffer accepted, String senderFingerprint, byte[] payload);
    }

    /**
     * Connects to {@code sender} and runs one receive.
     *
     * @param trusted the trust list; the sender must be on it
     * @param received share ids already applied, from the vault ({@link Devices#receivedShares}); the
     *     replay guard, which the applier must extend in the same save as the item
     * @return the offer that was applied
     * @throws ShareException declined, refused or not applied; nothing was applied
     * @throws LanException {@code NETWORK} if the connection or handshake failed, which includes a
     *     sender that is not paired and a window that was revoked or has closed
     */
    public static Message.ShareOffer receive(Local self, InetSocketAddress sender, List<TrustedDeviceRecord> trusted,
            Clock clock, ReceivedShares received, OfferPrompt prompt, Applier applier)
            throws ShareException, LanException {
        Objects.requireNonNull(self, "self");
        Objects.requireNonNull(received, "received");
        Objects.requireNonNull(prompt, "prompt");
        Objects.requireNonNull(applier, "applier");
        // The applier is told which offer was accepted, from whom, so it can check the payload
        // against it; ShareClient asks the prompt before it hands over any payload.
        AtomicReference<Message.ShareOffer> accepted = new AtomicReference<>();
        AtomicReference<String> from = new AtomicReference<>();
        OfferPrompt asking = (offer, fingerprint) -> {
            boolean yes = prompt.accept(offer, fingerprint);
            if (yes) {
                accepted.set(offer);
                from.set(fingerprint);
            }
            return yes;
        };
        ShareApplier checked = (kind, payload) -> {
            Message.ShareOffer offer = accepted.get();
            return offer != null && offer.kind() == kind && applier.apply(offer, from.get(), payload);
        };
        try (PeerLink link = Lan.connect(self.identity(), Devices.pinnedIn(trusted), clock, sender)) {
            ReceiveSession session = new ReceiveSession(self.identity().publicKey(), link.peerKey(), self.name(),
                    received, clock);
            return ShareClient.receive(link, session, asking, checked);
        } catch (IOException | CryptoException e) {
            throw new LanException(LanException.Code.NETWORK, e);
        }
    }
}
