package pm.sharing.share;

import pm.sharing.wire.Message;

/** Asks the receiving user whether to take an offer; shows names and counts only. */
@FunctionalInterface
public interface OfferPrompt {
    /**
     * Shows {@code offer} and waits for the answer.
     *
     * @param offer the sender's offer
     * @param senderFingerprint the pinned sender's fingerprint
     * @return true to accept
     */
    boolean accept(Message.ShareOffer offer, String senderFingerprint);
}
