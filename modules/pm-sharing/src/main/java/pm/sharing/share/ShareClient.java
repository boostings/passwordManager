package pm.sharing.share;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import pm.crypto.DeviceIdentity;
import pm.sharing.net.PeerLink;
import pm.sharing.pair.Pairer;
import pm.sharing.wire.Message;
import pm.sharing.wire.WireException;

/** Runs a {@link ReceiveSession} over a connection to the sender (lan-share.md §6 steps 3–5). */
public final class ShareClient {
    private ShareClient() {
    }

    /**
     * Receives one share.
     *
     * @return the offer that was applied
     * @throws ShareException declined, refused, or not applied; nothing was applied
     */
    public static Message.ShareOffer receive(PeerLink link, ReceiveSession session, OfferPrompt prompt,
            ShareApplier applier) throws IOException, ShareException {
        Objects.requireNonNull(link, "link");
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(prompt, "prompt");
        Objects.requireNonNull(applier, "applier");
        return run(link, session, prompt, applier);
    }

    private static Message.ShareOffer run(PeerLink link, ReceiveSession s, OfferPrompt prompt, ShareApplier applier)
            throws IOException, ShareException {
        link.send(s.start());
        while (s.state() != ReceiveSession.State.DONE) {
            if (s.state() == ReceiveSession.State.OFFERED) {
                decide(link, s, prompt);
            } else if (s.state() == ReceiveSession.State.VALIDATING) {
                apply(link, s, applier);
            } else {
                link.send(step(link, s));
            }
        }
        return s.offer();
    }

    private static void decide(PeerLink link, ReceiveSession s, OfferPrompt prompt)
            throws IOException, ShareException {
        link.readTimeout(Pairer.CONFIRM_TIMEOUT);
        if (!prompt.accept(s.offer(), DeviceIdentity.fingerprint(link.peerKey()))) {
            link.send(s.decline());
            throw new ShareException(ShareException.Code.DECLINED);
        }
        link.send(s.accept());
    }

    private static void apply(PeerLink link, ReceiveSession s, ShareApplier applier)
            throws IOException, ShareException {
        byte[] payload = s.payload().toByteArray();
        boolean ok;
        try {
            ok = applier.apply(s.offer().kind(), payload);
        } finally {
            Arrays.fill(payload, (byte) 0);
        }
        link.send(s.applied(ok));
        if (!ok) {
            throw new ShareException(ShareException.Code.NOT_APPLIED);
        }
    }

    /** Receives and handles one message; on a failure tells the sender why, then rethrows. */
    private static List<Message> step(PeerLink link, ReceiveSession s) throws IOException, ShareException {
        try {
            return s.receive(next(link, s));
        } catch (ShareException e) {
            ShareServer.sendBestEffort(link, s.abort(e.code()));
            throw e;
        }
    }

    private static Message next(PeerLink link, ReceiveSession s) throws IOException, ShareException {
        try {
            return link.receive();
        } catch (WireException e) {
            throw s.fail(ShareException.Code.PROTOCOL);
        }
    }
}
