package pm.sharing.share;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pm.sharing.share.SharesTest.BOB;
import static pm.sharing.share.SharesTest.PAYLOAD;
import static pm.sharing.share.SharesTest.T0;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.crypto.DeviceIdentity;
import pm.sharing.share.ShareException.Code;
import pm.sharing.wire.Message;
import pm.sharing.wire.Octets;

/** The two share session state machines, pumped in memory (lan-share.md §6, §9). */
@Tag("T-LAN-03")
@Tag("T-LAN-05")
class ShareSessionTest {
    private static final byte[] ALICE = SharesTest.filled(1);
    private static final Octets OTHER_ID = Octets.copyOf(new byte[16]);

    /** Alice sends to Bob; each side has its own clock. */
    private static final class Fixture {
        final MutableClock senderClock = new MutableClock(T0);
        final MutableClock receiverClock = new MutableClock(T0);
        final Shares shares = new Shares();
        final ReceivedShares received = new ReceivedShares();
        final SendSession send = new SendSession(ALICE, BOB, "alice", shares, senderClock);
        final ReceiveSession recv = new ReceiveSession(BOB, ALICE, "bob", received, receiverClock);
        final List<Message> toRecv = new ArrayList<>();
        final List<Message> toSend = new ArrayList<>();

        Fixture(boolean oneUse) {
            SharesTest.open(shares, BOB, oneUse);
        }

        /** Exchanges HELLOs and delivers the offer: receiver in OFFERED. */
        Fixture offered() throws ShareException {
            toRecv.addAll(send.start());
            toSend.addAll(recv.start());
            toRecv.addAll(send.receive(toSend.remove(0)));
            assertEquals(List.of(), recv.receive(toRecv.remove(0)));
            assertEquals(List.of(), recv.receive(toRecv.remove(0)));
            return this;
        }

        /** Accepts and delivers the data: receiver in VALIDATING. */
        Fixture validating() throws ShareException {
            offered();
            toRecv.addAll(send.receive(recv.accept().get(0)));
            assertEquals(List.of(), recv.receive(toRecv.remove(0)));
            return this;
        }

        /** Applies and acknowledges: sender DONE, receiver WAIT_BYE with the BYE in hand. */
        Fixture acknowledged() throws ShareException {
            validating();
            toRecv.addAll(send.receive(recv.applied(true).get(0)));
            return this;
        }
    }

    private static Code fails(SendSession s, Message m) {
        Code c = assertThrows(ShareException.class, () -> s.receive(m)).code();
        assertTrue(s.failed());
        return c;
    }

    private static Code fails(ReceiveSession s, Message m) {
        Code c = assertThrows(ShareException.class, () -> s.receive(m)).code();
        assertTrue(s.failed());
        return c;
    }

    @Test
    void anAcceptedShareIsSentAppliedAndAcknowledged() throws ShareException {
        Fixture f = new Fixture(true).validating();
        assertEquals("api: 3 variables", f.recv.offer().summary());
        assertEquals(Message.Kind.PROJECT, f.recv.offer().kind());
        assertTrue(f.recv.offer().oneUse());
        assertArrayEquals(PAYLOAD, f.recv.payload().toByteArray());
        assertEquals(SendSession.State.WAIT_ACK, f.send.state());
        f.toRecv.addAll(f.send.receive(f.recv.applied(true).get(0)));
        assertEquals(SendSession.State.DONE, f.send.state());
        assertTrue(f.send.delivered());
        assertEquals(List.of(), f.recv.receive(f.toRecv.remove(0)));
        assertEquals(ReceiveSession.State.DONE, f.recv.state());
        assertTrue(f.received.contains(f.recv.offer().shareId()));
        assertFalse(f.shares.anyOpen(T0));
    }

    @Test
    void theSameShareOfferedAgainIsAReplay() throws ShareException {
        Fixture first = new Fixture(false).acknowledged();
        Octets id = first.recv.offer().shareId();
        ReceiveSession again = new ReceiveSession(BOB, ALICE, "bob", first.received, first.receiverClock);
        SendSession resend = new SendSession(ALICE, BOB, "alice", first.shares, first.senderClock);
        resend.start();
        again.start();
        List<Message> hello = new SendSession(ALICE, BOB, "alice", first.shares, first.senderClock).start();
        again.receive(hello.get(0));
        Message offer = resend.receive(new Message.Hello(0, Octets.copyOf(DeviceIdentity.deviceId(BOB)), "bob",
                List.of())).get(0);
        assertEquals(id, ((Message.ShareOffer) offer).shareId());
        assertEquals(Code.REPLAY, fails(again, offer));
    }

    @Test
    void aOneUseShareIsNotOfferedTwice() throws ShareException {
        Fixture first = new Fixture(true).acknowledged();
        SendSession second = new SendSession(ALICE, BOB, "alice", first.shares, first.senderClock);
        second.start();
        List<Message> out = second.receive(new Message.Hello(0, Octets.copyOf(DeviceIdentity.deviceId(BOB)), "bob",
                List.of()));
        assertInstanceOf(Message.Bye.class, out.get(0));
        assertEquals(SendSession.State.DONE, second.state());
        assertTrue(second.offered().isEmpty());
        ReceiveSession r = new ReceiveSession(BOB, ALICE, "bob", new ReceivedShares(), first.receiverClock);
        r.start();
        r.receive(new SendSession(ALICE, BOB, "alice", first.shares, first.senderClock).start().get(0));
        assertEquals(Code.NOTHING_OFFERED, fails(r, new Message.Bye(1)));
    }

    @Test
    void anOfferThatHasExpiredByTheReceiversClockIsRefused() throws ShareException {
        Fixture f = new Fixture(true);
        f.toRecv.addAll(f.send.start());
        f.toSend.addAll(f.recv.start());
        f.toRecv.addAll(f.send.receive(f.toSend.remove(0)));
        f.recv.receive(f.toRecv.remove(0));
        f.receiverClock.advance(Shares.DEFAULT_TTL);
        assertEquals(Code.EXPIRED, fails(f.recv, f.toRecv.remove(0)));
        Message error = f.recv.abort(Code.EXPIRED).get(0);
        assertEquals(new Message.ErrorReport(1, Code.EXPIRED.wire()), error);
        assertEquals(Code.EXPIRED, fails(f.send, error));
    }

    @Test
    void theSenderEnforcesExpiryAndRevocationAtTheAccept() throws ShareException {
        Fixture late = new Fixture(true).offered();
        late.senderClock.advance(Shares.DEFAULT_TTL);
        assertEquals(Code.EXPIRED, fails(late.send, late.recv.accept().get(0)));
        Message error = late.send.abort(Code.EXPIRED).get(0);
        assertEquals(Code.EXPIRED, fails(late.recv, error));

        Fixture revoked = new Fixture(true).offered();
        revoked.shares.revokeDevice(BOB);
        assertEquals(Code.REVOKED, fails(revoked.send, revoked.recv.accept().get(0)));
    }

    @Test
    void decliningEndsBothSidesWithoutData() throws ShareException {
        Fixture f = new Fixture(true).offered();
        Message bye = f.recv.decline().get(0);
        assertEquals(ReceiveSession.State.ENDED, f.recv.state());
        assertEquals(Code.DECLINED, fails(f.send, bye));
        assertTrue(f.shares.anyOpen(T0));
    }

    @Test
    void aFailedApplyIsReportedAndConsumesTheOneUseShare() throws ShareException {
        Fixture f = new Fixture(true).validating();
        List<Message> out = f.recv.applied(false);
        assertEquals(ReceiveSession.State.ENDED, f.recv.state());
        assertEquals(new Message.ErrorReport(3, Code.NOT_APPLIED.wire()), out.get(1));
        assertEquals(Code.NOT_APPLIED, fails(f.send, out.get(0)));
        assertFalse(f.send.delivered());
        assertFalse(f.received.contains(f.recv.offer().shareId()));
        assertFalse(f.shares.anyOpen(T0));
    }

    @Test
    void aHelloForAnotherDeviceOrOutOfSequenceIsAProtocolError() throws ShareException {
        Fixture f = new Fixture(true);
        f.send.start();
        assertEquals(Code.PROTOCOL, fails(f.send, new Message.Hello(0, OTHER_ID, "bob", List.of())));
        Fixture g = new Fixture(true);
        g.recv.start();
        assertEquals(Code.PROTOCOL, fails(g.recv, new Message.Bye(0)));
        Fixture h = new Fixture(true);
        h.recv.start();
        assertEquals(Code.PROTOCOL, fails(h.recv, new Message.Bye(1)));
        assertEquals(Code.PROTOCOL, fails(h.recv, new Message.Bye(0)));
        assertInstanceOf(Message.Bye.class, h.recv.abort(Code.DECLINED).get(0));
    }

    @Test
    void everyOutOfTurnMessageToTheSenderFails() throws ShareException {
        Octets id = new Fixture(true).shares.offerFor(BOB, T0).orElseThrow().id();
        assertEquals(Code.PROTOCOL, sendAfterOffer(new Message.ShareAccept(1, OTHER_ID)));
        assertEquals(Code.PROTOCOL, sendAfterOffer(new Message.ShareAck(1, OTHER_ID, true)));
        assertEquals(Code.PROTOCOL, sendAfterOffer(new Message.Revoke(1, OTHER_ID)));
        assertEquals(Code.PROTOCOL, sendAfterData(f -> new Message.ShareAccept(2, f.recv.offer().shareId())));
        assertEquals(Code.PROTOCOL, sendAfterData(f -> new Message.ShareAck(2, OTHER_ID, true)));
        assertEquals(Code.PROTOCOL, sendAfterData(f -> new Message.Bye(2)));
        assertEquals(16, id.length());
        Fixture done = new Fixture(true).acknowledged();
        assertEquals(Code.PROTOCOL, fails(done.send, new Message.Bye(3)));
        SendSession fresh = new SendSession(ALICE, BOB, "alice", new Shares(), new MutableClock(T0));
        assertEquals(Code.PROTOCOL, fails(fresh, new Message.Bye(0)));
        assertThrows(IllegalStateException.class, fresh::start);
        SendSession started = new SendSession(ALICE, BOB, "alice", new Shares(), new MutableClock(T0));
        started.start();
        assertThrows(IllegalStateException.class, started::start);
    }

    private static Code sendAfterOffer(Message m) throws ShareException {
        return fails(new Fixture(true).offered().send, m);
    }

    private interface Make {
        Message make(Fixture f);
    }

    private static Code sendAfterData(Make m) throws ShareException {
        Fixture f = new Fixture(true).validating();
        return fails(f.send, m.make(f));
    }

    @Test
    void everyOutOfTurnMessageToTheReceiverFails() throws ShareException {
        Fixture f = new Fixture(true).offered();
        assertEquals(Code.PROTOCOL, fails(f.recv, new Message.Bye(2)));

        Fixture g = new Fixture(true).offered();
        g.send.receive(g.recv.accept().get(0));
        assertEquals(Code.PROTOCOL, fails(g.recv, new Message.ShareData(2, OTHER_ID, Octets.copyOf(PAYLOAD))));

        Fixture h = new Fixture(true).offered();
        h.recv.accept();
        assertEquals(Code.PROTOCOL, fails(h.recv, new Message.Bye(2)));

        Fixture i = new Fixture(true).offered();
        i.recv.accept();
        Message.ShareOffer o = i.recv.offer();
        assertEquals(Code.PROTOCOL, fails(i.recv, new Message.ShareOffer(2, o.shareId(), o.kind(), o.summary(),
                o.expires(), o.oneUse())));

        Fixture j = new Fixture(true);
        j.recv.start();
        j.recv.receive(j.send.start().get(0));
        assertEquals(Code.PROTOCOL, fails(j.recv, new Message.ShareData(1, OTHER_ID, Octets.copyOf(PAYLOAD))));

        Fixture k = new Fixture(true).acknowledged();
        assertEquals(Code.PROTOCOL, fails(k.recv, new Message.ShareAck(3, OTHER_ID, true)));

        Fixture v = new Fixture(true).validating();
        assertEquals(Code.PROTOCOL, fails(v.recv, new Message.Bye(3)));

        Fixture d = new Fixture(true).acknowledged();
        d.recv.receive(d.toRecv.remove(0));
        assertEquals(Code.PROTOCOL, fails(d.recv, new Message.Bye(4)));

        Fixture e = new Fixture(true).offered();
        e.recv.decline();
        assertEquals(Code.PROTOCOL, fails(e.recv, new Message.Bye(2)));

        ReceiveSession fresh = new ReceiveSession(BOB, ALICE, "bob", new ReceivedShares(), new MutableClock(T0));
        assertEquals(Code.PROTOCOL, fails(fresh, new Message.Bye(0)));
        assertThrows(IllegalStateException.class, fresh::start);
    }

    @Test
    void receiverLifecycleMisuseIsRefused() throws ShareException {
        ReceiveSession r = new ReceiveSession(BOB, ALICE, "bob", new ReceivedShares(), new MutableClock(T0));
        assertThrows(IllegalStateException.class, r::offer);
        assertThrows(IllegalStateException.class, r::payload);
        assertThrows(IllegalStateException.class, r::accept);
        assertThrows(IllegalStateException.class, r::decline);
        assertThrows(IllegalStateException.class, () -> r.applied(true));
        r.start();
        assertThrows(IllegalStateException.class, r::start);
        assertThrows(IllegalArgumentException.class, () -> new ReceiveSession(new byte[31], ALICE, "bob",
                new ReceivedShares(), new MutableClock(T0)));
        Fixture f = new Fixture(true).offered();
        assertEquals(ReceiveSession.State.OFFERED, f.recv.state());
        assertEquals(Duration.ofMinutes(10).toSeconds(), f.recv.offer().expires() - T0.getEpochSecond());
    }
}
