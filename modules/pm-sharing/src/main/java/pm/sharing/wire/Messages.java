package pm.sharing.wire;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/**
 * Encodes messages to frame bodies and decodes frame bodies strictly (SR-206): one deterministic
 * CBOR map whose keys are exactly the fields of its {@code t}, each of the right type and within
 * its bounds. Anything else is a {@link WireException} and nothing is returned, so a malformed
 * message never reaches the protocol state machine. The rules are written out in
 * {@code docs/schemas/lan-share.cddl}.
 */
public final class Messages {
    /** Depth 2 (a map holding the caps array); every other bound is the frame size. */
    static final CborLimits LIMITS = new CborLimits(2, 64, Frames.MAX_BODY, Frames.MAX_BODY);

    private Messages() {
    }

    /** The frame body for {@code m}. */
    public static byte[] encode(Message m) {
        Map<String, CborValue> f = new HashMap<>();
        f.put("seq", uint(m.seq()));
        switch (m) {
            case Message.Hello h -> {
                f.put("t", text("hello"));
                f.put("v", uint(Message.Hello.VERSION));
                f.put("device_id", bytes(h.deviceId()));
                f.put("name", text(h.name()));
                f.put("caps", new CborValue.Array(h.caps().stream().map(Messages::text).toList()));
            }
            case Message.PairReq r -> f.put("t", text("pair_req"));
            case Message.PairCommit c -> {
                f.put("t", text("pair_commit"));
                f.put("commit", bytes(c.commit()));
            }
            case Message.PairNonce n -> {
                f.put("t", text("pair_nonce"));
                f.put("nonce", bytes(n.nonce()));
            }
            case Message.PairReveal r -> {
                f.put("t", text("pair_reveal"));
                f.put("nonce", bytes(r.nonce()));
            }
            case Message.PairSasOk s -> {
                f.put("t", text("pair_sas_ok"));
                f.put("mac", bytes(s.mac()));
            }
            case Message.PairDone d -> f.put("t", text("pair_done"));
            case Message.ShareOffer o -> {
                f.put("t", text("share_offer"));
                f.put("share_id", bytes(o.shareId()));
                f.put("kind", text(o.kind().wire()));
                f.put("summary", text(o.summary()));
                f.put("expires", uint(o.expires()));
                f.put("one_use", new CborValue.Bool(o.oneUse()));
            }
            case Message.ShareAccept a -> {
                f.put("t", text("share_accept"));
                f.put("share_id", bytes(a.shareId()));
            }
            case Message.ShareData d -> {
                f.put("t", text("share_data"));
                f.put("share_id", bytes(d.shareId()));
                f.put("payload", bytes(d.payload()));
            }
            case Message.ShareAck a -> {
                f.put("t", text("share_ack"));
                f.put("share_id", bytes(a.shareId()));
                f.put("applied", new CborValue.Bool(a.applied()));
            }
            case Message.Revoke r -> {
                f.put("t", text("revoke"));
                f.put("device_id", bytes(r.deviceId()));
            }
            case Message.ErrorReport e -> {
                f.put("t", text("error"));
                f.put("code", uint(e.code()));
            }
            case Message.Bye b -> f.put("t", text("bye"));
        }
        CborValue.MapV map = new CborValue.MapV(f);
        try {
            return CborWriter.encode(map, LIMITS);
        } finally {
            map.wipe();
        }
    }

    /**
     * Decodes one frame body.
     *
     * @throws WireException {@code MALFORMED}, {@code UNKNOWN_TYPE}, {@code BAD_FIELD} or
     *     {@code VERSION}
     */
    public static Message decode(byte[] body) throws WireException {
        CborValue value;
        try {
            value = CborReader.decode(Objects.requireNonNull(body, "body"), LIMITS);
        } catch (CborException e) {
            throw new WireException(WireException.Code.MALFORMED);
        }
        try {
            if (!(value instanceof CborValue.MapV map)) {
                throw new WireException(WireException.Code.MALFORMED);
            }
            Fields f = new Fields(map.entries());
            Message m = build(f);
            f.requireAllRead();
            return m;
        } catch (IllegalArgumentException e) {
            throw new WireException(WireException.Code.BAD_FIELD);
        } finally {
            value.wipe();
        }
    }

    private static Message build(Fields f) throws WireException {
        String type = f.text("t");
        long seq = f.uint("seq");
        return switch (type) {
            case "hello" -> {
                if (f.uint("v") != Message.Hello.VERSION) {
                    throw new WireException(WireException.Code.VERSION);
                }
                yield new Message.Hello(seq, f.bytes("device_id"), f.text("name"), f.texts("caps"));
            }
            case "pair_req" -> new Message.PairReq(seq);
            case "pair_commit" -> new Message.PairCommit(seq, f.bytes("commit"));
            case "pair_nonce" -> new Message.PairNonce(seq, f.bytes("nonce"));
            case "pair_reveal" -> new Message.PairReveal(seq, f.bytes("nonce"));
            case "pair_sas_ok" -> new Message.PairSasOk(seq, f.bytes("mac"));
            case "pair_done" -> new Message.PairDone(seq);
            case "share_offer" -> new Message.ShareOffer(seq, f.bytes("share_id"),
                    Message.Kind.fromWire(f.text("kind")), f.text("summary"), f.uint("expires"), f.bool("one_use"));
            case "share_accept" -> new Message.ShareAccept(seq, f.bytes("share_id"));
            case "share_data" -> new Message.ShareData(seq, f.bytes("share_id"), f.bytes("payload"));
            case "share_ack" -> new Message.ShareAck(seq, f.bytes("share_id"), f.bool("applied"));
            case "revoke" -> new Message.Revoke(seq, f.bytes("device_id"));
            case "error" -> new Message.ErrorReport(seq, f.uint("code"));
            case "bye" -> new Message.Bye(seq);
            default -> throw new WireException(WireException.Code.UNKNOWN_TYPE);
        };
    }

    private static CborValue uint(long v) {
        return new CborValue.UInt(v);
    }

    private static CborValue text(String s) {
        return new CborValue.Text(s);
    }

    private static CborValue bytes(Octets o) {
        return new CborValue.Bytes(o.toByteArray());
    }

    /** Typed reads from a decoded map that remember which keys were read. */
    private static final class Fields {
        private final Map<String, CborValue> entries;
        private final Set<String> read = new HashSet<>();

        Fields(Map<String, CborValue> entries) {
            this.entries = entries;
        }

        private CborValue get(String key) throws WireException {
            CborValue v = entries.get(key);
            if (v == null) {
                throw new WireException(WireException.Code.BAD_FIELD);
            }
            read.add(key);
            return v;
        }

        long uint(String key) throws WireException {
            if (get(key) instanceof CborValue.UInt u) {
                return u.value();
            }
            throw new WireException(WireException.Code.BAD_FIELD);
        }

        String text(String key) throws WireException {
            return asText(get(key));
        }

        boolean bool(String key) throws WireException {
            if (get(key) instanceof CborValue.Bool b) {
                return b.value();
            }
            throw new WireException(WireException.Code.BAD_FIELD);
        }

        Octets bytes(String key) throws WireException {
            if (get(key) instanceof CborValue.Bytes b) {
                return Octets.copyOf(b.value());
            }
            throw new WireException(WireException.Code.BAD_FIELD);
        }

        List<String> texts(String key) throws WireException {
            if (get(key) instanceof CborValue.Array a) {
                List<String> out = new java.util.ArrayList<>();
                for (CborValue item : a.items()) {
                    out.add(asText(item));
                }
                return out;
            }
            throw new WireException(WireException.Code.BAD_FIELD);
        }

        private static String asText(CborValue v) throws WireException {
            if (v instanceof CborValue.Text t) {
                return t.value();
            }
            throw new WireException(WireException.Code.BAD_FIELD);
        }

        void requireAllRead() throws WireException {
            if (read.size() != entries.size()) {
                throw new WireException(WireException.Code.BAD_FIELD);
            }
        }
    }
}
