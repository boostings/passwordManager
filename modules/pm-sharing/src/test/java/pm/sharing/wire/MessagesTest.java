package pm.sharing.wire;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.Size;
import org.junit.jupiter.api.Test;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/** The strict message codec (lan-share.md §4, docs/schemas/lan-share.cddl). */
class MessagesTest {
    private static final Octets ID16 = Octets.copyOf(new byte[16]);
    private static final Octets V32 = Octets.copyOf(new byte[32]);

    static List<Message> samples() {
        return List.of(
                new Message.Hello(0, ID16, "Jimmy's laptop", List.of("share", "pair")),
                new Message.PairReq(1),
                new Message.PairCommit(2, V32),
                new Message.PairNonce(3, V32),
                new Message.PairReveal(4, V32),
                new Message.PairSasOk(5, V32),
                new Message.PairDone(6),
                new Message.ShareOffer(7, ID16, Message.Kind.PROJECT, "api: 3 variables", 1_800_000_000L, true),
                new Message.ShareAccept(8, ID16),
                new Message.ShareData(9, ID16, Octets.copyOf(new byte[] {1, 2, 3})),
                new Message.ShareAck(10, ID16, false),
                new Message.Revoke(11, ID16),
                new Message.ErrorReport(12, 3),
                new Message.Bye(13));
    }

    @Test
    void everyMessageRoundTrips() throws WireException {
        for (Message m : samples()) {
            assertEquals(m, Messages.decode(Messages.encode(m)), m.getClass().getSimpleName());
        }
        Message.ShareOffer secret = new Message.ShareOffer(0, ID16, Message.Kind.SECRET, "1 secret", 1, false);
        assertEquals(secret, Messages.decode(Messages.encode(secret)));
    }

    @Test
    void encodingIsDeterministicCbor() {
        // {"t": "bye", "seq": 0}: keys in bytewise order of their encoding, shortest forms.
        assertEquals("a261746362796563736571" + "00", HexFormat.of().formatHex(Messages.encode(new Message.Bye(0))));
    }

    @Test
    void bodiesThatAreNotOneCanonicalMapAreMalformed() {
        assertCode(WireException.Code.MALFORMED, CborWriter.encode(new CborValue.UInt(1)));
        assertCode(WireException.Code.MALFORMED, new byte[] {(byte) 0xff});
        byte[] bye = Messages.encode(new Message.Bye(0));
        byte[] trailing = java.util.Arrays.copyOf(bye, bye.length + 1);
        assertCode(WireException.Code.MALFORMED, trailing);
    }

    @Test
    void typeAndSequenceAreRequired() {
        assertCode(WireException.Code.UNKNOWN_TYPE, with(new Message.Bye(0), f -> f.put("t", text("hax"))));
        assertCode(WireException.Code.BAD_FIELD, with(new Message.Bye(0), f -> f.put("t", new CborValue.UInt(1))));
        assertCode(WireException.Code.BAD_FIELD, with(new Message.Bye(0), f -> f.remove("seq")));
        assertCode(WireException.Code.BAD_FIELD, with(new Message.Bye(0), f -> f.put("seq", text("0"))));
    }

    @Test
    void extraFieldsAreRefused() {
        assertCode(WireException.Code.BAD_FIELD, with(new Message.Bye(0), f -> f.put("debug", text("x"))));
        assertCode(WireException.Code.BAD_FIELD,
                with(new Message.PairReq(0), f -> f.put("nonce", new CborValue.Bytes(new byte[32]))));
    }

    @Test
    void fieldsOfTheWrongTypeAreRefused() {
        Message offer = samples().get(7);
        assertCode(WireException.Code.BAD_FIELD, with(offer, f -> f.put("one_use", new CborValue.UInt(1))));
        assertCode(WireException.Code.BAD_FIELD, with(offer, f -> f.put("share_id", text("id"))));
        Message hello = samples().get(0);
        assertCode(WireException.Code.BAD_FIELD, with(hello, f -> f.put("caps", text("share"))));
        assertCode(WireException.Code.BAD_FIELD,
                with(hello, f -> f.put("caps", new CborValue.Array(List.of(new CborValue.UInt(1))))));
    }

    @Test
    void fieldsOutOfRangeAreRefused() {
        Message hello = samples().get(0);
        assertCode(WireException.Code.BAD_FIELD, with(hello, f -> f.put("device_id", new CborValue.Bytes(new byte[15]))));
        assertCode(WireException.Code.BAD_FIELD, with(hello, f -> f.put("name", text("line\nbreak"))));
        assertCode(WireException.Code.BAD_FIELD, with(hello, f -> f.put("name", text((char) 0x202E + "evil"))));
        assertCode(WireException.Code.BAD_FIELD, with(hello, f -> f.put("name", text(""))));
        assertCode(WireException.Code.BAD_FIELD, with(hello, f -> f.put("name", text("n".repeat(33)))));
        assertCode(WireException.Code.BAD_FIELD, with(hello, f -> f.put("caps", texts(17))));
        assertCode(WireException.Code.BAD_FIELD,
                with(hello, f -> f.put("caps", new CborValue.Array(List.of(text("UPPER"))))));
        Message offer = samples().get(7);
        assertCode(WireException.Code.BAD_FIELD, with(offer, f -> f.put("kind", text("other"))));
        assertCode(WireException.Code.BAD_FIELD, with(offer, f -> f.put("expires", new CborValue.UInt(0))));
        assertCode(WireException.Code.BAD_FIELD,
                with(samples().get(12), f -> f.put("code", new CborValue.UInt(0x1_0000))));
        assertCode(WireException.Code.BAD_FIELD,
                with(samples().get(9), f -> f.put("payload", new CborValue.Bytes(new byte[0]))));
        assertCode(WireException.Code.BAD_FIELD,
                with(samples().get(2), f -> f.put("commit", new CborValue.Bytes(new byte[33]))));
    }

    @Test
    void anotherProtocolVersionIsRefused() {
        assertCode(WireException.Code.VERSION, with(samples().get(0), f -> f.put("v", new CborValue.UInt(2))));
    }

    @Test
    void constructorsEnforceTheSameBoundsWhenSending() {
        assertThrows(IllegalArgumentException.class, () -> new Message.ErrorReport(0, -1));
        assertThrows(IllegalArgumentException.class,
                () -> new Message.ShareData(0, ID16, Octets.copyOf(new byte[Message.MAX_PAYLOAD + 1])));
        assertThrows(IllegalArgumentException.class, () -> Message.Kind.fromWire("SECRET"));
        assertEquals(Message.Kind.SECRET, Message.Kind.fromWire("secret"));
    }

    @Test
    void theLargestPayloadFitsInOneFrame() throws WireException {
        Message big = new Message.ShareData(Long.MAX_VALUE, ID16, Octets.copyOf(new byte[Message.MAX_PAYLOAD]));
        byte[] body = Messages.encode(big);
        assertEquals(true, body.length <= Frames.MAX_BODY);
        assertEquals(big, Messages.decode(body));
    }

    @Property(tries = 2000)
    void arbitraryBytesAreRefusedOnlyWithWireException(@ForAll @Size(max = 300) byte[] body) {
        try {
            Messages.decode(body);
        } catch (WireException e) {
            assertEquals(e.code().name(), e.getMessage());
        }
    }

    @Property(tries = 2000)
    void mutatedValidMessagesDecodeOrAreRefusedCleanly(@ForAll("encoded") byte[] body,
            @ForAll int position, @ForAll byte xor) {
        body[Math.floorMod(position, body.length)] ^= xor;
        try {
            Messages.decode(body);
        } catch (WireException e) {
            assertEquals(e.code().name(), e.getMessage());
        }
    }

    @Provide
    Arbitrary<byte[]> encoded() {
        return Arbitraries.of(samples()).map(Messages::encode);
    }

    private static CborValue text(String s) {
        return new CborValue.Text(s);
    }

    private static CborValue texts(int n) {
        return new CborValue.Array(java.util.stream.IntStream.range(0, n).mapToObj(i -> text("c" + i)).toList());
    }

    /** The encoding of {@code m} with its field map edited. */
    private static byte[] with(Message m, Consumer<Map<String, CborValue>> edit) {
        try {
            CborValue.MapV map = (CborValue.MapV) pm.vault.cbor.CborReader.decode(Messages.encode(m), Messages.LIMITS);
            Map<String, CborValue> fields = new HashMap<>(map.entries());
            edit.accept(fields);
            return CborWriter.encode(new CborValue.MapV(fields));
        } catch (pm.vault.cbor.CborException e) {
            throw new AssertionError(e);
        }
    }

    private static void assertCode(WireException.Code code, byte[] body) {
        assertEquals(code, assertThrows(WireException.class, () -> Messages.decode(body)).code());
    }
}
