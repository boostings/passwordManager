package pm.sharing.wire;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** Length-prefixed framing, bounded before allocation. */
@Tag("T-FUZZ-LAN")
class FramesTest {
    @Test
    void framesRoundTripBackToBack() throws IOException, WireException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Frames.write(out, new byte[] {1, 2, 3});
        Frames.write(out, new byte[Frames.MAX_BODY]);
        ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
        assertArrayEquals(new byte[] {1, 2, 3}, Frames.read(in));
        assertEquals(Frames.MAX_BODY, Frames.read(in).length);
        assertCode(WireException.Code.CLOSED, in);
    }

    @Test
    void writingAnEmptyOrOversizedBodyIsRefused() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertThrows(IllegalArgumentException.class, () -> Frames.write(out, new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> Frames.write(out, new byte[Frames.MAX_BODY + 1]));
        assertEquals(0, out.size());
    }

    @Test
    void badLengthsAreRefusedBeforeReadingTheBody() {
        assertCode(WireException.Code.FRAME_SIZE, header(0));
        assertCode(WireException.Code.FRAME_SIZE, header(Frames.MAX_BODY + 1));
        assertCode(WireException.Code.FRAME_SIZE, header(-1)); // 4 GiB - 1 read as unsigned
    }

    @Test
    void streamsThatEndInsideAFrameAreTruncated() {
        assertCode(WireException.Code.TRUNCATED, new ByteArrayInputStream(new byte[] {0, 0}));
        assertCode(WireException.Code.TRUNCATED, header(10)); // header only, no body
    }

    private static ByteArrayInputStream header(int length) {
        return new ByteArrayInputStream(ByteBuffer.allocate(Integer.BYTES).putInt(length).array());
    }

    private static void assertCode(WireException.Code code, ByteArrayInputStream in) {
        assertEquals(code, assertThrows(WireException.class, () -> Frames.read(in)).code());
    }
}
