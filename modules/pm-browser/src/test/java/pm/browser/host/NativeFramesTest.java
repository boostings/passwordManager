package pm.browser.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;

/** Chrome framing: u32 little-endian length, bounded before allocation (SR-303). */
@Tag("T-FUZZ-NM")
class NativeFramesTest {

    @Test
    void framesRoundTripWithALittleEndianHeader() throws IOException, HostException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (SecretBytes body = SecretBytes.copyOf("{\"a\":1}".getBytes(StandardCharsets.UTF_8))) {
            NativeFrames.write(out, body);
        }
        byte[] written = out.toByteArray();
        assertArrayEquals(new byte[] {7, 0, 0, 0}, java.util.Arrays.copyOf(written, 4));
        ByteArrayInputStream in = new ByteArrayInputStream(Frames.concat(written, Frames.frame(new byte[NativeFrames.MAX_INBOUND])));
        assertEquals("{\"a\":1}", new String(NativeFrames.read(in), StandardCharsets.UTF_8));
        assertEquals(NativeFrames.MAX_INBOUND, NativeFrames.read(in).length);
        assertCode(HostException.Code.CLOSED, in);
    }

    @Test
    void shortHeadersAndBodiesAreTruncated() {
        assertCode(HostException.Code.TRUNCATED, new ByteArrayInputStream(new byte[] {5}));
        assertCode(HostException.Code.TRUNCATED, new ByteArrayInputStream(new byte[] {5, 0, 0}));
        byte[] cut = Frames.concat(Frames.header(10), new byte[] {'{', '}'});
        assertCode(HostException.Code.TRUNCATED, new ByteArrayInputStream(cut));
    }

    @Test
    void zeroAndOversizedLengthsAreRefusedWithoutReadingTheBody() {
        assertCode(HostException.Code.FRAME_SIZE, new ByteArrayInputStream(Frames.header(0)));
        assertCode(HostException.Code.FRAME_SIZE, headerThenExplode(NativeFrames.MAX_INBOUND + 1));
        assertCode(HostException.Code.FRAME_SIZE, headerThenExplode(-1)); // 4 GiB - 1 as unsigned
        assertCode(HostException.Code.FRAME_SIZE, headerThenExplode(64 << 20)); // Chrome's own cap
    }

    @Test
    void writingEmptyOrOversizedRepliesIsRefusedAndWritesNothing() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (SecretBytes empty = SecretBytes.copyOf(new byte[0]);
                SecretBytes big = SecretBytes.copyOf(new byte[NativeFrames.MAX_OUTBOUND + 1])) {
            assertEquals(HostException.Code.FRAME_SIZE,
                    assertThrows(HostException.class, () -> NativeFrames.write(out, empty)).code());
            assertEquals(HostException.Code.FRAME_SIZE,
                    assertThrows(HostException.class, () -> NativeFrames.write(out, big)).code());
        }
        assertEquals(0, out.size());
    }

    @Test
    void aFailingStdoutIsReported() throws IOException {
        try (OutputStream broken = new OutputStream() {
            private int written;

            @Override
            public void write(int b) throws IOException {
                written++;
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                if (written > 0 || len > 4) {
                    throw new IOException("closed");
                }
                written += len;
            }
        };
                SecretBytes body = SecretBytes.copyOf(new byte[] {'1', '2'})) {
            assertThrows(IOException.class, () -> NativeFrames.write(broken, body));
        }
    }

    @Test
    void utf8IsDecodedStrictly() throws HostException {
        assertEquals("é€😀", String.valueOf(NativeFrames.utf8("é€😀".getBytes(StandardCharsets.UTF_8))));
        assertBadUtf8(new byte[] {(byte) 0xff});
        assertBadUtf8(new byte[] {(byte) 0xc0, (byte) 0x80}); // overlong NUL
        assertBadUtf8(new byte[] {(byte) 0xe2, (byte) 0x82}); // truncated sequence
        assertBadUtf8(new byte[] {(byte) 0xed, (byte) 0xa0, (byte) 0x80}); // encoded surrogate
        assertBadUtf8(new byte[] {(byte) 0x80});
    }

    private static void assertBadUtf8(byte[] bytes) {
        assertEquals(HostException.Code.BAD_UTF8,
                assertThrows(HostException.class, () -> NativeFrames.utf8(bytes)).code());
    }

    /** A header of {@code length} followed by a stream that fails if the body is read. */
    private static InputStream headerThenExplode(int length) {
        return new SequenceInputStream(new ByteArrayInputStream(Frames.header(length)), Frames.explode());
    }

    private static void assertCode(HostException.Code code, InputStream in) {
        assertEquals(code, assertThrows(HostException.class, () -> NativeFrames.read(in)).code());
    }
}
