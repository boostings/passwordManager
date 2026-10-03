package pm.browser.host;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import pm.crypto.SecretBytes;

/**
 * Chrome native messaging framing (ADR 0014 §2): a 4-byte length in native byte order, then that
 * many bytes of UTF-8 JSON. Every platform the host ships on (x86-64, AArch64) is little-endian,
 * so the order is fixed to little-endian rather than read from the JVM. The length is checked
 * before anything is allocated (MSC05-J).
 */
public final class NativeFrames {
    /** Largest message accepted from the browser: 1 MiB (SR-303). Chrome allows 64 MiB; we do not. */
    public static final int MAX_INBOUND = 1 << 20;
    /** Largest message Chrome accepts from a host: 1 MiB. */
    public static final int MAX_OUTBOUND = 1 << 20;
    private static final int HEADER = Integer.BYTES;

    private NativeFrames() {
    }

    /**
     * Reads one frame body. The caller owns the bytes and should zero them after decoding.
     *
     * @throws HostException {@code CLOSED} at a clean end of stream, {@code TRUNCATED} inside a
     *     frame, {@code FRAME_SIZE} for a length of zero or above {@link #MAX_INBOUND}
     */
    public static byte[] read(InputStream in) throws IOException, HostException {
        byte[] header = Objects.requireNonNull(in, "in").readNBytes(HEADER);
        if (header.length == 0) {
            throw new HostException(HostException.Code.CLOSED);
        }
        if (header.length < HEADER) {
            throw new HostException(HostException.Code.TRUNCATED);
        }
        long length = Integer.toUnsignedLong(ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN).getInt());
        if (length == 0 || length > MAX_INBOUND) {
            throw new HostException(HostException.Code.FRAME_SIZE);
        }
        byte[] body = in.readNBytes((int) length);
        if (body.length != length) {
            Arrays.fill(body, (byte) 0);
            throw new HostException(HostException.Code.TRUNCATED);
        }
        return body;
    }

    /**
     * Writes one frame and flushes.
     *
     * @throws HostException {@code FRAME_SIZE} if {@code body} is empty or above
     *     {@link #MAX_OUTBOUND}; nothing is written then
     */
    public static void write(OutputStream out, SecretBytes body) throws IOException, HostException {
        Objects.requireNonNull(out, "out");
        int length = Objects.requireNonNull(body, "body").length();
        if (length == 0 || length > MAX_OUTBOUND) {
            throw new HostException(HostException.Code.FRAME_SIZE);
        }
        out.write(ByteBuffer.allocate(HEADER).order(ByteOrder.LITTLE_ENDIAN).putInt(length).array());
        IOException[] failed = new IOException[1];
        body.withBytes(b -> {
            try {
                out.write(b);
            } catch (IOException e) {
                failed[0] = e;
            }
        });
        if (failed[0] != null) {
            throw failed[0];
        }
        out.flush();
    }

    /**
     * Decodes a frame body as strict UTF-8: malformed, overlong, truncated or surrogate-encoding
     * sequences are refused, never replaced. The caller owns the returned chars and should zero
     * them after parsing; the intermediate buffer is zeroed here.
     *
     * @throws HostException {@code BAD_UTF8}
     */
    public static char[] utf8(byte[] body) throws HostException {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        // UTF-8 never yields more UTF-16 units than it has bytes, so the buffer cannot overflow.
        CharBuffer chars = CharBuffer.allocate(body.length);
        try {
            CoderResult result = decoder.decode(ByteBuffer.wrap(body), chars, true);
            if (result.isUnderflow()) {
                result = decoder.flush(chars);
            }
            if (!result.isUnderflow()) {
                throw new HostException(HostException.Code.BAD_UTF8);
            }
            return Arrays.copyOf(chars.array(), chars.position());
        } finally {
            Arrays.fill(chars.array(), '\0');
        }
    }
}
