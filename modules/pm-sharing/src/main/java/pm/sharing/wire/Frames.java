package pm.sharing.wire;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * Frames: a 4-byte big-endian length, then that many body bytes (lan-share.md §4). The length is
 * checked before anything is allocated (MSC05-J).
 */
public final class Frames {
    /** Largest body: 1 MiB. */
    public static final int MAX_BODY = 1 << 20;
    private static final int HEADER = Integer.BYTES;

    private Frames() {
    }

    /** Writes one frame and flushes. */
    public static void write(OutputStream out, byte[] body) throws IOException {
        Objects.requireNonNull(out, "out");
        Checks.range(Objects.requireNonNull(body, "body").length, 1, MAX_BODY);
        out.write(ByteBuffer.allocate(HEADER).putInt(body.length).array());
        out.write(body);
        out.flush();
    }

    /**
     * Reads one frame body.
     *
     * @throws WireException {@code CLOSED} at a clean end of stream, {@code TRUNCATED} inside a
     *     frame, {@code FRAME_SIZE} for a length of zero or above {@link #MAX_BODY}
     */
    public static byte[] read(InputStream in) throws IOException, WireException {
        byte[] header = Objects.requireNonNull(in, "in").readNBytes(HEADER);
        if (header.length == 0) {
            throw new WireException(WireException.Code.CLOSED);
        }
        if (header.length < HEADER) {
            throw new WireException(WireException.Code.TRUNCATED);
        }
        long length = Integer.toUnsignedLong(ByteBuffer.wrap(header).getInt());
        if (length == 0 || length > MAX_BODY) {
            throw new WireException(WireException.Code.FRAME_SIZE);
        }
        byte[] body = in.readNBytes((int) length);
        if (body.length != length) {
            throw new WireException(WireException.Code.TRUNCATED);
        }
        return body;
    }
}
