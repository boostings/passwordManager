package pm.approval.ipc;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;

/** Frames: a 4-byte big-endian length, then that many bytes. */
final class Frames {
    /** Largest request frame (approval-model §5). */
    static final int MAX_REQUEST = 64 * 1024;
    /** Largest reply frame: up to 1024 variables of up to 64 KiB would not fit, so replies are capped here. */
    static final int MAX_REPLY = 8 * 1024 * 1024;
    private static final int HEADER = 4;

    private Frames() {
    }

    static void write(ByteChannel ch, byte[] body) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(HEADER + body.length);
        buf.putInt(body.length).put(body).flip();
        while (buf.hasRemaining()) {
            ch.write(buf);
        }
    }

    /**
     * Reads one frame of at most {@code max} bytes.
     *
     * @throws IpcException {@code TOO_LARGE} before reading a body over the cap, {@code MALFORMED}
     *     if the peer closes early
     */
    static byte[] read(ByteChannel ch, int max) throws IpcException {
        try {
            ByteBuffer header = ByteBuffer.allocate(HEADER);
            fill(ch, header);
            int length = header.flip().getInt();
            if (length < 0 || length > max) {
                throw new IpcException(IpcException.Code.TOO_LARGE, null);
            }
            ByteBuffer body = ByteBuffer.allocate(length);
            fill(ch, body);
            return body.array();
        } catch (IOException e) {
            throw new IpcException(IpcException.Code.IO, e);
        }
    }

    private static void fill(ByteChannel ch, ByteBuffer buf) throws IOException, IpcException {
        while (buf.hasRemaining()) {
            if (ch.read(buf) < 0) {
                throw new IpcException(IpcException.Code.MALFORMED, null);
            }
        }
    }
}
