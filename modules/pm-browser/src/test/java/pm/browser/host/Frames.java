package pm.browser.host;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Test helpers: build browser-side frames and read the host's replies back. */
final class Frames {
    private Frames() {
    }

    /** A little-endian length header for {@code length}. */
    static byte[] header(int length) {
        return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(length).array();
    }

    /** One frame carrying {@code json} as UTF-8. */
    static byte[] frame(String json) {
        return frame(json.getBytes(StandardCharsets.UTF_8));
    }

    /** One frame carrying {@code body}. */
    static byte[] frame(byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(header(body.length));
        out.writeBytes(body);
        return out.toByteArray();
    }

    /** The concatenation of {@code frames}. */
    static byte[] concat(byte[]... frames) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] f : frames) {
            out.writeBytes(f);
        }
        return out.toByteArray();
    }

    /** A stream that fails the test if anything reads from it. */
    static InputStream explode() {
        return new InputStream() {
            @Override
            public int read() {
                throw new AssertionError("read from a stream that must not be read");
            }

            @Override
            public int read(byte[] b, int off, int len) {
                throw new AssertionError("read from a stream that must not be read");
            }
        };
    }

    /** Every reply frame in {@code written}, decoded as UTF-8 text. */
    static List<String> replies(byte[] written) {
        List<String> out = new ArrayList<>();
        ByteArrayInputStream in = new ByteArrayInputStream(written);
        try {
            while (in.available() > 0) {
                int n = ByteBuffer.wrap(in.readNBytes(4)).order(ByteOrder.LITTLE_ENDIAN).getInt();
                out.add(new String(in.readNBytes(n), StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out;
    }
}
