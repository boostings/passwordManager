package pm.tui;

import java.util.Optional;

/**
 * The system clipboard, for the record card's Copy (SR-503). The CLI provides it from the platform
 * modules (pm-platform-macos); {@link #none()} where there is none, and tests use a fake.
 * {@link ClipboardGuard} decides when to clear it.
 */
public interface Clipboard {
    /** Whether this platform has a clipboard pm can use. */
    boolean available();

    /**
     * Replaces the clipboard's contents with {@code utf8} as text.
     *
     * @param utf8 the text; not kept, and not zeroed (the caller owns it)
     * @return whether it was placed
     */
    boolean copy(byte[] utf8);

    /** The clipboard's text as bytes the caller zeroes; empty when it cannot be read. */
    Optional<byte[]> read();

    /** Empties the clipboard; returns whether that worked. */
    boolean clear();

    /** No clipboard: Copy says that it is not available here. */
    static Clipboard none() {
        return new Clipboard() {
            @Override
            public boolean available() {
                return false;
            }

            @Override
            public boolean copy(byte[] utf8) {
                return false;
            }

            @Override
            public Optional<byte[]> read() {
                return Optional.empty();
            }

            @Override
            public boolean clear() {
                return false;
            }
        };
    }
}
