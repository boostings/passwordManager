package pm.cli;

import java.time.Duration;
import java.util.Optional;
import java.util.function.UnaryOperator;
import pm.domain.env.Env;
import pm.platform.macos.Pasteboard;
import pm.tui.Clipboard;
import pm.tui.TuiApp;

/**
 * The TUI's clipboard (M7.8, SR-503): the macOS general pasteboard through {@link Pasteboard}.
 * Linux and Windows have no clipboard in v1 (platform matrix), so Copy says so there and Reveal
 * still works.
 */
final class CliClipboard implements Clipboard {
    /** Shortest and longest {@code PM_CLIPBOARD_CLEAR}, in seconds. */
    static final long MIN_CLEAR_SECONDS = 5;
    static final long MAX_CLEAR_SECONDS = 300;

    private final Pasteboard pasteboard;

    private CliClipboard(Pasteboard pasteboard) {
        this.pasteboard = pasteboard;
    }

    /** The system clipboard on macOS when its tools are present; {@link Clipboard#none()} otherwise. */
    static Clipboard forSystem(UnaryOperator<String> properties) {
        if (!VaultPaths.isMac(properties)) {
            return Clipboard.none();
        }
        return Pasteboard.system().<Clipboard>map(CliClipboard::new).orElseGet(Clipboard::none);
    }

    /**
     * How long a copied password stays on the clipboard: {@code PM_CLIPBOARD_CLEAR} seconds when
     * it is a whole number from {@value #MIN_CLEAR_SECONDS} to {@value #MAX_CLEAR_SECONDS}, else
     * {@link TuiApp#DEFAULT_CLIPBOARD_CLEAR}.
     */
    static Duration clearAfter(Env env) {
        return env.get(Env.Var.PM_CLIPBOARD_CLEAR)
                .filter(v -> v.length() <= 3 && v.chars().allMatch(c -> c >= '0' && c <= '9'))
                .map(Long::parseLong)
                .filter(s -> s >= MIN_CLEAR_SECONDS && s <= MAX_CLEAR_SECONDS)
                .map(Duration::ofSeconds)
                .orElse(TuiApp.DEFAULT_CLIPBOARD_CLEAR);
    }

    @Override
    public boolean available() {
        return true;
    }

    @Override
    public boolean copy(byte[] utf8) {
        return pasteboard.copy(utf8);
    }

    @Override
    public Optional<byte[]> read() {
        return pasteboard.read();
    }

    @Override
    public boolean clear() {
        return pasteboard.clear();
    }
}
