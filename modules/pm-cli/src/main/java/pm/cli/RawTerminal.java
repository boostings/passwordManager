package pm.cli;

import com.googlecode.lanterna.terminal.ansi.UnixTerminal;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;

/**
 * The TUI's terminal on macOS and Linux: Lanterna's {@link UnixTerminal} with software flow
 * control turned off as well. Lanterna's raw mode leaves {@code ixon} on, so the terminal driver
 * takes Ctrl+S as XOFF (the screen freezes until Ctrl+Q) and the app never sees the share
 * shortcut. Lanterna saves the tty settings before raw mode and restores them on close, so
 * {@code ixon} comes back when pm exits. The command runs through Lanterna's own {@code stty}
 * call; pm code spawns no process here (SR-100).
 */
final class RawTerminal extends UnixTerminal {

    RawTerminal(InputStream in, OutputStream out, Charset charset) throws IOException {
        super(in, out, charset, CtrlCBehaviour.CTRL_C_KILLS_APPLICATION);
    }

    @Override
    protected void canonicalMode(boolean enabled) throws IOException {
        super.canonicalMode(enabled);
        if (!enabled) {
            runSTTYCommand("-ixon");
        }
    }
}
