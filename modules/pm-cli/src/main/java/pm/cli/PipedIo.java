package pm.cli;

import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.Charset;

/**
 * Output-only {@link ConsoleIo} for a command that needs no input when there is no terminal, such
 * as {@code pm generate | pbcopy}. Nothing can be read: a passphrase is never taken from a pipe
 * (SR-500): a line read reports end of input and a secret read returns nothing (an empty array,
 * which every secret prompt refuses).
 */
final class PipedIo implements ConsoleIo {
    private final PrintWriter outWriter;
    private final PrintWriter errWriter;

    PipedIo(OutputStream out, OutputStream err, Charset charset) {
        // Both live for the whole process; closing them would close the standard streams.
        this.outWriter = new PrintWriter(new OutputStreamWriter(out, charset), false);
        this.errWriter = new PrintWriter(new OutputStreamWriter(err, charset), true);
    }

    @Override
    public char[] readPassword(String prompt) {
        return new char[0];
    }

    @Override
    public String readLine(String prompt) {
        return null;
    }

    @Override
    public PrintWriter out() {
        return outWriter;
    }

    @Override
    public PrintWriter err() {
        return errWriter;
    }
}
