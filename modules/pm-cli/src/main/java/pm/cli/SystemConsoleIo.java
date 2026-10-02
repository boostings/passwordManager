package pm.cli;

import java.io.Console;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.Objects;

/**
 * Production {@link ConsoleIo} over {@link System#console()}: passphrases are read with echo off
 * through {@link Console#readPassword} (SR-500, ADR 0008); output uses the console charset
 * (FIO11-J).
 */
final class SystemConsoleIo implements ConsoleIo {
    /** Constant format string: prompts are never used as a format (IDS06-J). */
    private static final String PROMPT_FORMAT = "%s";

    private final Console console;
    private final PrintWriter errWriter;

    SystemConsoleIo(Console console) {
        this.console = Objects.requireNonNull(console, "console");
        // Lives for the whole process; closing it would close System.err.
        this.errWriter = new PrintWriter(new OutputStreamWriter(System.err, console.charset()), true);
    }

    @Override
    public char[] readPassword(String prompt) {
        return console.readPassword(PROMPT_FORMAT, prompt);
    }

    @Override
    public String readLine(String prompt) {
        return console.readLine(PROMPT_FORMAT, prompt);
    }

    @Override
    public PrintWriter out() {
        return console.writer();
    }

    @Override
    public PrintWriter err() {
        return errWriter;
    }
}
