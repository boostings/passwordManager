package pm.cli;

import java.io.PrintWriter;

/**
 * Terminal I/O seam so {@link Cli} can be driven by scripted input in tests (SR-500). Passphrases
 * are read only as {@code char[]}, never as {@code String} (MSC03-J, ADR 0008).
 */
interface ConsoleIo {

    /**
     * Prompts and reads a line without echo. The caller owns and must zero the returned array.
     *
     * @return the characters typed, or {@code null} at end of input
     */
    char[] readPassword(String prompt);

    /**
     * Prompts and reads a line of non-secret text.
     *
     * @return the line, or {@code null} at end of input
     */
    String readLine(String prompt);

    /** Writer for normal output. */
    PrintWriter out();

    /** Writer for diagnostics; carries only catalogue messages (SR-501). */
    PrintWriter err();
}
