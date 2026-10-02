package pm.cli;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/** Scripted {@link ConsoleIo}: secrets and lines are consumed in order; prompts are echoed to out. */
final class FakeConsoleIo implements ConsoleIo {
    private final Deque<char[]> secrets = new ArrayDeque<>();
    private final Deque<String> lines = new ArrayDeque<>();
    private final List<char[]> handedOut = new ArrayList<>();
    private final StringWriter outBuffer = new StringWriter();
    private final StringWriter errBuffer = new StringWriter();
    private final PrintWriter outWriter = new PrintWriter(outBuffer);
    private final PrintWriter errWriter = new PrintWriter(errBuffer);

    FakeConsoleIo secret(String typed) {
        secrets.addLast(typed.toCharArray());
        return this;
    }

    FakeConsoleIo line(String typed) {
        lines.addLast(typed);
        return this;
    }

    @Override
    public char[] readPassword(String prompt) {
        outWriter.print(prompt);
        char[] next = secrets.pollFirst();
        if (next != null) {
            handedOut.add(next);
        }
        return next;
    }

    @Override
    public String readLine(String prompt) {
        outWriter.print(prompt);
        return lines.pollFirst();
    }

    @Override
    public PrintWriter out() {
        return outWriter;
    }

    @Override
    public PrintWriter err() {
        return errWriter;
    }

    String outText() {
        outWriter.flush();
        return outBuffer.toString();
    }

    String errText() {
        errWriter.flush();
        return errBuffer.toString();
    }

    /** Whether every array returned by {@link #readPassword} has been zero-filled. */
    boolean allSecretsZeroed() {
        for (char[] a : handedOut) {
            for (char c : a) {
                if (c != Character.MIN_VALUE) {
                    return false;
                }
            }
        }
        return true;
    }

    int secretsRead() {
        return handedOut.size();
    }
}
