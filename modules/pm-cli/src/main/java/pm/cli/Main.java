package pm.cli;

/**
 * Command-line entry point: {@code init | add-login | list | search <q> | tui}, or no command to
 * open the whole app, with global option {@code --vault <path>} (plan.md §13 M1). The only class allowed to call {@code System.exit}
 * (ERR09-J); all behaviour lives in {@link Cli} and messages come from a fixed catalogue (SR-501).
 */
public final class Main {

    private Main() {
    }

    /**
     * Parses {@code args}, runs the command and exits with its documented exit code. {@link Cli}
     * already maps runtime exceptions inside a command to exit 5; this catch covers what is left (a
     * failure before the command starts, or an {@link Error} such as running out of memory), so the
     * JVM never prints a stack trace or exception text (SR-501, ERR01-J; ERR08-J-EX0: a catch-all
     * at the trust boundary that filters the exception before it reaches the user).
     */
    public static void main(String[] args) {
        int status;
        try {
            status = new Cli().run(args);
        } catch (RuntimeException | Error e) {
            Cli.reportInternalError(System.err);
            status = ExitCodes.INTERNAL;
        }
        System.exit(status);
    }
}
