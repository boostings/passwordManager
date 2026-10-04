package pm.cli;

import java.io.PrintStream;
import pm.domain.env.Env;

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
            status = refuseJvmOptionsFromEnvironment(Env.system(), System.err);
            if (status == ExitCodes.OK) {
                status = new Cli().run(args);
            }
        } catch (RuntimeException | Error e) {
            Cli.reportInternalError(System.err);
            status = ExitCodes.INTERNAL;
        }
        System.exit(status);
    }

    /**
     * Refuses to run when a JVM-option environment variable is set (SR-711): such a variable can
     * turn off the hardening flags of the release runtime, for example re-enable the attach
     * mechanism. The JVM has already applied the options by the time {@code main} runs, so this
     * detects the condition and stops before any vault is opened; it cannot undo the options.
     *
     * @return {@link ExitCodes#OK} to continue, or {@link ExitCodes#USAGE} after printing why not
     */
    static int refuseJvmOptionsFromEnvironment(Env env, PrintStream err) {
        if (env.jvmOptionsInjected()) {
            err.println(Messages.JVM_OPTIONS_IN_ENVIRONMENT.text());
            err.flush();
            return ExitCodes.USAGE;
        }
        return ExitCodes.OK;
    }
}
