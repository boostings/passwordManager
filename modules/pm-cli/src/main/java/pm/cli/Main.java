package pm.cli;

/**
 * Command-line entry point: {@code init | add-login | list | search <q> | tui} with global option
 * {@code --vault <path>} (plan.md §13 M1). The only class allowed to call {@code System.exit}
 * (ERR09-J); all behaviour lives in {@link Cli} and messages come from a fixed catalogue (SR-501).
 */
public final class Main {

    private Main() {
    }

    /** Parses {@code args}, runs the command and exits with its documented exit code. */
    public static void main(String[] args) {
        System.exit(new Cli().run(args));
    }
}
