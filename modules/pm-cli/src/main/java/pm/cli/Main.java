package pm.cli;

/**
 * Command-line entry point: {@code init | add-login | list | search <q> | tui} with global option
 * {@code --vault <path>} (plan.md §13 M1). The only class allowed to call {@code System.exit}
 * (ERR09-J); messages come from a fixed catalogue (SR-501).
 */
@SuppressWarnings("DoNotCallSuggester") // M1 stub: removed when implemented (not a CERT suppression)
public final class Main {

    private Main() {
    }

    /** Parses {@code args} and runs the command. */
    public static void main(String[] args) {
        throw new UnsupportedOperationException("M1 stub");
    }
}
