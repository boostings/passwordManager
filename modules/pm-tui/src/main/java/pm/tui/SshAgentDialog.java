package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.CheckBox;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.GridLayout;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextGUI;
import com.googlecode.lanterna.gui2.Window;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Function;
import pm.crypto.SecretBytes;
import pm.vault.record.SshKeyRecord;

/**
 * ssh-agent actions on one SSH key item (plan.md §13 M4.4, ADR 0013): add it to the user's agent,
 * optionally for one hour and with a confirmation before each use, or remove it. The dialog shows
 * only non-secret fields and hands the record to {@link SshActions}; key parsing and the agent
 * protocol live in {@code pm.cli} (SR-060). Results are catalogue text (SR-501). There is no
 * export here: writing a private key file stays an explicit {@code pm ssh export} in a terminal.
 *
 * <p>The agent call runs on {@link SshActions#executor()}, not the GUI thread, so lock, idle-lock
 * and Ctrl+X keep working while an agent is slow. The call gets its own copy of the key text,
 * closed when it returns, so locking (which closes the session's records) cannot pull bytes from
 * under it. The result is posted back to the GUI thread and dropped if the dialog was closed or
 * torn down by a lock meanwhile. One call at a time.
 */
final class SshAgentDialog {
    static final String TITLE = "SSH agent";
    static final String ADD_LABEL = "Add to agent";
    static final String REMOVE_LABEL = "Remove from agent";
    static final String CLOSE = "Close";
    static final String ONE_HOUR = "Remove after 1 hour";
    static final String CONFIRM = "Confirm each use";
    static final String HINT = "esc close";
    static final Duration LIFETIME = Duration.ofHours(1);

    private static final int GRID_COLUMNS = 2;
    private static final int SIDE_MARGIN = 3;

    private final SshKeyRecord key;
    private final SshActions actions;
    private final PmTheme theme;
    private final BasicWindow basicWindow;
    private final CheckBox oneHour = new CheckBox(ONE_HOUR);
    private final CheckBox confirm = new CheckBox(CONFIRM);
    private final Label statusLine = new Label("");
    /** GUI-thread confined: an agent call is in flight. */
    private boolean inFlight;

    SshAgentDialog(SshKeyRecord key, SshActions actions, PmTheme theme) {
        this.key = key;
        this.actions = actions;
        this.theme = theme;
        basicWindow = new BasicWindow(TITLE);

        GridLayout layout = new GridLayout(GRID_COLUMNS);
        layout.setHorizontalSpacing(2);
        layout.setLeftMarginSize(SIDE_MARGIN);
        layout.setRightMarginSize(SIDE_MARGIN);
        layout.setTopMarginSize(1);
        Panel grid = new Panel(layout);
        row(grid, "Key:", DisplaySafe.text(key.title()));
        row(grid, "Type:", DisplaySafe.text(key.keyType()));
        row(grid, "Fingerprint:", DisplaySafe.text(key.fingerprint()));
        grid.addComponent(new EmptySpace());
        grid.addComponent(oneHour);
        grid.addComponent(new EmptySpace());
        grid.addComponent(confirm);

        Panel buttons = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(2));
        var add = PmTheme.pill(ADD_LABEL, this::add);
        buttons.addComponent(add);
        buttons.addComponent(PmTheme.pill(REMOVE_LABEL, this::remove));
        buttons.addComponent(PmTheme.pill(CLOSE, basicWindow::close));

        GridLayout footerLayout = new GridLayout(1);
        footerLayout.setLeftMarginSize(SIDE_MARGIN);
        footerLayout.setRightMarginSize(SIDE_MARGIN);
        footerLayout.setBottomMarginSize(1);
        Panel footer = new Panel(footerLayout);
        footer.addComponent(new EmptySpace());
        footer.addComponent(buttons, UnlockWindow.centered());
        footer.addComponent(statusLine, UnlockWindow.centered());
        footer.addComponent(UnlockWindow.dim(theme, HINT), UnlockWindow.centered());

        Panel content = new Panel(new LinearLayout(Direction.VERTICAL));
        content.addComponent(grid);
        content.addComponent(footer, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        basicWindow.setTheme(theme.cards());
        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(content);
        basicWindow.setFocusedInteractable(add);
        basicWindow.addWindowListener(TuiController.closeOnEscape(basicWindow::close));
    }

    private void row(Panel grid, String name, String value) {
        grid.addComponent(UnlockWindow.dim(theme, name), GridLayout.createLayoutData(
                GridLayout.Alignment.END, GridLayout.Alignment.CENTER));
        Label v = new Label(value);
        v.setForegroundColor(theme.color(PmTheme.Tone.BRIGHT));
        grid.addComponent(v);
    }

    /** The Lanterna window. */
    Window window() {
        return basicWindow;
    }

    /** The status line, for tests. */
    String status() {
        return statusLine.getText();
    }

    /** Whether an agent call is in flight, for tests. */
    boolean busy() {
        return inFlight;
    }

    /** Adds the key with the chosen constraints, off the GUI thread. */
    void add() {
        Duration lifetime = oneHour.isChecked() ? LIFETIME : Duration.ZERO;
        boolean confirmEach = confirm.isChecked();
        start(text -> actions.add(text, lifetime, confirmEach));
    }

    /** Removes the key from the agent, off the GUI thread. */
    void remove() {
        start(actions::remove);
    }

    /** Runs {@code call} on the port's executor with a private copy of the key text. */
    private void start(Function<SecretBytes, SshActions.Outcome> call) {
        Optional<TextGUI> gui = Optional.ofNullable(basicWindow.getTextGUI());
        if (inFlight || gui.isEmpty()) {
            return;
        }
        inFlight = true;
        statusLine.setForegroundColor(theme.color(PmTheme.Tone.BRIGHT));
        statusLine.setText(Messages.SSH_WORKING);
        SecretBytes text = key.privateKey().apply(SecretBytes::copyOf);
        var guiThread = gui.get().getGUIThread();
        try {
            actions.executor().execute(() -> {
                SshActions.Outcome outcome;
                try (text) {
                    outcome = call.apply(text);
                } catch (RuntimeException e) {
                    outcome = SshActions.Outcome.AGENT_FAILED;
                }
                SshActions.Outcome result = outcome;
                guiThread.invokeLater(() -> finish(result));
            });
        } catch (RejectedExecutionException e) {
            text.close();
            finish(SshActions.Outcome.AGENT_FAILED);
        }
    }

    /** On the GUI thread: shows {@code outcome} unless the dialog is gone. */
    private void finish(SshActions.Outcome outcome) {
        inFlight = false;
        if (basicWindow.getTextGUI() != null) {
            show(outcome);
        }
    }

    private void show(SshActions.Outcome outcome) {
        boolean ok = outcome == SshActions.Outcome.ADDED || outcome == SshActions.Outcome.REMOVED;
        statusLine.setForegroundColor(theme.color(ok ? PmTheme.Tone.GREEN : PmTheme.Tone.RED));
        statusLine.setText(Messages.of(outcome));
    }
}
