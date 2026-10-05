package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.GridLayout;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.gui2.WindowListenerAdapter;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import pm.approval.ApprovalBroker;
import pm.approval.ApprovalRequest;
import pm.approval.PendingApproval;

/**
 * The approval prompt (approval-model §4, SR-109): who asks (the caller's label in the untrusted
 * style), the verified OS user, the operation and scope, and the exact argv, one element per line.
 * Keys are ignored for {@link #INPUT_GUARD} after it appears, so typing meant for another window
 * cannot approve. {@code y} then Enter approves once; {@code s} or {@code p} then Enter shows a
 * confirmation line and a second Enter approves for the session or for {@link #POLICY_DURATION};
 * {@code n} or Esc denies. A request no grant may cover ({@link ApprovalRequest#allowsStandingGrant()}
 * false, such as a passkey) offers only {@link #KEYS_ONCE}, and {@code s} and {@code p} do nothing
 * (SR-119). Only one prompt is shown at a time, in arrival order.
 */
final class ApprovalDialog implements InputForm {
    static final String TITLE = "Approval requested";
    static final Duration INPUT_GUARD = Duration.ofMillis(500);
    static final Duration POLICY_DURATION = Duration.ofHours(1);
    static final String KEYS = "y once   s this session   p 1 hour   n deny";
    /** The keys for a request that must prompt every time. */
    static final String KEYS_ONCE = "y once   n deny";
    static final String GUARDED = "keys open in a moment…";
    static final String CONFIRM_ONCE = "Approve this run once? Enter to confirm, n to deny.";
    static final String CONFIRM_SESSION = "Allow this same request until the vault locks? Enter to confirm.";
    static final String CONFIRM_POLICY = "Allow this same request for 1 hour, even after a lock? Enter to confirm.";
    static final String CONFIRM_AGAIN = "Press Enter once more to confirm.";
    /** Longest argument shown in full; longer ones are cut and flagged. */
    static final int MAX_ARG_COLUMNS = 72;
    /** Most argv lines shown; the rest are counted and flagged. */
    static final int MAX_ARG_LINES = 12;

    private static final int SIDE_MARGIN = 3;

    /** What the user chose so far. */
    private enum Choice { NONE, ONCE, SESSION, POLICY }

    private final PendingApproval pending;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final Label status = new Label(GUARDED);
    private final Label countdown = new Label("");
    private final PmTheme theme;
    private final Instant opensAt;
    private final Instant deniedAt;
    /** False when only "once" and "deny" are offered. */
    private final boolean standing;
    // GUI-thread confined.
    private Choice choice = Choice.NONE;
    private boolean confirming;
    /** The latest tick; keys before {@link #opensAt} are ignored. */
    private Instant now = Instant.MIN;

    ApprovalDialog(PmTheme theme, PendingApproval prompt, String osUser, Instant shown) {
        this.theme = theme;
        this.pending = prompt;
        this.opensAt = shown.plus(INPUT_GUARD);
        this.deniedAt = prompt.arrived().plus(ApprovalBroker.PROMPT_TIMEOUT);
        ApprovalRequest q = prompt.request();
        this.standing = q.allowsStandingGrant();

        GridLayout layout = new GridLayout(1);
        layout.setLeftMarginSize(SIDE_MARGIN);
        layout.setRightMarginSize(SIDE_MARGIN);
        layout.setTopMarginSize(1);
        layout.setBottomMarginSize(1);
        Panel content = new Panel(layout);
        content.addComponent(untrusted("\"" + DisplaySafe.text(q.requester().label()) + "\"  ("
                + q.requester().kind().name().toLowerCase(Locale.ROOT) + ")"));
        content.addComponent(UnlockWindow.dim(theme, "runs as " + DisplaySafe.text(osUser) + " (verified)"));
        content.addComponent(new EmptySpace());
        content.addComponent(new Label(describe(q)));
        content.addComponent(new Label("project " + DisplaySafe.text(q.scope().project()) + "   profile "
                + q.scope().profile()));
        content.addComponent(new Label(q.scope().vars()
                .map(v -> v.size() + (v.size() == 1 ? " variable: " : " variables: ") + String.join(", ", v))
                .orElse("every variable in the profile")));
        if (!q.display().argv().isEmpty()) {
            content.addComponent(new EmptySpace());
            content.addComponent(new Label("command, one argument per line:"));
            argvLines(q.display().argv()).forEach(content::addComponent);
        }
        content.addComponent(new EmptySpace());
        status.setForegroundColor(theme.color(PmTheme.Tone.DIM));
        content.addComponent(status);
        countdown.setForegroundColor(theme.color(PmTheme.Tone.DIM));
        content.addComponent(countdown);

        basicWindow.setTheme(theme.cards());
        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(content);
        basicWindow.addWindowListener(new Keys());
    }

    private static String describe(ApprovalRequest q) {
        return switch (q.display().effect()) {
            case INJECT -> "wants these secrets injected into a command";
            case SHOW -> "wants these secrets shown";
            case WRITE_FILE -> "wants these secrets written to a file";
            case SEND -> "wants these secrets sent to another device";
        };
    }

    private Label untrusted(String text) {
        Label label = new Label(text);
        label.setForegroundColor(theme.color(PmTheme.Tone.AMBER));
        return label;
    }

    private List<Label> argvLines(List<String> argv) {
        List<Label> lines = new java.util.ArrayList<>();
        boolean cut = false;
        for (int i = 0; i < argv.size() && i < MAX_ARG_LINES; i++) {
            String arg = DisplaySafe.text(argv.get(i));
            if (arg.length() > MAX_ARG_COLUMNS) {
                arg = arg.substring(0, MAX_ARG_COLUMNS) + "…";
                cut = true;
            }
            Label line = new Label("  \"" + arg + "\"");
            line.setForegroundColor(theme.color(PmTheme.Tone.CYAN));
            lines.add(line);
        }
        if (argv.size() > MAX_ARG_LINES || cut) {
            Label warn = new Label("  ⚠ shortened for display: " + argv.size() + " arguments in all");
            warn.setForegroundColor(theme.color(PmTheme.Tone.RED));
            lines.add(warn);
        }
        return lines;
    }

    /** The prompt this dialog answers. */
    PendingApproval prompt() {
        return pending;
    }

    @Override
    public Window window() {
        return basicWindow;
    }

    @Override
    public void clearInputs() {
        // no text boxes
    }

    @Override
    public void animate(Instant now) {
        if (!now.isBefore(opensAt) && GUARDED.equals(status.getText())) {
            status.setText(standing ? KEYS : KEYS_ONCE);
            status.setForegroundColor(theme.color(PmTheme.Tone.TEXT));
        }
        long left = Math.max(0, Duration.between(now, deniedAt).toSeconds());
        countdown.setText(String.format(Locale.ROOT, "denied automatically in %d s", left));
        this.now = now;
    }

    private void handle(KeyStroke key) {
        if (now.isBefore(opensAt)) {
            return; // SR-109: the first half second of keys is ignored
        }
        if (key.getKeyType() == KeyType.Escape) {
            answer(pending::deny);
            return;
        }
        if (key.getKeyType() == KeyType.Enter) {
            enter();
            return;
        }
        if (key.getKeyType() != KeyType.Character || key.isCtrlDown() || key.isAltDown()) {
            return;
        }
        switch (Character.toLowerCase(key.getCharacter())) {
            case 'y' -> choose(Choice.ONCE, CONFIRM_ONCE);
            case 's' -> chooseStanding(Choice.SESSION, CONFIRM_SESSION);
            case 'p' -> chooseStanding(Choice.POLICY, CONFIRM_POLICY);
            case 'n' -> answer(pending::deny);
            default -> {
                // other keys do nothing
            }
        }
    }

    /** {@code s} and {@code p}: ignored when the request may not be covered by a grant (SR-119). */
    private void chooseStanding(Choice c, String text) {
        if (standing) {
            choose(c, text);
        }
    }

    private void choose(Choice c, String text) {
        choice = c;
        confirming = false;
        status.setText(text);
        status.setForegroundColor(theme.color(c == Choice.ONCE ? PmTheme.Tone.GREEN : PmTheme.Tone.AMBER));
    }

    private void enter() {
        switch (choice) {
            case NONE -> {
                // Enter alone never approves
            }
            case ONCE -> answer(pending::approveOnce);
            case SESSION, POLICY -> {
                if (!confirming) {
                    confirming = true;
                    status.setText(CONFIRM_AGAIN);
                    return;
                }
                answer(choice == Choice.SESSION ? pending::approveForSession
                        : () -> pending.approveForPolicy(POLICY_DURATION));
            }
        }
    }

    private void answer(Runnable decision) {
        decision.run();
        basicWindow.close();
    }

    /** Swallows every key: nothing typed here reaches the windows below. */
    private final class Keys extends WindowListenerAdapter {
        @Override
        public void onInput(Window basePane, KeyStroke key, AtomicBoolean deliverEvent) {
            deliverEvent.set(false);
            handle(key);
        }
    }
}
