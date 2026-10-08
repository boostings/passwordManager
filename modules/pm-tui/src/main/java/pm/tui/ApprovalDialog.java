package pm.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TerminalTextUtils;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
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
 *
 * <p>A browser request (ADR 0014 §8, SR-113) is shown in full or not at all: the site origin is
 * wrapped across as many lines as it needs, measured in terminal columns, and if the whole prompt
 * does not fit the terminal (now, or after the terminal shrinks) the request is denied and the
 * dialog says why. It offers only {@link #KEYS_ONCE} in the same way: every browser connection
 * has its own requester label, so a session or one-hour approval could never be reused anyway.
 */
final class ApprovalDialog implements InputForm {
    static final String TITLE = "Approval requested";
    static final String TOO_SMALL_TITLE = "Browser request denied";
    static final Duration INPUT_GUARD = Duration.ofMillis(500);
    static final Duration POLICY_DURATION = Duration.ofHours(1);
    static final String KEYS = "y once   s this session   p 1 hour   n deny";
    /** The keys for a request that must prompt every time (and for every browser request). */
    static final String KEYS_ONCE = "y once   n deny";
    static final String GUARDED = "keys open in a moment…";
    static final String CONFIRM_ONCE = "Approve this run once? Enter to confirm, n to deny.";
    static final String CONFIRM_SESSION = "Allow this same request until the vault locks? Enter to confirm.";
    static final String CONFIRM_POLICY = "Allow this same request for 1 hour, even after a lock? Enter to confirm.";
    static final String CONFIRM_AGAIN = "Press Enter once more to confirm.";
    /** Shown under a browser origin that may imitate another site ({@link #isLookalikeRisk}). */
    static final String LOOKALIKE = "⚠ internationalised name: check the site letter by letter";
    /** Shown for a browser request the relay did not register (it did not come through the relay). */
    static final String UNKNOWN_SENDER = "from an unknown sender (not the browser relay)";
    /** Longest argument shown in full; longer ones are cut and flagged. */
    static final int MAX_ARG_COLUMNS = 72;
    /** Most argv lines shown; the rest are counted and flagged. */
    static final int MAX_ARG_LINES = 12;
    /** Columns and rows the window adds around its text: border and margins. */
    static final int FRAME_COLUMNS = 8;
    static final int FRAME_ROWS = 4;

    private static final int SIDE_MARGIN = 3;
    private static final String SITE = "site ";
    private static final String ACTION = "action ";
    private static final String FROM = "from ";
    /** Widest countdown text ({@code PROMPT_TIMEOUT} in seconds, three digits at most). */
    private static final String COUNTDOWN_WIDEST = "denied automatically in 999 s";

    /** What the user chose so far. */
    private enum Choice { NONE, ONCE, SESSION, POLICY }

    /** One line of a browser prompt and its colour. */
    private record Line(String text, PmTheme.Tone tone) { }

    private final PendingApproval pending;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final Label status = new Label(GUARDED);
    private final Label countdown = new Label("");
    private final PmTheme theme;
    private final Instant opensAt;
    private final Instant deniedAt;
    /** False when only "once" and "deny" are offered. */
    private final boolean standing;
    private final boolean browser;
    private final Supplier<TerminalSize> screen;
    /** Smallest terminal the browser prompt fits in; unused for other prompts. */
    private final TerminalSize needed;
    // GUI-thread confined.
    private Choice choice = Choice.NONE;
    private boolean confirming;
    private boolean tooSmall;
    /** The latest tick; keys before {@link #opensAt} are ignored. */
    private Instant now = Instant.MIN;

    /**
     * A prompt for {@code prompt}, shown at {@code shown}.
     *
     * @param screen the terminal's current size, read when the prompt opens and on every tick
     * @param peer for a browser request, the host instance that sent it as the relay saw it;
     *     empty if the relay did not register it
     */
    ApprovalDialog(PmTheme theme, PendingApproval prompt, String osUser, Instant shown, Supplier<TerminalSize> screen,
            Optional<String> peer) {
        this.theme = theme;
        this.pending = prompt;
        this.screen = Objects.requireNonNull(screen, "screen");
        this.opensAt = shown.plus(INPUT_GUARD);
        this.deniedAt = prompt.arrived().plus(ApprovalBroker.PROMPT_TIMEOUT);
        ApprovalRequest q = prompt.request();
        this.browser = q.operation() == ApprovalRequest.Operation.AUTOFILL;
        // A browser approval never outlives its connection (its requester label names it).
        this.standing = q.allowsStandingGrant() && !browser;

        Panel content = panel();
        if (browser) {
            TerminalSize size = screen.get();
            int width = Math.max(1, Math.min(MAX_ARG_COLUMNS, size.getColumns() - FRAME_COLUMNS));
            List<Line> lines = browserLines(q, osUser, peer, width);
            int widest = columns(COUNTDOWN_WIDEST);
            for (String fixed : List.of(GUARDED, KEYS_ONCE, CONFIRM_ONCE)) {
                widest = Math.max(widest, columns(fixed));
            }
            for (Line line : lines) {
                widest = Math.max(widest, columns(line.text()));
            }
            // the lines, a blank line, the status and the countdown
            needed = new TerminalSize(widest + FRAME_COLUMNS, lines.size() + 3 + FRAME_ROWS);
            for (Line line : lines) {
                content.addComponent(line.text().isEmpty() ? new EmptySpace() : label(line));
            }
        } else {
            needed = new TerminalSize(0, 0);
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
        if (browser) {
            checkFits(); // never shows a prompt it would have to cut
        }
    }

    private static Panel panel() {
        GridLayout layout = new GridLayout(1);
        layout.setLeftMarginSize(SIDE_MARGIN);
        layout.setRightMarginSize(SIDE_MARGIN);
        layout.setTopMarginSize(1);
        layout.setBottomMarginSize(1);
        return new Panel(layout);
    }

    private static String describe(ApprovalRequest q) {
        return switch (q.display().effect()) {
            case INJECT -> "wants these secrets injected into a command";
            case SHOW -> "wants these secrets shown";
            case WRITE_FILE -> "wants these secrets written to a file";
            case SEND -> "wants these secrets sent to another device";
        };
    }

    /**
     * The browser extension's request (ADR 0014 §8, SR-113): who asks and from which process,
     * then the exact site origin, wrapped across lines by terminal columns and broken inside the
     * host where it must be, then the action with the login's title or username. Every dynamic
     * part passes through {@link DisplaySafe}; an internationalised (possibly lookalike) host also
     * gets a warning to check it letter by letter. No line is wider than {@code width} columns
     * unless {@code width} cannot hold even its fixed prefix.
     */
    private static List<Line> browserLines(ApprovalRequest q, String osUser, Optional<String> peer, int width) {
        List<Line> lines = new ArrayList<>();
        String label = "\"" + DisplaySafe.text(q.requester().label()) + "\"  ("
                + q.requester().kind().name().toLowerCase(Locale.ROOT) + ")";
        hardWrap("", "", label, width).forEach(t -> lines.add(new Line(t, PmTheme.Tone.AMBER)));
        if (peer.isPresent()) {
            hardWrap(FROM, "     ", DisplaySafe.text(peer.get()), width)
                    .forEach(t -> lines.add(new Line(t, PmTheme.Tone.AMBER)));
        } else {
            hardWrap("", "", UNKNOWN_SENDER, width).forEach(t -> lines.add(new Line(t, PmTheme.Tone.RED)));
        }
        hardWrap("", "", "runs as " + DisplaySafe.text(osUser) + " (verified)", width)
                .forEach(t -> lines.add(new Line(t, PmTheme.Tone.DIM)));
        lines.add(new Line("", PmTheme.Tone.TEXT));
        lines.add(new Line("wants to fill or save a login in the browser", PmTheme.Tone.TEXT));
        String origin = q.scope().project();
        hardWrap(SITE, " ".repeat(SITE.length()), DisplaySafe.text(origin), width)
                .forEach(t -> lines.add(new Line(t, PmTheme.Tone.CYAN)));
        if (isLookalikeRisk(origin)) {
            hardWrap("  ", "  ", LOOKALIKE, width).forEach(t -> lines.add(new Line(t, PmTheme.Tone.RED)));
        }
        String what = q.display().origin()
                .map(d -> d.startsWith(origin + " - ") ? d.substring(origin.length() + 3) : d)
                .orElse("use a login");
        List<String> wrapped = wrap(DisplaySafe.text(what), Math.max(1, width - ACTION.length()));
        for (int i = 0; i < wrapped.size(); i++) {
            lines.add(new Line((i == 0 ? ACTION : " ".repeat(ACTION.length())) + wrapped.get(i), PmTheme.Tone.TEXT));
        }
        return lines;
    }

    /**
     * Whether {@code origin} may look like another site: an internationalised host (the bridge
     * passes only A-labels, {@code xn--}, which browsers may show in Unicode) or, defensively,
     * any character outside printable ASCII.
     */
    static boolean isLookalikeRisk(String origin) {
        return origin.contains("xn--") || !origin.chars().allMatch(c -> c >= 0x20 && c < 0x7f);
    }

    /** Terminal columns {@code text} takes: two for a wide (for example CJK) character, one otherwise. */
    static int columns(String text) {
        return text.codePoints().map(ApprovalDialog::columns).sum();
    }

    private static int columns(int codePoint) {
        return TerminalTextUtils.getColumnWidth(Character.toString(codePoint));
    }

    /**
     * {@code text} cut into lines of at most {@code width} terminal columns, at spaces where
     * possible and inside a word where it must be. Nothing is dropped except the spaces lines
     * are broken at.
     */
    static List<String> wrap(String text, int width) {
        List<String> out = new ArrayList<>();
        String rest = text;
        while (columns(rest) > width) {
            int limit = fit(rest, width);
            int cut = rest.lastIndexOf(' ', limit);
            if (cut <= 0) {
                cut = limit;
            }
            out.add(rest.substring(0, cut));
            rest = rest.substring(cut).stripLeading();
        }
        out.add(rest);
        return out;
    }

    /**
     * {@code text} broken into lines of at most {@code width} columns, every character kept and
     * in order: the first line starts with {@code first}, the others with {@code next} (both of
     * the same width). For a site origin, so it may break inside the host.
     */
    static List<String> hardWrap(String first, String next, String text, int width) {
        int room = Math.max(1, width - columns(first));
        List<String> out = new ArrayList<>();
        String rest = text;
        String prefix = first;
        while (columns(rest) > room) {
            int cut = fit(rest, room);
            out.add(prefix + rest.substring(0, cut));
            rest = rest.substring(cut);
            prefix = next;
        }
        out.add(prefix + rest);
        return out;
    }

    /** The longest prefix of {@code text} (in chars) of at most {@code width} columns; at least one code point. */
    private static int fit(String text, int width) {
        int used = 0;
        int i = 0;
        while (i < text.length()) {
            int cp = text.codePointAt(i);
            int w = columns(cp);
            if (used + w > width && i > 0) {
                break;
            }
            used += w;
            i += Character.charCount(cp);
        }
        return i;
    }

    private Label label(Line line) {
        Label label = new Label(line.text());
        label.setForegroundColor(theme.color(line.tone()));
        return label;
    }

    private Label untrusted(String text) {
        Label label = new Label(text);
        label.setForegroundColor(theme.color(PmTheme.Tone.AMBER));
        return label;
    }

    private List<Label> argvLines(List<String> argv) {
        List<Label> lines = new ArrayList<>();
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

    /**
     * Whether this dialog no longer asks anything: a browser request that did not fit the
     * terminal was denied, and the dialog now only says so until it is closed.
     */
    boolean isNotice() {
        return tooSmall;
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
        this.now = now;
        if (browser && !tooSmall) {
            checkFits();
        }
        if (tooSmall) {
            return;
        }
        if (!now.isBefore(opensAt) && GUARDED.equals(status.getText())) {
            status.setText(standing ? KEYS : KEYS_ONCE);
            status.setForegroundColor(theme.color(PmTheme.Tone.TEXT));
        }
        long left = Math.max(0, Duration.between(now, deniedAt).toSeconds());
        countdown.setText(String.format(Locale.ROOT, "denied automatically in %d s", left));
    }

    /** Denies a browser request the terminal cannot show in full, and says so instead. */
    private void checkFits() {
        TerminalSize size = screen.get();
        if (size.getColumns() >= needed.getColumns() && size.getRows() >= needed.getRows()) {
            return;
        }
        tooSmall = true;
        pending.deny();
        Panel notice = panel();
        int width = Math.max(1, size.getColumns() - FRAME_COLUMNS);
        String text = String.format(Locale.ROOT, "The browser asked for a login, but this terminal (%d×%d) is too"
                + " small to show the whole request, so it was denied. Enlarge the terminal (at least %d×%d)"
                + " and try again.", size.getColumns(), size.getRows(), needed.getColumns(), needed.getRows());
        wrap(text, width).forEach(t -> notice.addComponent(new Label(t)));
        notice.addComponent(new EmptySpace());
        Label close = new Label("Enter or Esc to close");
        close.setForegroundColor(theme.color(PmTheme.Tone.DIM));
        notice.addComponent(close);
        basicWindow.setTitle(TOO_SMALL_TITLE);
        basicWindow.setComponent(notice);
    }

    private void handle(KeyStroke key) {
        if (tooSmall) {
            if (key.getKeyType() == KeyType.Enter || key.getKeyType() == KeyType.Escape) {
                basicWindow.close();
            }
            return;
        }
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

    /** {@code s} and {@code p}: ignored when the request may not be covered by a grant (SR-119, SR-113). */
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
