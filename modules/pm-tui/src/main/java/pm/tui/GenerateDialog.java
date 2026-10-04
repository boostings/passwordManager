package pm.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.CheckBox;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.GridLayout;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import java.time.Clock;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import pm.crypto.SecretBoundary;
import pm.domain.generate.CharClass;
import pm.domain.generate.Generated;
import pm.domain.generate.PassphraseGenerator;
import pm.domain.generate.PassphrasePolicy;
import pm.domain.generate.PasswordGenerator;
import pm.domain.generate.PasswordPolicy;

/**
 * Generator dialog (plan.md §13 M4.4, ADR 0012): a password (length, symbols, look-alike
 * characters) or a passphrase (words), drawn by {@code pm.domain.generate} from {@code Csprng}.
 * The result is shown in the dialog with its entropy and is not saved. The generator's
 * {@code SecretChars} is closed as soon as the label holds the text, and the label is emptied on
 * Close, Esc, lock and quit like any form (ADR 0008); Lanterna keeps label text as a
 * {@code String}, the same accepted residual as typed passwords in {@link AddLoginDialog}.
 */
final class GenerateDialog implements InputForm {
    static final String TITLE = "Generate";
    static final String GENERATE_LABEL = "Generate";
    static final String CLOSE = "Close";
    static final String WORDS_MODE_LABEL = "Passphrase (words)";
    static final String SYMBOLS = "Symbols";
    static final String NO_LOOKALIKES = "No look-alike characters";
    static final String HINT = "⇥ next   esc close";

    private static final int SIZE_COLUMNS = 6;
    private static final int RESULT_COLUMNS = 64;
    private static final int GRID_COLUMNS = 2;
    private static final int SIDE_MARGIN = 3;
    private static final Pattern DIGITS = Pattern.compile("[0-9]{1,4}");

    private final Clock clock;
    private final BasicWindow basicWindow = new BasicWindow(TITLE);
    private final CheckBox passphraseBox = new CheckBox(WORDS_MODE_LABEL);
    private final TextBox sizeBox = new TextBox(new TerminalSize(SIZE_COLUMNS, 1),
            String.valueOf(PasswordPolicy.DEFAULT_LENGTH));
    private final CheckBox symbolsBox = new CheckBox(SYMBOLS);
    private final CheckBox lookalikesBox = new CheckBox(NO_LOOKALIKES);
    private final Label result = new Label("");
    private final Label entropy = new Label("");
    private final Notice notice;

    GenerateDialog(PmTheme theme, Clock clock) {
        this.clock = clock;
        this.notice = new Notice(theme);
        symbolsBox.setChecked(true);
        sizeBox.setValidationPattern(Pattern.compile("[0-9]{0,4}"));
        passphraseBox.addListener(words -> {
            sizeBox.setText(String.valueOf(words ? PassphrasePolicy.DEFAULT_WORDS : PasswordPolicy.DEFAULT_LENGTH));
            symbolsBox.setEnabled(!words);
            lookalikesBox.setEnabled(!words);
        });
        result.setForegroundColor(theme.color(PmTheme.Tone.BRIGHT));
        result.setLabelWidth(RESULT_COLUMNS);
        entropy.setForegroundColor(theme.color(PmTheme.Tone.MUTED));

        GridLayout layout = new GridLayout(GRID_COLUMNS);
        layout.setHorizontalSpacing(2);
        layout.setLeftMarginSize(SIDE_MARGIN);
        layout.setRightMarginSize(SIDE_MARGIN);
        layout.setTopMarginSize(1);
        Panel grid = new Panel(layout);
        grid.addComponent(UnlockWindow.dim(theme, "Length or words:"), GridLayout.createLayoutData(
                GridLayout.Alignment.END, GridLayout.Alignment.CENTER));
        grid.addComponent(sizeBox);
        grid.addComponent(new EmptySpace());
        grid.addComponent(passphraseBox);
        grid.addComponent(new EmptySpace());
        grid.addComponent(symbolsBox);
        grid.addComponent(new EmptySpace());
        grid.addComponent(lookalikesBox);

        Panel buttons = new Panel(new LinearLayout(Direction.HORIZONTAL).setSpacing(2));
        buttons.addComponent(PmTheme.pill(GENERATE_LABEL, this::generate));
        buttons.addComponent(PmTheme.pill(CLOSE, this::dismiss));

        GridLayout footerLayout = new GridLayout(1);
        footerLayout.setLeftMarginSize(SIDE_MARGIN);
        footerLayout.setRightMarginSize(SIDE_MARGIN);
        footerLayout.setBottomMarginSize(1);
        Panel footer = new Panel(footerLayout);
        footer.addComponent(new EmptySpace());
        footer.addComponent(result, UnlockWindow.centered());
        footer.addComponent(entropy, UnlockWindow.centered());
        footer.addComponent(new EmptySpace());
        footer.addComponent(buttons, UnlockWindow.centered());
        footer.addComponent(notice.label(), UnlockWindow.centered());
        footer.addComponent(UnlockWindow.dim(theme, Messages.GENERATED_HINT), UnlockWindow.centered());
        footer.addComponent(UnlockWindow.dim(theme, HINT), UnlockWindow.centered());

        Panel content = new Panel(new LinearLayout(Direction.VERTICAL));
        content.addComponent(grid);
        content.addComponent(footer, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        basicWindow.setTheme(theme.cards());
        basicWindow.setHints(List.of(Window.Hint.CENTERED, Window.Hint.MODAL));
        basicWindow.setComponent(content);
        basicWindow.setFocusedInteractable(sizeBox);
        basicWindow.addWindowListener(TuiController.closeOnEscape(this::dismiss));
    }

    @Override
    public Window window() {
        return basicWindow;
    }

    /** Empties the shown secret and its entropy (ADR 0008). Idempotent. */
    @Override
    public void clearInputs() {
        result.setText("");
        entropy.setText("");
        notice.clear();
    }

    @Override
    public void animate(Instant now) {
        notice.animate(now);
    }

    /** The text the dialog currently shows as the result, for tests. */
    String shown() {
        return result.getText();
    }

    private void dismiss() {
        clearInputs();
        basicWindow.close();
    }

    /** Draws a new secret under the chosen policy; an out-of-range size shows a catalogue error. */
    void generate() {
        clearInputs();
        String size = sizeBox.getText();
        if (!DIGITS.matcher(size).matches()) {
            notice.error(Messages.BAD_POLICY, clock.instant());
            return;
        }
        int n = Integer.parseInt(size);
        try (Generated generated = passphraseBox.isChecked()
                ? PassphraseGenerator.secure().generate(new PassphrasePolicy(n, PassphrasePolicy.DEFAULT_SEPARATOR))
                : PasswordGenerator.secure().generate(new PasswordPolicy(n, classes(), lookalikesBox.isChecked()))) {
            show(generated);
        } catch (IllegalArgumentException e) {
            notice.error(Messages.BAD_POLICY, clock.instant());
        }
    }

    private Set<CharClass> classes() {
        Set<CharClass> classes = EnumSet.of(CharClass.LOWER, CharClass.UPPER, CharClass.DIGIT);
        if (symbolsBox.isChecked()) {
            classes.add(CharClass.SYMBOL);
        }
        return classes;
    }

    /** Puts the secret on screen, the one reviewed place the generator's output becomes text. */
    @SecretBoundary(reason = "show a generated secret in the generator dialog")
    private void show(Generated generated) {
        generated.secret().withChars(chars -> result.setText(String.valueOf(chars)));
        entropy.setText(Messages.entropy(generated.entropyBits()));
    }
}
