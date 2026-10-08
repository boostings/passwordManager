package pm.tui;

import com.googlecode.lanterna.gui2.BasicWindow;
import com.googlecode.lanterna.gui2.CheckBox;
import com.googlecode.lanterna.gui2.ComboBox;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import com.googlecode.lanterna.gui2.Window;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.vault.record.WifiRecord;

/**
 * Add or edit a Wi-Fi network: title (the SSID when left empty), SSID, security, hidden, and a
 * masked password, with the rules {@code pm wifi add} and {@code pm edit} apply: an OPEN network
 * has no password, and every other one needs one. Editing keeps the password when its box is left
 * empty, keeps the notes and creation time, and writes back a field shown with replacement
 * characters (SR-501) only if it was changed. Storage and secret handling as {@link LoginDialog}.
 */
final class WifiDialog implements InputForm {
    static final String TITLE = "Add Wi-Fi network";
    static final String EDIT_TITLE = "Edit Wi-Fi network";
    static final String HIDDEN = "Hidden network";
    static final String OPEN = "OPEN";
    static final List<String> SECURITY = List.of("WPA2", "WPA3", "WEP", OPEN);
    static final String KEEP_PASSWORD = "Leave the password empty to keep the current one.";

    private final TuiController controller;
    private final Session session;
    private final Optional<WifiRecord> editing;
    private final BasicWindow basicWindow;
    private final TextBox titleBox = FormLayout.textBox();
    private final TextBox ssidBox = FormLayout.textBox();
    private final ComboBox<String> securityBox = new ComboBox<>(SECURITY);
    private final CheckBox hiddenBox = new CheckBox(HIDDEN);
    private final TextBox passwordBox = MaskedInput.newBox(FormLayout.FIELD_COLUMNS);
    private final Notice notice;

    private WifiDialog(TuiController controller, Session session, Optional<WifiRecord> editing) {
        this.controller = controller;
        this.session = session;
        this.editing = editing;
        PmTheme theme = controller.theme();
        this.notice = new Notice(theme);
        basicWindow = new BasicWindow(editing.isPresent() ? EDIT_TITLE : TITLE);

        Panel grid = FormLayout.grid();
        FormLayout.row(grid, FormLayout.label(theme, "Title:"), titleBox);
        FormLayout.row(grid, FormLayout.requiredLabel(theme, "SSID:"), ssidBox);
        FormLayout.row(grid, FormLayout.label(theme, "Security:"), securityBox);
        FormLayout.row(grid, FormLayout.label(theme, ""), hiddenBox);
        FormLayout.row(grid, FormLayout.label(theme, editing.isPresent() ? "New password:" : "Password:"), passwordBox);
        FormLayout.visibleTextOnly(() -> notice.error(Messages.UNSAFE_CHARACTER, controller.clock().instant()),
                titleBox, ssidBox);
        editing.ifPresent(this::fill);

        FormLayout.dialog(basicWindow, theme, grid, editing.isPresent() ? KEEP_PASSWORD : "", notice,
                List.of(PmTheme.pill(FormLayout.OK, this::submit), PmTheme.pill(FormLayout.CANCEL, this::dismiss)),
                editing.isPresent() ? titleBox : ssidBox, this::dismiss);
    }

    /** The dialog for a new network. */
    static WifiDialog add(TuiController controller, Session session) {
        return new WifiDialog(controller, session, Optional.empty());
    }

    /** The dialog that edits {@code old}. */
    static WifiDialog edit(TuiController controller, Session session, WifiRecord old) {
        return new WifiDialog(controller, session, Optional.of(old));
    }

    private void fill(WifiRecord old) {
        titleBox.setText(DisplaySafe.text(old.title()));
        ssidBox.setText(DisplaySafe.text(old.ssid()));
        securityBox.setSelectedItem(old.security());
        hiddenBox.setChecked(old.hidden());
    }

    /** The Lanterna window. */
    @Override
    public Window window() {
        return basicWindow;
    }

    /** Empties every text box, the masked password included (ADR 0008). */
    @Override
    public void clearInputs() {
        for (TextBox box : List.of(titleBox, ssidBox, passwordBox)) {
            box.setText("");
        }
        notice.clear();
    }

    @Override
    public void animate(Instant now) {
        notice.animate(now);
    }

    private void dismiss() {
        clearInputs();
        basicWindow.close();
    }

    private void submit() {
        String ssid = FormLayout.edited(ssidBox, editing.map(WifiRecord::ssid));
        if (ssid.isEmpty()) {
            showError(Messages.SSID_REQUIRED, ssidBox);
            return;
        }
        String typedTitle = FormLayout.edited(titleBox, editing.map(WifiRecord::title));
        String title = typedTitle.isEmpty() ? ssid : typedTitle;
        String security = securityBox.getSelectedItem();
        try (SecretChars typed = SecretChars.takeOwnership(MaskedInput.drain(passwordBox))) {
            Optional<SecretBytes> password = password(security, typed);
            password.ifPresent(p -> build(title, ssid, security, p));
        } catch (IllegalArgumentException e) {
            showError(Messages.INVALID_INPUT, passwordBox); // unpaired surrogate in the password
        }
    }

    /** The password the rules allow for {@code security}; empty after showing why there is none. */
    private Optional<SecretBytes> password(String security, SecretChars typed) {
        if (OPEN.equals(security)) {
            if (typed.length() > 0) {
                showError(Messages.OPEN_HAS_NO_PASSWORD, passwordBox);
                return Optional.empty();
            }
            return Optional.of(SecretBytes.copyOf(new byte[0]));
        }
        if (typed.length() > 0) {
            return Optional.of(typed.toUtf8());
        }
        Optional<SecretBytes> kept = editing.map(WifiRecord::password).filter(p -> p.length() > 0)
                .map(p -> p.apply(SecretBytes::copyOf));
        if (kept.isEmpty()) {
            showError(Messages.WIFI_NEEDS_PASSWORD, passwordBox);
        }
        return kept;
    }

    private void build(String title, String ssid, String security, SecretBytes password) {
        Instant now = controller.clock().instant();
        boolean hidden = hiddenBox.isChecked();
        Optional<String> failure;
        try {
            failure = editing.isPresent()
                    ? RecordStore.replace(session, editing.get(), new WifiRecord(editing.get().id(), title, ssid,
                            security, password, hidden, editing.get().notes(), editing.get().created(), now))
                    : RecordStore.add(session, new WifiRecord(UUID.randomUUID(), title, ssid, security, password,
                            hidden, "", now, now));
        } catch (IllegalArgumentException e) {
            password.close();
            showError(Messages.INVALID_INPUT, titleBox);
            return;
        }
        if (failure.isPresent()) {
            showError(failure.get(), passwordBox);
            return;
        }
        dismiss();
        controller.changed(editing.isPresent() ? Messages.CHANGES_SAVED : Messages.WIFI_SAVED);
    }

    private void showError(String message, TextBox focus) {
        notice.error(message, controller.clock().instant());
        basicWindow.setFocusedInteractable(focus);
    }
}
