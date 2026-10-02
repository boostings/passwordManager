package pm.tui;

import com.googlecode.lanterna.gui2.Window;

/**
 * A window whose text boxes can hold typed input, including masked secrets. {@link TuiController}
 * tracks every open form and calls {@link #clearInputs()} on lock, idle-lock and quit, so a typed
 * password does not stay referenced by a closed window (ADR 0008, SR-504).
 */
interface InputForm {
    /** The Lanterna window. */
    Window window();

    /** Empties every text box of the form, masked or not (ADR 0008). Idempotent. */
    void clearInputs();
}
