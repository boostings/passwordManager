package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.terminal.swing.SwingTerminal;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Objects;
import javax.swing.SwingUtilities;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Exercises actual Swing Ctrl-character decoding and then the real TUI shortcut listeners. */
class DesktopShortcutTest {
    private static final String CANARY =
            Objects.requireNonNull(System.getProperty("pm.canary.secret"), "pm.canary.secret");

    @ParameterizedTest
    @ValueSource(chars = {'n', 't', 'd', 's', 'l', 'x'})
    void desktopCtrlKeysReachTheirActions(char letter) throws IOException, InvocationTargetException,
            InterruptedException {
        try (SwingTerminal terminal = new SwingTerminal();
                TuiHarness h = new TuiHarness(new FakeVaultPort(CANARY, "RK"))) {
            h.unlockWith(CANARY);
            Window dashboard = h.activeWindow();
            // AWT KEY_TYPED Ctrl+letter carries the ASCII control character, not a plain letter.
            SwingUtilities.invokeAndWait(() -> {
                // Simulate the component becoming displayable without opening a desktop window.
                terminal.addNotify();
                HierarchyEvent created = new HierarchyEvent(terminal,
                        HierarchyEvent.HIERARCHY_CHANGED, terminal, null,
                        HierarchyEvent.DISPLAYABILITY_CHANGED);
                for (HierarchyListener listener : terminal.getHierarchyListeners()) {
                    listener.hierarchyChanged(created);
                }
                KeyEvent event = new KeyEvent(terminal, KeyEvent.KEY_TYPED, 0,
                        InputEvent.CTRL_DOWN_MASK, KeyEvent.VK_UNDEFINED, (char) (letter - 'a' + 1));
                for (KeyListener listener : terminal.getKeyListeners()) {
                    listener.keyTyped(event);
                }
            });
            KeyStroke key = terminal.pollInput();
            SwingUtilities.invokeAndWait(terminal::removeNotify);
            assertNotNull(key);
            assertTrue(TuiController.isCtrl(key, letter), key.toString());
            h.terminal.addInput(key);
            h.tick();
            switch (letter) {
                case 'n' -> assertTrue(h.screenText().contains(LoginDialog.TAGS_LABEL));
                case 't' -> assertTrue(h.screenText().contains(ToolsMenu.TITLE));
                case 'd' -> assertTrue(h.screenText().contains("Devices"));
                case 's' -> assertTrue(h.screenText().contains("Share"));
                case 'l' -> assertTrue(h.screenText().contains(UnlockWindow.TITLE));
                case 'x' -> assertTrue(h.controller.isQuit());
                default -> throw new IllegalArgumentException("unsupported test shortcut");
            }
            if (letter != 'x' && letter != 'l') {
                assertEquals("", TuiHarness.boxTexts(dashboard).get(0));
            }
        }
    }
}
