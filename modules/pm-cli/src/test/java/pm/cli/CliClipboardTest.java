package pm.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import pm.domain.env.Env;
import pm.tui.TuiApp;

/** PM_CLIPBOARD_CLEAR (SR-503) and the platforms without a clipboard in v1. */
class CliClipboardTest {
    private static Duration clearAfter(String value) {
        return CliClipboard.clearAfter(Env.of(Map.of("PM_CLIPBOARD_CLEAR", value)));
    }

    @Test
    void theClearTimeIsTakenOnlyInRange() {
        assertEquals(TuiApp.DEFAULT_CLIPBOARD_CLEAR, CliClipboard.clearAfter(Env.of(Map.of())));
        assertEquals(Duration.ofSeconds(5), clearAfter("5"));
        assertEquals(Duration.ofMinutes(5), clearAfter("300"));
        for (String bad : new String[] {"4", "301", "0", "-10", "10s", "1e2", "0010", " 10"}) {
            assertEquals(TuiApp.DEFAULT_CLIPBOARD_CLEAR, clearAfter(bad), bad);
        }
    }

    @Test
    void linuxAndWindowsHaveNoClipboardInV1() {
        assertFalse(CliClipboard.forSystem(Map.of("os.name", "Linux")::get).available());
        assertFalse(CliClipboard.forSystem(Map.of("os.name", "Windows 11")::get).available());
        assertFalse(CliClipboard.forSystem(k -> null).available());
    }
}
