package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.Window;
import com.googlecode.lanterna.input.KeyType;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The redesigned TUI: keyboard shortcuts, Esc handling, empty states, the header count, the saved
 * toast, and the time-driven color (countdown meter, row fade-in, logo shimmer, error flash). All
 * time comes from the harness's manual clock, so every frame here is deterministic.
 */
class TuiLookTest {
    private static final String CANARY =
            Objects.requireNonNull(System.getProperty("pm.canary.secret"), "pm.canary.secret");

    private static TuiHarness unlocked() throws IOException {
        TuiHarness h = new TuiHarness(new FakeVaultPort(CANARY, "RK-0000-1111-2222"));
        h.unlockWith(CANARY);
        return h;
    }

    @Test
    void ctrlNOpensAddLoginAndEscCancelsWithoutSaving() throws IOException {
        try (TuiHarness h = unlocked()) {
            Window dashboard = h.activeWindow();
            h.ctrl('n');
            assertTrue(h.screenText().contains(AddLoginDialog.TAGS_LABEL));
            assertEquals("", TuiHarness.boxTexts(dashboard).get(0)); // ^N never typed an "n"
            Window dialog = h.activeWindow();
            h.type("Title");
            h.press(KeyType.Escape);

            assertFalse(h.screenText().contains(AddLoginDialog.TAGS_LABEL));
            TuiHarness.boxTexts(dialog).forEach(t -> assertEquals("", t));
            assertEquals(0, h.port.last().saveCount());
        }
    }

    @Test
    void arrowDownFromSearchReachesTheTable() throws IOException {
        try (TuiHarness h = unlocked()) {
            h.press(KeyType.ArrowDown, KeyType.ArrowDown, KeyType.Enter); // second row
            assertTrue(h.screenText().contains("HomeNet"));
            assertTrue(h.screenText().contains("WPA3"), h.screenText());
        }
    }

    @Test
    void escClosesTheDetailCard() throws IOException {
        try (TuiHarness h = unlocked()) {
            h.press(KeyType.Tab, KeyType.Enter);
            assertTrue(h.screenText().contains(RecordDetailWindow.CLOSE));
            h.press(KeyType.Escape);
            assertFalse(h.screenText().contains(RecordDetailWindow.CLOSE));
            assertTrue(h.controller.isUnlocked());
        }
    }

    @Test
    void escClearsTheSearch() throws IOException {
        try (TuiHarness h = unlocked()) {
            Window dashboard = h.activeWindow();
            h.type("git");
            assertFalse(h.screenText().contains("HomeNet"));
            h.press(KeyType.Escape);
            assertTrue(h.screenText().contains("HomeNet"));
            assertEquals("", TuiHarness.boxTexts(dashboard).get(0));
        }
    }

    @Test
    void escOnTheUnlockScreenDoesNothing() throws IOException {
        try (TuiHarness h = new TuiHarness(new FakeVaultPort(CANARY, "RK"))) {
            h.press(KeyType.Escape);
            assertTrue(h.screenText().contains(UnlockWindow.TITLE));
            assertFalse(h.controller.isQuit());
        }
    }

    @Test
    void headerCountsItemsAndSearchMatches() throws IOException {
        try (TuiHarness h = unlocked()) {
            h.tick();
            assertTrue(h.screenText().contains("3 items"), h.screenText());
            h.type("git");
            h.tick();
            assertTrue(h.screenText().contains("1 of 3"), h.screenText());
        }
        assertEquals("1 item", Messages.items(1, 1));
        assertEquals("0 items", Messages.items(0, 0));
    }

    @Test
    void noMatchesShowsAHint() throws IOException {
        try (TuiHarness h = unlocked()) {
            assertFalse(h.screenText().contains(Messages.NO_MATCHES));
            h.type("zzz");
            String screen = h.screenText();
            assertTrue(screen.contains(Messages.NO_MATCHES), screen);
            assertTrue(screen.contains(Messages.NO_MATCHES_HINT), screen);
            assertFalse(screen.contains(Messages.EMPTY_VAULT));
        }
    }

    @Test
    void emptyVaultInvitesTheFirstLogin() throws IOException {
        try (TuiHarness h = unlocked()) {
            for (UUID id : h.port.last().records().stream().map(r -> r.id()).toList()) {
                h.port.last().remove(id);
            }
            h.type("x");
            h.press(KeyType.Backspace); // refresh with a blank query
            h.tick();
            String screen = h.screenText();
            assertTrue(screen.contains(Messages.EMPTY_VAULT), screen);
            assertTrue(screen.contains(Messages.EMPTY_VAULT_HINT), screen);
            assertTrue(screen.contains("0 items"), screen);
        }
    }

    @Test
    void savedToastShowsThenFadesAway() throws IOException {
        try (TuiHarness h = unlocked()) {
            h.ctrl('n');
            h.type("Gitea");
            h.press(KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Tab, KeyType.Enter);
            h.tick();
            assertTrue(h.screenText().contains(Messages.SAVED), h.screenText());

            h.clock.advance(Duration.ofSeconds(3));
            h.tick();
            assertFalse(h.screenText().contains(Messages.SAVED));
        }
    }

    @Test
    void countdownShiftsGreenToAmberToRed() throws IOException {
        try (TuiHarness h = unlocked()) {
            h.tick();
            assertEquals(h.theme.color(PmTheme.Tone.GREEN), colorOf(h, "Locked in 5:00"));

            h.clock.advance(Duration.ofMinutes(2).plusSeconds(30));
            h.tick();
            assertEquals(h.theme.color(PmTheme.Tone.AMBER), colorOf(h, "Locked in 2:30"));

            h.clock.advance(Duration.ofMinutes(2).plusSeconds(20)); // 10 s left: red, pulsing
            h.tick();
            TextColor urgent = colorOf(h, "Locked in 0:10");
            assertTrue(urgent.getRed() > urgent.getGreen() && urgent.getRed() > urgent.getBlue(),
                    urgent::toString);
            h.clock.advance(Duration.ofMillis(500));
            h.tick();
            assertNotEquals(urgent, colorOf(h, "Locked in 0:09"), "pulse moves the color");
        }
    }

    @Test
    void rowsFadeInOnAStagger() throws IOException {
        try (TuiHarness h = unlocked()) {
            h.tick();
            TextColor surface = h.theme.color(PmTheme.Tone.SURFACE);
            assertEquals(surface, colorOf(h, "Deploy key"), "rows start invisible");

            h.clock.advance(Duration.ofMillis(100));
            h.tick();
            assertNotEquals(surface, colorOf(h, "Home WiFi"));

            h.clock.advance(Duration.ofSeconds(1));
            h.tick();
            assertEquals(h.theme.color(PmTheme.Tone.TEXT), colorOf(h, "Deploy key"));
        }
    }

    @Test
    void logoGradientFlowsAndShineSweeps() throws IOException {
        try (TuiHarness h = new TuiHarness(new FakeVaultPort(CANARY, "RK"))) {
            h.tick();
            String logo = Banner.LOGO.get(1);
            h.clock.advance(Duration.ofMillis(500));
            h.tick();
            List<TextColor> shining = colorsOf(h, logo);
            h.clock.advance(Duration.ofMillis(1500));
            h.tick();
            List<TextColor> between = colorsOf(h, logo);
            h.clock.advance(Duration.ofMillis(10));
            h.tick();
            List<TextColor> sameFrame = colorsOf(h, logo);
            h.clock.advance(Duration.ofMillis(990));
            h.tick();
            List<TextColor> later = colorsOf(h, logo);
            h.clock.advance(Duration.ofMillis(3500)); // 6.5 s: same gradient phase as 0.5 s, shine at rest
            h.tick();
            List<TextColor> unlit = colorsOf(h, logo);

            assertEquals(between, sameFrame, "repaints only on a new frame");
            assertNotEquals(between, later, "the gradient keeps flowing between sweeps");
            assertNotEquals(unlit, shining, "the shine is mid-logo at 500 ms");
        }
    }

    @Test
    void errorFlashesBrightThenSettlesRed() throws IOException {
        try (TuiHarness h = new TuiHarness(new FakeVaultPort(CANARY, "RK"))) {
            h.unlockWith("wrong");
            String error = Notice.ERROR_MARK + "Wrong passphrase";
            assertEquals(h.theme.color(PmTheme.Tone.BRIGHT), colorOf(h, error));
            assertFalse(h.screenText().contains(Messages.UNLOCKING));
            h.clock.advance(Duration.ofSeconds(1));
            h.tick();
            assertEquals(h.theme.color(PmTheme.Tone.RED), colorOf(h, error));
        }
    }

    @Test
    void appUses256ColorsAndTruecolorStaysExact() {
        assertFalse(PmTheme.standard().isTrueColor());
        assertInstanceOf(TextColor.Indexed.class, PmTheme.standard().color(PmTheme.Tone.VIOLET));
        TextColor violet = new PmTheme(true).color(PmTheme.Tone.VIOLET);
        assertEquals(new TextColor.RGB(0xbb, 0x9a, 0xf7), violet);
    }

    @Test
    void colortermSelectsTruecolorThroughTheEnvAccessor() {
        assertTrue(PmTheme.forEnvironment(pm.domain.env.Env.of(java.util.Map.of("COLORTERM", "truecolor"))).isTrueColor());
        assertTrue(PmTheme.forEnvironment(pm.domain.env.Env.of(java.util.Map.of("COLORTERM", "24bit"))).isTrueColor());
        assertFalse(PmTheme.forEnvironment(pm.domain.env.Env.of(java.util.Map.of("COLORTERM", "yes"))).isTrueColor());
        assertFalse(PmTheme.forEnvironment(pm.domain.env.Env.of(java.util.Map.of())).isTrueColor());
        assertFalse(PmTheme.forEnvironment(pm.domain.env.Env.of(java.util.Map.of("COLORTERM", "truecolor\u001b[2J")))
                .isTrueColor(), "an invalid value counts as unset");
    }

    @Test
    void motionHelpersAreClampedAndEased() {
        assertEquals(0x000000, PmTheme.blend(0x000000, 0xffffff, -1));
        assertEquals(0xffffff, PmTheme.blend(0x000000, 0xffffff, 2));
        assertEquals(0x808080, PmTheme.blend(0x000000, 0xffffff, 0.5));
        Instant t0 = Instant.EPOCH;
        assertEquals(0.5, PmTheme.progress(t0, t0.plusMillis(50), Duration.ofMillis(100)));
        assertEquals(1.0, PmTheme.progress(t0, t0.plusSeconds(9), Duration.ofMillis(100)));
        assertEquals(0.0, PmTheme.progress(t0, t0.minusSeconds(1), Duration.ofMillis(100)));
        assertEquals(0.0, PmTheme.easeOut(0));
        assertEquals(1.0, PmTheme.easeOut(1));
        assertTrue(PmTheme.easeOut(0.5) > 0.5);
    }

    @Test
    void footerListsTheShortcuts() throws IOException {
        try (TuiHarness h = unlocked()) {
            h.tick();
            String screen = h.screenText();
            for (List<String> hint : DashboardWindow.KEY_HINTS) {
                assertTrue(screen.contains(hint.get(0) + " " + hint.get(1)), hint::toString);
            }
        }
    }

    /** Foreground color of every character of {@code text} on screen. */
    private static List<TextColor> colorsOf(TuiHarness h, String text) {
        List<String> lines = h.screenText().lines().toList();
        for (int row = 0; row < lines.size(); row++) {
            int col = lines.get(row).indexOf(text);
            if (col >= 0) {
                int r = row;
                return java.util.stream.IntStream.range(col, col + text.length())
                        .mapToObj(c -> h.terminal.getCharacter(c, r).getForegroundColor()).toList();
            }
        }
        throw new AssertionError("not on screen: " + text);
    }

    /** Foreground color of the first character of {@code text} on screen. */
    private static TextColor colorOf(TuiHarness h, String text) {
        List<String> lines = h.screenText().lines().toList();
        for (int row = 0; row < lines.size(); row++) {
            int col = lines.get(row).indexOf(text);
            if (col >= 0) {
                return h.terminal.getCharacter(col, row).getForegroundColor();
            }
        }
        throw new AssertionError("not on screen: " + text + "\n" + h.screenText());
    }
}
