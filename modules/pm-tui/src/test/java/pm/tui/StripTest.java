package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TerminalTextUtils;
import com.googlecode.lanterna.TextColor;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import pm.approval.ApprovalBroker;
import pm.approval.ipc.Releaser;

/** The header and footer strips: the right runs (the idle-lock countdown, SR-504) are never overdrawn. */
class StripTest {
    private static final String CANARY = "strip test passphrase";
    private static final TextColor RED = TextColor.ANSI.RED;
    private static final TextColor BLUE = TextColor.ANSI.BLUE;

    private static String text(List<Strip.Span> spans) {
        StringBuilder sb = new StringBuilder();
        spans.forEach(s -> sb.append(s.text()));
        return sb.toString();
    }

    @Test
    void runsThatFitAreLeftAlone() {
        List<Strip.Span> spans = List.of(Strip.Span.of("pm", RED), Strip.Span.bold(" vault", BLUE));
        assertSame(spans, Strip.clip(spans, 8));
        assertSame(spans, Strip.clip(spans, 80));
    }

    @Test
    void runsThatDoNotFitAreCutWithAnEllipsisInTheColorWhereTheCutFalls() {
        List<Strip.Span> spans = List.of(Strip.Span.of("pm  ·  ", RED), Strip.Span.bold("browser off", BLUE));
        List<Strip.Span> cut = Strip.clip(spans, 10);
        assertEquals("pm  ·  br…", text(cut));
        assertEquals(BLUE, cut.get(cut.size() - 1).color());
        assertTrue(cut.get(cut.size() - 1).bold());

        assertEquals("pm  ·  …", text(Strip.clip(spans, 8)), "a cut on a run boundary");
        assertEquals("…", text(Strip.clip(spans, 1)));
        assertEquals("", text(Strip.clip(spans, 0)));
        assertEquals("", text(Strip.clip(spans, -3)));
    }

    @Test
    void wideCharactersAreCountedByColumn() {
        List<Strip.Span> spans = List.of(Strip.Span.of("界界界界", RED));
        String cut = text(Strip.clip(spans, 6));
        assertEquals(6, TerminalTextUtils.getColumnWidth(cut), cut);
        assertTrue(cut.startsWith("界界") && cut.endsWith("…"), cut);
    }

    @Test
    void theLongestBrowserNoteNeverRunsIntoTheLockCountdownAtTheMinimumTerminal() throws IOException {
        ApprovalHost noted = new ApprovalHost() {
            @Override
            public Optional<ApprovalBroker> broker() {
                return Optional.empty();
            }

            @Override
            public void unlocked(Releaser releaser) {
                // nothing to serve
            }

            @Override
            public void locked() {
                // nothing to withdraw
            }

            @Override
            public Optional<String> browserNote() {
                return Optional.of(Messages.BROWSER_NO_APPROVALS);
            }

            @Override
            public void close() {
                // nothing to stop
            }
        };
        try (noted; TuiHarness h = new TuiHarness(new FakeVaultPort(CANARY, "unused"), noted,
                new TuiHarness.ManualClock(FakeVaultPort.T0), new TerminalSize(80, 24))) {
            h.unlockWith(CANARY);
            String screen = h.screenText();
            String header = screen.lines().filter(l -> l.contains("Locked in")).findFirst().orElse(screen);
            int countdown = header.indexOf("Locked in");
            assertTrue(header.substring(0, countdown).endsWith("…  "), header);
            assertTrue(header.contains("Locked in 5:00"), header);
        }
    }
}
