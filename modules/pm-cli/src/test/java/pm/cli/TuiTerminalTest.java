package pm.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import com.googlecode.lanterna.terminal.DefaultTerminalFactory;
import com.googlecode.lanterna.terminal.Terminal;
import com.googlecode.lanterna.terminal.virtual.DefaultVirtualTerminal;
import java.io.IOException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Verifies production backend selection without opening windows or modifying the host console. */
class TuiTerminalTest {
    @ParameterizedTest
    @CsvSource({"Windows 10,true", "Windows 11,true", "WINDOWS Server 2022,true",
            "Mac OS X,false", "Darwin,false", "Linux,false"})
    void selectsBackend(String osName, boolean desktop) throws IOException {
        try (DefaultVirtualTerminal terminal = new DefaultVirtualTerminal()) {
            RecordingFactory factory = new RecordingFactory(terminal);
            assertSame(terminal, Cli.createTuiTerminal(factory, osName));
            assertEquals(desktop, factory.desktopCalled);
            assertEquals(!desktop, factory.textCalled);
        }
    }

    private static final class RecordingFactory extends DefaultTerminalFactory {
        private final Terminal terminal;
        private boolean desktopCalled;
        private boolean textCalled;

        RecordingFactory(Terminal terminal) {
            this.terminal = terminal;
        }

        @Override
        public Terminal createTerminalEmulator() {
            desktopCalled = true;
            return terminal;
        }

        @Override
        public Terminal createTerminal() {
            textCalled = true;
            return terminal;
        }
    }
}
