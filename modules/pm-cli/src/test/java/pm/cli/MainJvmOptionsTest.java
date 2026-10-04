package pm.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import pm.domain.env.Env;

/** SR-711: pm refuses to run with JVM options injected through the environment (M7.3 review). */
class MainJvmOptionsTest {

    @ParameterizedTest
    @ValueSource(strings = {"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"})
    void refusesEachJvmOptionVariable(String name) {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        String value = "-XX:-DisableAttachMechanism";
        int status = Main.refuseJvmOptionsFromEnvironment(
                Env.of(Map.of(name, value)), new PrintStream(err, true, StandardCharsets.UTF_8));
        assertEquals(ExitCodes.USAGE, status);
        String printed = err.toString(StandardCharsets.UTF_8);
        assertEquals(Messages.JVM_OPTIONS_IN_ENVIRONMENT.text() + System.lineSeparator(), printed);
        assertFalse(printed.contains(value), "the variable's value is never echoed");
    }

    @Test
    void runsWhenNoneIsSetOrAllAreEmpty() {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(err, true, StandardCharsets.UTF_8);
        assertEquals(ExitCodes.OK, Main.refuseJvmOptionsFromEnvironment(Env.of(Map.of("TERM", "xterm")), ps));
        assertEquals(ExitCodes.OK, Main.refuseJvmOptionsFromEnvironment(
                Env.of(Map.of("JAVA_TOOL_OPTIONS", "", "_JAVA_OPTIONS", "", "JDK_JAVA_OPTIONS", "")), ps));
        assertTrue(err.toString(StandardCharsets.UTF_8).isEmpty());
    }
}
