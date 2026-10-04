package pm.domain.env;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class EnvTest {

    @Test
    void acceptsWellFormedValues() {
        String home = Path.of("").toAbsolutePath().toString();
        Env env = Env.of(Map.of("HOME", home, "COLORTERM", "truecolor", "TERM", "xterm-256color"));
        assertEquals(Optional.of(home), env.get(Env.Var.HOME));
        assertEquals(Optional.of(Path.of(home).normalize()), env.path(Env.Var.HOME));
        assertEquals(Optional.of("truecolor"), env.get(Env.Var.COLORTERM));
        assertEquals(Optional.of("xterm-256color"), env.get(Env.Var.TERM));
    }

    @Test
    void treatsMalformedValuesAsUnset() {
        Env env = Env.of(Map.of(
                "HOME", "relative/dir",
                "XDG_RUNTIME_DIR", Path.of("").toAbsolutePath() + "\n/evil",
                "COLORTERM", "true color",
                "TERM", "x".repeat(65),
                "SSH_AUTH_SOCK", "",
                "APPDATA", "/" + "a".repeat(Env.MAX_VALUE_CHARS)));
        for (Env.Var v : Env.Var.values()) {
            assertEquals(Optional.empty(), env.get(v), v::name);
        }
    }

    @Test
    void pathOnlyForPathVariables() {
        assertThrows(IllegalArgumentException.class, () -> Env.of(Map.of()).path(Env.Var.COLORTERM));
    }

    @Test
    void systemEnvironmentIsReadable() {
        Env.system().get(Env.Var.TERM); // must not throw whatever the CI environment holds
    }

    @Test
    void jvmOptionVariablesAreDetectedByPresenceOnly() {
        assertFalse(Env.of(Map.of()).jvmOptionsInjected());
        assertFalse(Env.of(Map.of("JAVA_TOOL_OPTIONS", "", "_JAVA_OPTIONS", "", "JDK_JAVA_OPTIONS", ""))
                .jvmOptionsInjected());
        assertFalse(Env.of(Map.of("JAVA_HOME", "/opt/jdk", "TERM", "xterm")).jvmOptionsInjected());
        for (String name : new String[] {"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"}) {
            assertTrue(Env.of(Map.of(name, "-XX:-DisableAttachMechanism")).jvmOptionsInjected(), name);
            // A value no Var check would accept (spaces, control characters) still counts as set.
            assertTrue(Env.of(Map.of(name, " \n")).jvmOptionsInjected(), name);
        }
    }
}
