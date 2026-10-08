package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.approval.AuditLog;
import pm.approval.ipc.RunDir;
import pm.domain.env.Env;

/** The TUI's broker: served only while unlocked, nothing left behind on exit, no broker on a bad log. */
class SocketApprovalHostTest {
    @TempDir
    Path tmp;

    private Env env() throws IOException {
        Path xdg = Files.createDirectory(tmp.resolve("xdg"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        return Env.of(Map.of("XDG_RUNTIME_DIR", xdg.toString()));
    }

    @Test
    void tokenFileExistsOnlyWhileUnlockedAndSocketGoesOnClose() throws IOException {
        Env env = env();
        Path run = RunDir.locate(env, tmp);
        try (ApprovalHost host = ApprovalHost.socket(tmp, env, Clock.systemUTC(), "alice")) {
            assertTrue(host.broker().isEmpty(), "nothing runs before the first unlock");
            host.unlocked(grant -> new TreeMap<>());
            assertTrue(host.broker().isPresent());
            assertTrue(host.broker().get().isUnlocked());
            assertTrue(Files.exists(run.resolve(RunDir.AUTH_FILE)));
            assertTrue(Files.exists(run.resolve(RunDir.SOCKET)));
            host.locked();
            assertFalse(Files.exists(run.resolve(RunDir.AUTH_FILE)));
            assertFalse(host.broker().get().isUnlocked());
            host.unlocked(grant -> new TreeMap<>());
            assertTrue(Files.exists(run.resolve(RunDir.AUTH_FILE)), "a fresh token after unlocking again");
        }
        assertFalse(Files.exists(run.resolve(RunDir.AUTH_FILE)));
        assertFalse(Files.exists(run.resolve(RunDir.SOCKET)));
    }

    @Test
    void aDamagedAuditLogMeansNoBroker() throws IOException {
        Env env = env();
        Files.writeString(tmp.resolve(AuditLog.FILE_NAME), "not a log\n", StandardCharsets.US_ASCII);
        try (ApprovalHost host = ApprovalHost.socket(tmp, env, Clock.systemUTC(), "alice")) {
            host.unlocked(grant -> new TreeMap<>());
            assertTrue(host.broker().isEmpty(), "env run falls back to the CLI path, which reports the log");
            assertFalse(Files.exists(RunDir.locate(env, tmp).resolve(RunDir.AUTH_FILE)));
        }
    }

    @Test
    void onTheDefaultVaultABrokerThatCannotStartSaysTheBrowserIsOff() throws IOException {
        Env env = env();
        Path vault = tmp.resolve("v.pmv");
        Files.writeString(tmp.resolve(AuditLog.FILE_NAME), "not a log\n", StandardCharsets.US_ASCII);
        try (ApprovalHost host = ApprovalHost.socketFor(vault, env, Clock.systemUTC(), "alice", true)) {
            assertEquals(Optional.empty(), host.browserNote());
            host.unlocked(grant -> new TreeMap<>());
            assertTrue(host.broker().isEmpty());
            assertEquals(Optional.of(Messages.BROWSER_NO_APPROVALS), host.browserNote(), "the status line says why");
            assertFalse(Files.exists(BrowserRelay.socketPath(vault)), "no relay without a broker");
        }
    }
}
