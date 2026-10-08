package pm.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.approval.AuditEvent;
import pm.approval.AuditLog;
import pm.approval.ipc.RunDir;
import pm.domain.env.Env;
import pm.vault.record.LoginRecord;

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
    void aRefusedAuditEntryIsShownWithTheLogsOwnReason() throws IOException {
        // m712-002/-003: share and device notices name a broken or busy log; a plain I/O error keeps
        // the caller's own text.
        Env env = env();
        Path log = tmp.resolve(AuditLog.FILE_NAME);
        String fallback = ShareDialog.AUDIT_FAILED;
        try (ApprovalHost host = ApprovalHost.socket(tmp, env, Clock.systemUTC(), "alice")) {
            assertTrue(host.audit(AuditEvent.of("share")));
            assertEquals(fallback, host.auditFailure(fallback));
            Files.writeString(log, "not a log\n", StandardCharsets.US_ASCII);
            assertFalse(host.audit(AuditEvent.of("share")));
            assertEquals("audit log tampered or truncated after entry 0", host.auditFailure(fallback));
            Files.delete(log);
            Files.createDirectory(log);
            assertFalse(host.audit(AuditEvent.of("share")));
            assertEquals(fallback, host.auditFailure(fallback), "a plain I/O failure");
            Files.delete(log);
            Files.delete(tmp.resolve(AuditLog.FILE_NAME + ".head"));
            assertTrue(host.audit(AuditEvent.of("share")), "a new log after both files were archived");
            try (FileChannel channel = FileChannel.open(log, StandardOpenOption.READ, StandardOpenOption.WRITE);
                    FileLock held = channel.lock()) {
                assertTrue(held.isValid());
                assertFalse(host.audit(AuditEvent.of("share")), "after waiting AuditLog.LOCK_WAIT");
                assertEquals("the audit log is in use by another pm process; try again", host.auditFailure(fallback));
            }
            assertTrue(host.audit(AuditEvent.of("share")));
            assertEquals(fallback, host.auditFailure(fallback), "a success clears the last reason");
        }
        assertEquals(fallback, ApprovalHost.none().auditFailure(fallback));
    }

    @Test
    void theShareDialogNamesABrokenLogAndSharesNothing() throws IOException {
        Env env = env();
        Path log = Files.createFile(tmp.resolve(AuditLog.FILE_NAME),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.writeString(log, "not a log\n", StandardCharsets.US_ASCII);
        try (TuiHarness h = new TuiHarness(new FakeVaultPort("share passphrase", "share recovery"),
                ApprovalHost.socket(tmp, env, Clock.systemUTC(), "alice"))) {
            h.controller.useLanBind(InetAddress.getLoopbackAddress());
            h.unlockWith("share passphrase");
            h.controller.openShare(firstLogin(h));
            h.pump();
            ShareDialog share = h.controller.shownForm(ShareDialog.class);
            share.press(ShareDialog.BROWSER);
            h.pump();
            share.press(ShareDialog.APPROVE);
            h.pump();
            assertTrue(h.screenText().contains("audit log tampered or truncated after entry 0"), h::screenText);
            assertFalse(h.screenText().contains(ShareDialog.AUDIT_FAILED),
                    "the specific reason replaces the generic one");
            assertFalse(share.windowOpen(), "no audit, no share");
            h.controller.lock();
        }
    }

    @SuppressWarnings("PMD.CloseResource") // CE-035: records are the fake session's
    private static LoginRecord firstLogin(TuiHarness h) {
        return h.port.last().records().stream().filter(LoginRecord.class::isInstance)
                .map(LoginRecord.class::cast).findFirst().orElseThrow();
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
