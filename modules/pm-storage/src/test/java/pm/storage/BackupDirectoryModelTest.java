package pm.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import pm.storage.ModelFileSystem.Kind;
import pm.storage.StorageException.Code;

/**
 * {@link BackupDirectory}'s defensive paths on every host (M7.10), with the faults injected by
 * {@link ModelFileSystem}: the size bound, writes that make no progress, a target that appears
 * while the copy is staged, the listing filter, a folder that changes under an open directory,
 * and the ACL platforms' skipped directory sync.
 */
final class BackupDirectoryModelTest {
    private static final byte[] DATA = {1, 2, 3};

    @TempDir Path temp;

    private final ModelFileSystem fs = new ModelFileSystem(Kind.POSIX, FileSystems.getDefault());
    private final ModelFileSystem acl = new ModelFileSystem(Kind.ACL, FileSystems.getDefault());
    private Path dir;

    @BeforeEach
    void setUp() throws IOException {
        dir = fs.wrap(temp.toRealPath());
    }

    private static Code code(Executable call) {
        return assertThrows(StorageException.class, call).code();
    }

    @Test
    void limitsOutsideOneToTheMaximumAreRefused() {
        Path backups = dir.resolve("b");
        VaultFileStore.CrashHook none = step -> { };
        assertEquals("LIMIT", assertThrows(IllegalArgumentException.class,
                () -> BackupDirectory.open(backups, none, 0)).getMessage());
        assertEquals("LIMIT", assertThrows(IllegalArgumentException.class,
                () -> BackupDirectory.open(backups, none, BackupDirectory.maxBytes() + 1)).getMessage());
    }

    @Test
    void dataOverTheLimitIsRefusedBeforeAnythingIsWritten() throws IOException, StorageException {
        BackupDirectory backups = BackupDirectory.open(dir.resolve("b"), step -> { }, 2);
        assertEquals(Code.TOO_LARGE, code(() -> backups.createNew("x.pmbak", new byte[3])));
        assertEquals(List.of(), backups.list("x", ""));
        backups.createNew("x.pmbak", new byte[2]);
        assertEquals(List.of("x.pmbak"), backups.list("x", ""));
    }

    @Test
    void aWriteThatMakesNoProgressFailsAndLeavesNothing() throws IOException, StorageException {
        BackupDirectory backups = BackupDirectory.open(dir.resolve("b"));
        fs.meta(backups.path().resolve("x.pmbak.tmp")).zeroWrites = true;
        assertEquals(Code.IO, code(() -> backups.createNew("x.pmbak", DATA)));
        assertEquals(new BackupDirectory.Listing(List.of(), List.of()), backups.scan("x", ""));
    }

    @Test
    void aTargetThatAppearsWhileTheCopyIsStagedIsNeverReplaced() throws IOException, StorageException {
        Path folder = dir.resolve("b");
        byte[] theirs = {9};
        BackupDirectory backups = BackupDirectory.open(folder, step -> {
            if (step == VaultFileStore.Step.TMP_SYNCED) {
                Files.write(folder.resolve("x.pmbak"), theirs);
            }
        });
        assertEquals(Code.IO, code(() -> backups.createNew("x.pmbak", DATA)));
        Path real = temp.toRealPath().resolve("b");
        assertArrayEquals(theirs, Files.readAllBytes(real.resolve("x.pmbak")));
        assertFalse(Files.exists(real.resolve("x.pmbak.tmp")), "the staged copy was removed");
    }

    @Test
    void aFileReportedOverTheBoundIsRefusedUnread() throws IOException, StorageException {
        Path big = Files.createFile(dir.resolve("big.pmbak"));
        fs.meta(big).reportedSize = BackupDirectory.maxBytes() + 1;
        assertEquals(Code.TOO_LARGE, code(() -> BackupDirectory.readFile(big)));
    }

    @Test
    void aScanKeepsOnlyThePrefixTheSuffixAndTheNamePattern() throws IOException, StorageException {
        BackupDirectory backups = BackupDirectory.open(dir.resolve("b"));
        FileAttribute<?> ownerOnly = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
        for (String name : List.of("pm-1.pmbak", "other.pmbak", "pm-1.txt", "pm- 1.pmbak")) {
            Files.createFile(backups.path().resolve(name), ownerOnly);
        }
        assertEquals(new BackupDirectory.Listing(List.of("pm-1.pmbak"), List.of()), backups.scan("pm-", ".pmbak"));
    }

    @Test
    void aFolderThatBecameALinkOrMovedIsRefused() throws IOException, StorageException {
        BackupDirectory backups = BackupDirectory.open(dir.resolve("b"));
        ModelFileSystem.Meta folder = fs.meta(backups.path());
        folder.reportLink = true;
        assertEquals(Code.SYMLINK_REFUSED, code(() -> backups.list("x", "")));
        folder.reportLink = false;
        folder.realPath = dir;
        assertEquals(Code.SYMLINK_REFUSED, code(() -> backups.list("x", "")));
        folder.realPath = null;
        assertEquals(List.of(), backups.list("x", ""));
    }

    /** Directory fsync runs where POSIX directories can be opened, and is skipped on ACL systems. */
    @Test
    void theFolderIsSyncedOnPosixAndNotOnAclFileSystems() throws IOException, StorageException {
        BackupDirectory posix = BackupDirectory.open(dir.resolve("b"));
        posix.createNew("x.pmbak", DATA);
        assertNotNull(fs.meta(posix.path()).channel, "the folder was opened to sync it");
        BackupDirectory backups = BackupDirectory.open(acl.wrap(temp.toRealPath()).resolve("acl"));
        backups.createNew("x.pmbak", DATA);
        assertArrayEquals(DATA, backups.read("x.pmbak"));
        assertTrue(backups.delete("x.pmbak"));
        assertNull(acl.meta(backups.path()).channel, "no channel was opened on the folder");
    }
}
