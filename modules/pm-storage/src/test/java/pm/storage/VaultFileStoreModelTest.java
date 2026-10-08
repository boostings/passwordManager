package pm.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import pm.storage.ModelFileSystem.Kind;
import pm.storage.StorageException.Code;

/**
 * {@link VaultFileStore}'s defensive paths on every host (M7.10): lock contention, a lock file
 * that cannot be validated, writes that make no progress, a folder that changes under an open
 * store, races while creating folders, and the ACL platforms' skipped directory sync. Each fault
 * is one {@link ModelFileSystem} flag; the bytes, links and locks are real.
 */
final class VaultFileStoreModelTest {
    private static final byte[] DATA = {1, 2, 3};
    private static final FileAttribute<?> OWNER_ONLY =
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));

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

    private byte[] onDisk(String name) throws IOException {
        return Files.readAllBytes(temp.toRealPath().resolve(name));
    }

    @Test
    void limitsOutsideOneToTheMaximumAreRefused() {
        Path vault = dir.resolve("v");
        VaultFileStore.CrashHook none = step -> { };
        assertEquals("LIMIT", assertThrows(IllegalArgumentException.class,
                () -> VaultFileStore.open(vault, 0, none)).getMessage());
        assertEquals("LIMIT", assertThrows(IllegalArgumentException.class,
                () -> VaultFileStore.open(vault, VaultFileStore.MAX_FILE_BYTES + 1, none)).getMessage());
    }

    @Test
    void theRootAndNamesTheFilesystemMayAlterAreRefused() {
        assertEquals(Code.IO, code(() -> VaultFileStore.open(dir.getRoot())));
        assertEquals(Code.IO, code(() -> VaultFileStore.open(dir.resolve("v "))));
        assertEquals(Code.IO, code(() -> VaultFileStore.open(dir.resolve("v."))));
        assertFalse(VaultFileStore.usableName(""));
        assertTrue(VaultFileStore.usableName("v"));
    }

    @Test
    void aLockHeldByAnotherProcessIsReportedAndItsFileKept() throws IOException, StorageException {
        fs.meta(dir.resolve("v.lock")).lockHeld = true;
        assertEquals(Code.LOCKED_BY_OTHER, code(() -> VaultFileStore.open(dir.resolve("v"))));
        assertTrue(Files.exists(temp.toRealPath().resolve("v.lock")), "the holder keeps its lock file");
    }

    @Test
    void aLockHeldElsewhereInThisProcessIsReportedAndItsFileKept() throws IOException, StorageException {
        Files.createFile(dir.resolve("v.lock"), OWNER_ONLY);
        try (FileChannel holder = FileChannel.open(temp.toRealPath().resolve("v.lock"), StandardOpenOption.WRITE);
             FileLock held = holder.lock()) {
            assertTrue(held.isValid());
            assertEquals(Code.LOCKED_BY_OTHER, code(() -> VaultFileStore.open(dir.resolve("v"))));
        }
        assertTrue(Files.exists(temp.toRealPath().resolve("v.lock")), "a lock file this call did not create stays");
        VaultFileStore.open(dir.resolve("v")).close();
    }

    @Test
    void aLockFileThisCallCreatedButCannotValidateIsRemoved() throws IOException, StorageException {
        fs.meta(dir.resolve("v.lock")).reportOther = true;
        assertEquals(Code.PERMISSIONS, code(() -> VaultFileStore.open(dir.resolve("v"))));
        assertFalse(Files.exists(temp.toRealPath().resolve("v.lock")), "an unusable lock file would block every open");
    }

    @Test
    void aStreamThatReadsNothingIsAnError() throws IOException, StorageException {
        try (InputStream stalled = new InputStream() {
            @Override public int read() {
                return 0;
            }

            @Override public int read(byte[] buffer, int offset, int length) {
                return 0;
            }
        }) {
            assertEquals(Code.IO, code(() -> VaultFileStore.readBounded(stalled, 10)));
        }
    }

    @Test
    void aWriteThatMakesNoProgressFailsAndLeavesNoStagingFile() throws IOException, StorageException {
        try (VaultFileStore store = VaultFileStore.open(dir.resolve("v"))) {
            fs.meta(dir.resolve("v.tmp")).zeroWrites = true;
            assertEquals(Code.IO, code(() -> store.writeAtomically(DATA)));
            assertFalse(store.exists());
            assertFalse(Files.exists(temp.toRealPath().resolve("v.tmp")));
        }
    }

    /** A backup is skipped only when .bak.1 holds the same bytes; a size that lies is no match. */
    @Test
    void aBackupIsComparedByLengthThenByEveryByte() throws IOException, StorageException {
        try (VaultFileStore store = VaultFileStore.open(dir.resolve("v"))) {
            store.writeAtomically(new byte[] {1, 1});
            store.backup();
            store.writeAtomically(new byte[] {2, 2, 2});
            store.backup();
            assertArrayEquals(new byte[] {1, 1}, onDisk("v.bak.2"), "another length rotates");
            store.writeAtomically(new byte[] {3, 3, 3});
            store.backup();
            assertArrayEquals(new byte[] {2, 2, 2}, onDisk("v.bak.2"), "the same length, other bytes, rotates");
            store.writeAtomically(new byte[] {4, 4, 4, 4});
            fs.meta(dir.resolve("v.bak.1")).reportedSize = 4L;
            store.backup();
            assertArrayEquals(new byte[] {4, 4, 4, 4}, onDisk("v.bak.1"));
            assertArrayEquals(new byte[] {3, 3, 3}, onDisk("v.bak.2"), "a reported size the bytes do not match rotates");
        }
    }

    @Test
    void aStoreWhoseLockOrLockChannelIsGoneRefusesWork() throws IOException, StorageException {
        Path lock = dir.resolve("v.lock");
        try (VaultFileStore store = VaultFileStore.open(dir.resolve("v"))) {
            fs.meta(lock).openedChannel().heldLock().release();
            assertEquals("CLOSED", assertThrows(IllegalStateException.class, store::readAll).getMessage());
        }
        try (VaultFileStore store = VaultFileStore.open(dir.resolve("v"))) {
            fs.meta(lock).openedChannel().close();
            assertEquals("CLOSED", assertThrows(IllegalStateException.class,
                    () -> store.writeAtomically(DATA)).getMessage());
        }
    }

    @Test
    void aFolderThatBecameALinkMovedOrOpenedUpIsRefused() throws IOException, StorageException {
        try (VaultFileStore store = VaultFileStore.open(dir.resolve("v"))) {
            store.writeAtomically(DATA);
            ModelFileSystem.Meta folder = fs.meta(dir);
            folder.reportLink = true;
            assertEquals(Code.SYMLINK_REFUSED, code(store::readAll));
            folder.reportLink = false;
            folder.realPath = dir.resolve("elsewhere");
            assertEquals(Code.SYMLINK_REFUSED, code(store::readAll));
            folder.realPath = null;
            Files.setPosixFilePermissions(dir, ModelFileSystem.mode("rwxrwxrwx"));
            assertEquals(Code.PERMISSIONS, code(store::readAll));
            Files.setPosixFilePermissions(dir, ModelFileSystem.mode("rwx------"));
            assertArrayEquals(DATA, store.readAll());
        }
    }

    @Test
    void anAbsentRootOrAParentlessPathIsNotFound() {
        Path requested = dir.resolve("a").resolve("b");
        for (Path above = dir; above != null; above = above.getParent()) {
            fs.meta(above).absent = true;
        }
        assertEquals(Code.NOT_FOUND, code(() -> VaultFileStore.prepareDirectory(requested)));
        Path parentless = Path.of("pm-missing-" + UUID.randomUUID());
        assertEquals(Code.NOT_FOUND, code(() -> VaultFileStore.prepareDirectory(parentless)));
    }

    @Test
    void aFolderAnotherProcessCreatedFirstIsUsedUnlessItIsALink() throws IOException, StorageException {
        Path raced = dir.resolve("raced");
        fs.meta(raced).raceCreate = true;
        try (VaultFileStore store = VaultFileStore.open(raced.resolve("v"))) {
            store.writeAtomically(DATA);
        }
        assertArrayEquals(DATA, onDisk("raced/v"));
        Path elsewhere = Files.createDirectory(dir.resolve("elsewhere"));
        Path linked = dir.resolve("linked");
        fs.meta(linked).raceLink = elsewhere;
        assertEquals(Code.SYMLINK_REFUSED, code(() -> VaultFileStore.open(linked.resolve("v"))));
    }

    @Test
    void aFileWhereTheFolderShouldBeIsRefused() throws IOException, StorageException {
        Path plain = Files.createFile(dir.resolve("plain"));
        assertEquals(Code.PERMISSIONS, code(() -> VaultFileStore.open(plain.resolve("v"))));
    }

    /** A lock stored under another spelling that drops its suffix never renames the vault. */
    @Test
    void aLockWhoseStoredNameLacksTheSuffixLeavesTheRequestedName() throws IOException, StorageException {
        Path lock = Files.createFile(dir.resolve("v.lock"), OWNER_ONLY);
        fs.meta(lock).realPath = dir.resolve("V.LOCKED");
        try (VaultFileStore store = VaultFileStore.open(dir.resolve("v"))) {
            store.writeAtomically(DATA);
        }
        assertArrayEquals(DATA, onDisk("v"));
    }

    @Test
    void anOwnerOnlyFileOwnedByAnotherAccountIsRefused() throws IOException, StorageException {
        try (VaultFileStore store = VaultFileStore.open(dir.resolve("v"))) {
            store.writeAtomically(DATA);
            fs.meta(dir.resolve("v")).owner = ModelFileSystem.OTHER;
            assertEquals(Code.PERMISSIONS, code(store::readAll));
        }
    }

    /** Directory fsync runs where POSIX directories can be opened, and is skipped on ACL systems. */
    @Test
    void theFolderIsSyncedOnPosixAndNotOnAclFileSystems() throws IOException, StorageException {
        try (VaultFileStore store = VaultFileStore.open(dir.resolve("v"))) {
            store.writeAtomically(DATA);
        }
        assertNotNull(fs.meta(dir).channel, "the folder was opened to sync it");
        Path folder = acl.wrap(Files.createDirectory(temp.resolve("acl")).toRealPath());
        try (VaultFileStore store = VaultFileStore.open(folder.resolve("v"))) {
            store.writeAtomically(DATA);
            assertArrayEquals(DATA, store.readAll());
        }
        assertNull(acl.meta(folder).channel, "no channel was opened on the folder");
    }

    @Test
    void errorsAreTranslatedToStableCodes() {
        assertEquals(Code.NOT_FOUND, VaultFileStore.translated(new NoSuchFileException("x")).code());
        assertEquals(Code.PERMISSIONS, VaultFileStore.translated(new AccessDeniedException("x")).code());
        assertEquals(Code.PERMISSIONS, VaultFileStore.translated(new SecurityException("x")).code());
        assertEquals(Code.LOCKED_BY_OTHER, VaultFileStore.translated(new OverlappingFileLockException()).code());
        assertEquals(Code.IO, VaultFileStore.translated(new IOException("x")).code());
    }
}
