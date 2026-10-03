package pm.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Backup directories: owner-only, create-new, atomic, link-refusing (ADR 0015, SR-040/041). */
final class BackupDirectoryTest {
    @TempDir Path root;

    @Test
    void createListReadDeleteAreOwnerOnlyAndCreateNew() throws IOException, StorageException {
        BackupDirectory dir = BackupDirectory.open(root.resolve("a/b/backups"));
        assertTrue(OwnerOnly.isOwnerOnly(dir.path()));
        dir.createNew("pm-backup-2.pmbackup", new byte[] {2});
        dir.createNew("pm-backup-1.pmbackup", new byte[] {1});
        Files.write(dir.path().resolve("other.txt"), new byte[] {0});
        Files.createDirectory(dir.path().resolve("pm-backup-dir.pmbackup"));

        assertEquals(List.of("pm-backup-1.pmbackup", "pm-backup-2.pmbackup"), dir.list("pm-backup-", ".pmbackup"));
        assertEquals(new BackupDirectory.Listing(List.of("pm-backup-1.pmbackup", "pm-backup-2.pmbackup"),
                List.of("pm-backup-dir.pmbackup")), dir.scan("pm-backup-", ".pmbackup"));
        assertTrue(OwnerOnly.isOwnerOnly(dir.path().resolve("pm-backup-1.pmbackup")));
        assertArrayEquals(new byte[] {2}, dir.read("pm-backup-2.pmbackup"));
        assertArrayEquals(new byte[] {2}, BackupDirectory.readFile(dir.path().resolve("pm-backup-2.pmbackup")));

        assertEquals(StorageException.Code.IO, assertThrows(StorageException.class,
                () -> dir.createNew("pm-backup-1.pmbackup", new byte[] {9})).code());
        assertArrayEquals(new byte[] {1}, dir.read("pm-backup-1.pmbackup"));

        assertTrue(dir.delete("pm-backup-1.pmbackup"));
        assertFalse(dir.delete("pm-backup-1.pmbackup"));
        assertEquals(StorageException.Code.NOT_FOUND,
                assertThrows(StorageException.class, () -> dir.read("pm-backup-1.pmbackup")).code());
        assertEquals(List.of("pm-backup-2.pmbackup"), dir.list("pm-backup-", ".pmbackup"));
    }

    @Test
    void namesThatCouldLeaveTheDirectoryAreRefused() throws StorageException {
        BackupDirectory dir = BackupDirectory.open(root);
        for (String bad : new String[] {"", ".hidden", "../x", "a/b", "x.tmp", "a b", "a".repeat(129)}) {
            assertThrows(IllegalArgumentException.class, () -> dir.createNew(bad, new byte[0]), bad);
        }
        assertThrows(NullPointerException.class, () -> dir.read(null));
        assertThrows(NullPointerException.class, () -> dir.createNew("x", null));
    }

    @ParameterizedTest
    @EnumSource(value = VaultFileStore.Step.class, names = {"TMP_CREATED", "TMP_WRITTEN", "TMP_SYNCED"})
    void crashBeforeTheRenameLeavesNothing(VaultFileStore.Step at) throws IOException, StorageException {
        BackupDirectory dir = BackupDirectory.open(root.resolve("d"), step -> {
            if (step == at) {
                throw new IOException("injected");
            }
        });
        assertThrows(StorageException.class, () -> dir.createNew("b.pmbackup", new byte[] {1, 2, 3}));
        try (Stream<Path> entries = Files.list(dir.path())) {
            assertEquals(0, entries.count());
        }
    }

    @ParameterizedTest
    @EnumSource(value = VaultFileStore.Step.class, names = {"RENAMED", "DIR_SYNCED"})
    void crashAfterTheRenameLeavesTheCompleteFile(VaultFileStore.Step at) throws IOException, StorageException {
        BackupDirectory dir = BackupDirectory.open(root.resolve("d"), step -> {
            if (step == at) {
                throw new IOException("injected");
            }
        });
        assertThrows(StorageException.class, () -> dir.createNew("b.pmbackup", new byte[] {1, 2, 3}));
        assertArrayEquals(new byte[] {1, 2, 3}, Files.readAllBytes(dir.path().resolve("b.pmbackup")));
        assertFalse(Files.exists(dir.path().resolve("b.pmbackup.tmp")));
    }

    @Test
    void staleStagingFileIsReplaced() throws IOException, StorageException {
        BackupDirectory dir = BackupDirectory.open(root);
        Files.write(root.resolve("b.pmbackup.tmp"), new byte[] {9, 9});
        dir.createNew("b.pmbackup", new byte[] {1});
        assertArrayEquals(new byte[] {1}, dir.read("b.pmbackup"));
        assertFalse(Files.exists(root.resolve("b.pmbackup.tmp")));
    }

    @Test
    void linksAreRefused() throws IOException, StorageException {
        BackupDirectory dir = BackupDirectory.open(root.resolve("d"));
        Path real = root.resolve("real.bin");
        Files.write(real, new byte[] {1});
        Path link = dir.path().resolve("l.pmbackup");
        Files.createSymbolicLink(link, real);
        assertEquals(StorageException.Code.SYMLINK_REFUSED,
                assertThrows(StorageException.class, () -> dir.read("l.pmbackup")).code());
        assertEquals(StorageException.Code.SYMLINK_REFUSED,
                assertThrows(StorageException.class, () -> BackupDirectory.readFile(link)).code());
        assertEquals(StorageException.Code.SYMLINK_REFUSED,
                assertThrows(StorageException.class, () -> dir.delete("l.pmbackup")).code());
        assertEquals(new BackupDirectory.Listing(List.of(), List.of("l.pmbackup")), dir.scan("", ".pmbackup"));
        assertTrue(Files.exists(real));

        Path linkedDir = root.resolve("linked");
        Files.createSymbolicLink(linkedDir, dir.path());
        BackupDirectory viaLink = BackupDirectory.open(linkedDir);
        assertEquals(dir.path(), viaLink.path());
        assertEquals(StorageException.Code.NOT_FOUND, assertThrows(StorageException.class,
                () -> BackupDirectory.readFile(root.resolve("absent"))).code());
    }

    @Test
    void fileThatIsNotOwnerOnlyIsListedAsRefusedAndNeverDeleted() throws IOException, StorageException {
        assumeTrue(root.getFileSystem().supportedFileAttributeViews().contains("posix"));
        BackupDirectory dir = BackupDirectory.open(root.resolve("d"));
        dir.createNew("b.pmbackup", new byte[] {1});
        Path loose = dir.path().resolve("b.pmbackup");
        Files.setPosixFilePermissions(loose, PosixFilePermissions.fromString("rw-rw----"));
        assertEquals(new BackupDirectory.Listing(List.of(), List.of("b.pmbackup")), dir.scan("b", ".pmbackup"));
        assertEquals(StorageException.Code.PERMISSIONS,
                assertThrows(StorageException.class, () -> dir.delete("b.pmbackup")).code());
        assertTrue(Files.exists(loose));
    }

    @Test
    void insecureExistingDirectoryIsRefusedUnchanged() throws IOException {
        assumeTrue(root.getFileSystem().supportedFileAttributeViews().contains("posix"));
        Path shared = root.resolve("shared");
        Files.createDirectory(shared);
        Files.setPosixFilePermissions(shared, PosixFilePermissions.fromString("rwxrwx---"));
        assertEquals(StorageException.Code.PERMISSIONS,
                assertThrows(StorageException.class, () -> BackupDirectory.open(shared)).code());
        assertEquals("rwxrwx---", PosixFilePermissions.toString(Files.getPosixFilePermissions(shared)));
    }

    @Test
    void directoryMadeInsecureAfterOpenIsRefused() throws IOException, StorageException {
        assumeTrue(root.getFileSystem().supportedFileAttributeViews().contains("posix"));
        BackupDirectory dir = BackupDirectory.open(root.resolve("d"));
        Files.setPosixFilePermissions(dir.path(), PosixFilePermissions.fromString("rwxrwx---"));
        assertEquals(StorageException.Code.PERMISSIONS,
                assertThrows(StorageException.class, () -> dir.createNew("x", new byte[0])).code());
        assertTrue(BackupDirectory.maxBytes() > VaultFileStore.MAX_FILE_BYTES);
    }
}
