package pm.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** SR-040 / T-FS-01: run unchanged on the Linux, macOS, and Windows CI matrix. */
final class OwnerOnlyTest {
    @TempDir Path root;

    @Test
    void restrictsFilesAndDirectories() throws IOException, StorageException {
        Path file = Files.createFile(root.resolve("example"));
        OwnerOnly.apply(root);
        OwnerOnly.apply(file);
        assertTrue(OwnerOnly.isOwnerOnly(root));
        assertTrue(OwnerOnly.isOwnerOnly(file));
    }

    @Test
    void setsExactPosixModesAndDetectsSharedAccess() throws IOException, StorageException {
        assumeTrue(root.getFileSystem().supportedFileAttributeViews().contains("posix"));
        Path file = Files.createFile(root.resolve("example"));
        OwnerOnly.apply(root);
        OwnerOnly.apply(file);
        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(root));
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(file));
        Path changed = Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r-----"));
        assertFalse(OwnerOnly.isOwnerOnly(changed));
    }

    @Test
    void setsOneOwnerAclWithoutInheritance() throws IOException, StorageException {
        assumeTrue(root.getFileSystem().supportedFileAttributeViews().contains("acl"));
        Path file = Files.createFile(root.resolve("example"));
        OwnerOnly.apply(file);
        AclFileAttributeView view = Files.getFileAttributeView(file, AclFileAttributeView.class);
        List<AclEntry> entries = view.getAcl();
        assertEquals(1, entries.size());
        assertEquals(view.getOwner(), entries.getFirst().principal());
        assertEquals(AclEntryType.ALLOW, entries.getFirst().type());
        assertTrue(entries.getFirst().flags().isEmpty());
        assertTrue(OwnerOnly.isOwnerOnly(file));
    }

    @Test
    void missingPathIsReportedWithoutPathDetails() {
        StorageException error = assertThrows(StorageException.class,
                () -> OwnerOnly.apply(root.resolve("private-location")));
        assertEquals(StorageException.Code.PERMISSIONS, error.code());
        assertEquals("PERMISSIONS", error.getMessage());
    }
}
