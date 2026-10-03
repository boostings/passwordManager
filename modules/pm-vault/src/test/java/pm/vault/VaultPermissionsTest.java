package pm.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.Argon2Params;
import pm.crypto.SecretChars;
import pm.storage.OwnerOnly;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;

/**
 * SR-040 / T-FS-01 end to end: after {@code create} and two saves, the vault file, its backups
 * and the directory the store created are owner-only. Runs unchanged on the Linux, macOS and
 * Windows CI matrix: POSIX modes where the file system has a {@code posix} view, otherwise a
 * Windows ACL holding only ALLOW entries for the owner with no inheritance flags.
 */
final class VaultPermissionsTest {

    private static final String POSIX_VIEW = "posix";
    private static final String ACL_VIEW = "acl";
    private static final Set<PosixFilePermission> FILE_MODE = PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> DIRECTORY_MODE =
            PosixFilePermissions.fromString("rwx------");

    @TempDir
    Path root;

    @Test
    void vaultBackupsAndCreatedDirectoryAreOwnerOnly() throws VaultException, IOException, StorageException {
        // A missing parent, so the store itself creates the directory under test.
        Path directory = root.resolve("private");
        Path vaultPath = directory.resolve("vault.pmv");
        try (VaultFileStore store = VaultFileStore.open(vaultPath)) {
            VaultService service = new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR);
            try (SecretChars pw = Fixtures.chars(Fixtures.PHRASE);
                 CreatedVault created = service.create(pw)) {
                created.vault().save();
                created.vault().save();
            }
        }

        Path bak1 = directory.resolve("vault.pmv.bak.1");
        Path bak2 = directory.resolve("vault.pmv.bak.2");
        assertTrue(Files.isRegularFile(vaultPath, LinkOption.NOFOLLOW_LINKS));
        assertTrue(Files.isRegularFile(bak1, LinkOption.NOFOLLOW_LINKS));
        assertTrue(Files.isRegularFile(bak2, LinkOption.NOFOLLOW_LINKS));
        assertFalse(Files.exists(directory.resolve("vault.pmv.tmp"), LinkOption.NOFOLLOW_LINKS));

        for (Path file : List.of(vaultPath, bak1, bak2)) {
            assertOwnerOnly(file, FILE_MODE);
        }
        assertOwnerOnly(directory, DIRECTORY_MODE);
    }

    private static void assertOwnerOnly(Path path, Set<PosixFilePermission> posixMode)
            throws IOException, StorageException {
        assertTrue(OwnerOnly.isOwnerOnly(path), "OwnerOnly.isOwnerOnly");
        Set<String> views = path.getFileSystem().supportedFileAttributeViews();
        if (views.contains(POSIX_VIEW)) {
            assertEquals(posixMode, Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS));
        } else {
            assertTrue(views.contains(ACL_VIEW), "neither a posix nor an acl view");
            AclFileAttributeView view = Files.getFileAttributeView(
                    path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            UserPrincipal owner = view.getOwner();
            List<AclEntry> entries = view.getAcl();
            assertFalse(entries.isEmpty(), "an empty DACL is not owner-only");
            for (AclEntry entry : entries) {
                assertEquals(owner, entry.principal());
                assertEquals(AclEntryType.ALLOW, entry.type());
                assertTrue(entry.flags().isEmpty(), "no inheritance flags");
            }
        }
    }
}
