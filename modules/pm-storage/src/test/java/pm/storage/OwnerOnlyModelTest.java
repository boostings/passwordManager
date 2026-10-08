package pm.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import pm.storage.ModelFileSystem.Kind;

/**
 * SR-040 / T-FS-01 on every host: the Windows ACL rules and the POSIX mode rules of
 * {@link OwnerOnly}, run against {@link ModelFileSystem} so neither set waits for a CI machine of
 * its own platform (M7.10). The real-platform tests stay in {@code OwnerOnlyTest}.
 */
final class OwnerOnlyModelTest {
    private static final Set<AclEntryPermission> WRITE = EnumSet.of(AclEntryPermission.WRITE_DATA);
    private static final Set<AclEntryPermission> READ = EnumSet.of(AclEntryPermission.READ_DATA);

    // JUnit makes a new instance, so a new model of each kind, for every test.
    private final ModelFileSystem aclModel = new ModelFileSystem(Kind.ACL, FileSystems.getDefault());
    private final ModelFileSystem posixModel = new ModelFileSystem(Kind.POSIX, FileSystems.getDefault());
    private final ModelFileSystem basicModel = new ModelFileSystem(Kind.BASIC, FileSystems.getDefault());

    @TempDir Path temp;

    private Path base(ModelFileSystem fs) throws IOException {
        return fs.wrap(temp.toRealPath());
    }

    private static void acl(ModelFileSystem fs, Path path, UserPrincipal owner, AclEntry... entries) {
        ModelFileSystem.Meta meta = fs.meta(path);
        meta.owner = owner;
        meta.acl = List.of(entries);
    }

    private static AclEntry allow(UserPrincipal who, Set<AclEntryPermission> rights, AclEntryFlag... flags) {
        return ModelFileSystem.entry(who, AclEntryType.ALLOW, rights, flags);
    }

    private static StorageException.Code code(Executable call) {
        return assertThrows(StorageException.class, call).code();
    }

    @Test
    void aclApplyReplacesInheritedEntriesWithOneOwnerEntry() throws IOException, StorageException {
        Path file = Files.createFile(base(aclModel).resolve("inherited"));
        assertFalse(OwnerOnly.isOwnerOnly(file), "a Users read entry is not owner-only");
        OwnerOnly.apply(file);
        AclFileAttributeView view = Files.getFileAttributeView(file, AclFileAttributeView.class);
        assertEquals(ModelFileSystem.ownerAcl(ModelFileSystem.ME), view.getAcl());
        assertTrue(OwnerOnly.isOwnerOnly(file));
    }

    @Test
    void aclOwnerOnlyNeedsOneUnflaggedAllowForTheOwner() throws IOException, StorageException {
        Path file = Files.createFile(base(aclModel).resolve("f"));
        UserPrincipal me = ModelFileSystem.ME;
        acl(aclModel, file, me);
        assertFalse(OwnerOnly.isOwnerOnly(file), "an empty ACL is no DACL or no access: refused");
        acl(aclModel, file, me, ModelFileSystem.entry(me, AclEntryType.DENY, WRITE));
        assertFalse(OwnerOnly.isOwnerOnly(file));
        acl(aclModel, file, me, allow(me, READ, AclEntryFlag.FILE_INHERIT));
        assertFalse(OwnerOnly.isOwnerOnly(file));
        acl(aclModel, file, me, allow(me, READ), allow(ModelFileSystem.OTHER, READ));
        assertFalse(OwnerOnly.isOwnerOnly(file));
        acl(aclModel, file, me, allow(me, READ));
        assertTrue(OwnerOnly.isOwnerOnly(file));
    }

    @Test
    void applyThatDoesNotTakeEffectIsRefused() throws IOException {
        applyIsRefusedWhenIgnored(aclModel);
        applyIsRefusedWhenIgnored(posixModel);
    }

    private void applyIsRefusedWhenIgnored(ModelFileSystem fs) throws IOException {
        Path file = Files.createFile(base(fs).resolve("stuck-" + fs));
        fs.meta(file).ignoreChanges = true;
        assertEquals(StorageException.Code.PERMISSIONS, code(() -> OwnerOnly.apply(file)), fs.toString());
    }

    @Test
    void posixApplySetsExactModes() throws IOException, StorageException {
        Path dir = Files.createDirectory(base(posixModel).resolve("d"));
        Path file = Files.createFile(dir.resolve("f"));
        assertFalse(OwnerOnly.isOwnerOnly(file), "rw-r--r-- by default");
        OwnerOnly.apply(dir);
        OwnerOnly.apply(file);
        assertEquals(ModelFileSystem.mode("rwx------"), Files.getPosixFilePermissions(dir));
        assertEquals(ModelFileSystem.mode("rw-------"), Files.getPosixFilePermissions(file));
        assertTrue(OwnerOnly.isOwnerOnly(dir));
    }

    @Test
    void aFileIsNeverASecureDirectory() throws IOException, StorageException {
        assertFalse(OwnerOnly.isSecureDirectory(Files.createFile(base(aclModel).resolve("acl"))));
        assertFalse(OwnerOnly.isSecureDirectory(Files.createFile(base(posixModel).resolve("posix"))));
    }

    @Test
    void aclSecureDirectoryCountsOnlyApplicableAllowWritesByOthers() throws IOException, StorageException {
        Path dir = Files.createDirectory(base(aclModel).resolve("d"));
        UserPrincipal me = ModelFileSystem.ME;
        UserPrincipal other = ModelFileSystem.OTHER;
        acl(aclModel, dir, me);
        assertFalse(OwnerOnly.isSecureDirectory(dir), "empty ACL");
        acl(aclModel, dir, me, allow(me, EnumSet.allOf(AclEntryPermission.class)));
        assertTrue(OwnerOnly.isSecureDirectory(dir));
        for (AclEntryPermission right : List.of(AclEntryPermission.WRITE_DATA, AclEntryPermission.APPEND_DATA,
                AclEntryPermission.DELETE, AclEntryPermission.DELETE_CHILD, AclEntryPermission.WRITE_ATTRIBUTES,
                AclEntryPermission.WRITE_NAMED_ATTRS, AclEntryPermission.WRITE_ACL, AclEntryPermission.WRITE_OWNER)) {
            acl(aclModel, dir, me, allow(me, READ), allow(other, EnumSet.of(right)));
            assertFalse(OwnerOnly.isSecureDirectory(dir), right.name());
        }
        acl(aclModel, dir, me, allow(me, READ), allow(other, READ));
        assertTrue(OwnerOnly.isSecureDirectory(dir), "read and search for others is tolerated");
        acl(aclModel, dir, me, allow(me, READ), ModelFileSystem.entry(other, AclEntryType.DENY, WRITE));
        assertTrue(OwnerOnly.isSecureDirectory(dir), "a DENY entry is never a grant");
        acl(aclModel, dir, me, allow(me, READ), allow(other, WRITE, AclEntryFlag.INHERIT_ONLY));
        assertTrue(OwnerOnly.isSecureDirectory(dir), "inherit-only entries do not apply to the directory");
        acl(aclModel, dir, me, allow(me, READ), allow(other, WRITE, AclEntryFlag.FILE_INHERIT));
        assertFalse(OwnerOnly.isSecureDirectory(dir), "an inheritable entry also applies to the directory");
        acl(aclModel, dir, me, allow(ModelFileSystem.SYSTEM, WRITE), allow(ModelFileSystem.ADMINISTRATORS, WRITE));
        assertTrue(OwnerOnly.isSecureDirectory(dir), "SYSTEM and Administrators are trusted by SID");
    }

    @Test
    void anAdministratorOwnedDirectoryMayAlsoBeWrittenByTheCurrentUser() throws IOException, StorageException {
        Path dir = Files.createDirectory(base(aclModel).resolve("elevated"));
        acl(aclModel, dir, ModelFileSystem.ADMINISTRATORS, allow(ModelFileSystem.ME, WRITE));
        assertTrue(OwnerOnly.isSecureDirectory(dir));
        acl(aclModel, dir, ModelFileSystem.ADMINISTRATORS, allow(ModelFileSystem.OTHER, WRITE));
        assertFalse(OwnerOnly.isSecureDirectory(dir), "only the account named by user.name");
        aclModel.accounts(Map.of());
        acl(aclModel, dir, ModelFileSystem.ADMINISTRATORS, allow(ModelFileSystem.ME, WRITE));
        assertFalse(OwnerOnly.isSecureDirectory(dir), "an unknown current user trusts nobody extra");
        aclModel.accounts(Map.of(System.getProperty("user.name"), ModelFileSystem.ADMINISTRATORS));
        acl(aclModel, dir, ModelFileSystem.ADMINISTRATORS, allow(ModelFileSystem.ADMINISTRATORS, WRITE),
                allow(ModelFileSystem.ME, WRITE));
        assertFalse(OwnerOnly.isSecureDirectory(dir), "running as the owner adds no one");
        acl(aclModel, dir, ModelFileSystem.OTHER, allow(ModelFileSystem.ME, WRITE));
        assertFalse(OwnerOnly.isSecureDirectory(dir), "a plain owner trusts only itself");
    }

    @Test
    void administrativeMeansSystemOrAdministratorsGroupBySid() {
        assertTrue(OwnerOnly.administrative(ModelFileSystem.SYSTEM));
        assertTrue(OwnerOnly.administrative(ModelFileSystem.ADMINISTRATORS));
        assertFalse(OwnerOnly.administrative(ModelFileSystem.USERS));
        assertFalse(OwnerOnly.administrative(new ModelFileSystem.Principal("S-1-5-18", "not a group")),
                "a user principal is never administrative, whatever its hash");
    }

    @Test
    void posixSecureDirectoryRefusesSharedWriteAndAnotherOwner() throws IOException, StorageException {
        Path dir = Files.createDirectory(base(posixModel).resolve("d"));
        ModelFileSystem.Meta meta = posixModel.meta(dir);
        meta.permissions = ModelFileSystem.mode("rwxr-xr-x");
        assertTrue(OwnerOnly.isSecureDirectory(dir));
        meta.permissions = ModelFileSystem.mode("rwxrwxr-x");
        assertFalse(OwnerOnly.isSecureDirectory(dir));
        meta.permissions = ModelFileSystem.mode("rwxr-xrwx");
        assertFalse(OwnerOnly.isSecureDirectory(dir));
        meta.permissions = ModelFileSystem.mode("rwx------");
        meta.owner = ModelFileSystem.OTHER;
        assertFalse(OwnerOnly.isSecureDirectory(dir));
        posixModel.accounts(Map.of());
        assertTrue(OwnerOnly.isSecureDirectory(dir),
                "an account database that cannot name the user leaves ownership to the store");
    }

    @Test
    void aMissingOrBlankUserNameLeavesOwnershipToTheStore() throws IOException, StorageException {
        Path dir = Files.createDirectory(base(posixModel).resolve("d"));
        posixModel.meta(dir).owner = ModelFileSystem.OTHER;
        String saved = System.getProperty("user.name");
        try {
            System.setProperty("user.name", " ");
            assertTrue(OwnerOnly.isSecureDirectory(dir));
            System.clearProperty("user.name");
            assertTrue(OwnerOnly.isSecureDirectory(dir));
        } finally {
            System.setProperty("user.name", saved);
        }
    }

    @Test
    void filesMustBeOwnedLikeTheirDirectory() throws IOException, StorageException {
        Path dir = Files.createDirectory(base(aclModel).resolve("d"));
        Path file = Files.createFile(dir.resolve("f"));
        assertTrue(OwnerOnly.ownedLike(file, dir));
        aclModel.meta(dir).owner = ModelFileSystem.ADMINISTRATORS;
        assertTrue(OwnerOnly.ownedLike(file, dir), "the current user under an elevated directory");
        aclModel.meta(file).owner = ModelFileSystem.OTHER;
        assertFalse(OwnerOnly.ownedLike(file, dir), "another user under an elevated directory");
        aclModel.meta(dir).owner = ModelFileSystem.OTHER;
        aclModel.meta(file).owner = ModelFileSystem.ME;
        assertFalse(OwnerOnly.ownedLike(file, dir), "a directory of another plain user");

        Path posixDir = Files.createDirectory(base(posixModel).resolve("p"));
        Path posixFile = Files.createFile(posixDir.resolve("f"));
        posixModel.meta(posixDir).owner = ModelFileSystem.ADMINISTRATORS;
        assertFalse(OwnerOnly.ownedLike(posixFile, posixDir), "POSIX has no elevated-owner exception");
        assertEquals(StorageException.Code.PERMISSIONS,
                code(() -> OwnerOnly.ownedLike(posixDir.resolve("missing"), posixDir)));
    }

    @Test
    void creationAttributesNameTheParentsOwnerOrTheOwnerOnlyMode() throws IOException, StorageException {
        Path dir = base(aclModel);
        aclModel.meta(dir).owner = ModelFileSystem.ADMINISTRATORS;
        FileAttribute<?>[] attributes = OwnerOnly.creationAttributes(dir, false);
        assertEquals("acl:acl", attributes[0].name());
        assertEquals(ModelFileSystem.ownerAcl(ModelFileSystem.ADMINISTRATORS), attributes[0].value());
        Path file = Files.createFile(dir.resolve("made"), attributes);
        assertFalse(OwnerOnly.isOwnerOnly(file), "the creator owns it, the entry names Administrators");
        VaultFileStore.ensurePrivate(file);
        assertTrue(OwnerOnly.isOwnerOnly(file));

        Set<PosixFilePermission> directoryMode = ModelFileSystem.mode("rwx------");
        assertEquals(directoryMode, OwnerOnly.creationAttributes(base(posixModel), true)[0].value());
        assertEquals(StorageException.Code.PERMISSIONS,
                code(() -> OwnerOnly.creationAttributes(base(basicModel), false)));
    }

    @Test
    void aFileSystemWithoutPermissionsIsRefused() throws IOException, StorageException {
        Path file = Files.createFile(base(basicModel).resolve("f"));
        assertEquals(StorageException.Code.PERMISSIONS, code(() -> OwnerOnly.apply(file)));
        assertEquals(StorageException.Code.PERMISSIONS, code(() -> OwnerOnly.isOwnerOnly(file)));
        assertEquals(StorageException.Code.PERMISSIONS, code(() -> OwnerOnly.isSecureDirectory(base(basicModel))));
    }

    @Test
    void linksAndSpecialFilesAreRefused() throws IOException {
        linksAndSpecialFilesAreRefused(aclModel);
        linksAndSpecialFilesAreRefused(posixModel);
    }

    private void linksAndSpecialFilesAreRefused(ModelFileSystem fs) throws IOException {
        Path file = Files.createFile(base(fs).resolve("f-" + fs));
        fs.meta(file).reportLink = true;
        assertEquals(StorageException.Code.SYMLINK_REFUSED, code(() -> OwnerOnly.apply(file)));
        assertEquals(StorageException.Code.SYMLINK_REFUSED, code(() -> OwnerOnly.isOwnerOnly(file)));
        assertEquals(StorageException.Code.SYMLINK_REFUSED, code(() -> OwnerOnly.isSecureDirectory(file)));
        fs.meta(file).reportLink = false;
        fs.meta(file).reportOther = true;
        assertEquals(StorageException.Code.PERMISSIONS, code(() -> OwnerOnly.apply(file)));
        assertEquals(StorageException.Code.PERMISSIONS, code(() -> OwnerOnly.isOwnerOnly(file)));
    }
}
