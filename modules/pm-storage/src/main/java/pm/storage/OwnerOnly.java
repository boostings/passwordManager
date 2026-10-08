package pm.storage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Owner-only POSIX permissions or Windows ACLs (SR-040, CERT FIO01-J), and the secure-directory
 * test for directories the storage layer did not create (CERT FIO00-J).
 *
 * <p>Two levels are distinguished. Everything the store creates (vault, staging file, backups,
 * lock file, a missing parent directory) is <em>owner-only</em>: POSIX {@code rw-------} or
 * {@code rwx------}; on Windows a single ALLOW entry for the owner with no inheritance. A parent
 * directory that already existed is never modified. It must instead be <em>secure</em>:
 * <ul>
 * <li>POSIX: owned by the current user and without group or other write permission. Read and
 * search permission for others is tolerated, because the files inside are owner-only.</li>
 * <li>Windows: every ALLOW entry that applies to the directory and carries a write right
 * (add file, add subdirectory, delete, delete child, write attributes, write extended attributes,
 * change permissions, take ownership) must name the directory's owner, {@code NT AUTHORITY\SYSTEM}
 * (S-1-5-18) or {@code BUILTIN\Administrators} (S-1-5-32-544). DENY entries never count as
 * grants, and inherit-only entries do not apply to the directory itself. The two administrative
 * accounts are recognised by security identifier, not by their localised names. A directory
 * owned by one of them (created from an elevated process) may also be written by the account
 * named by {@code user.name}. Ownership by the current user is enforced on every file the store
 * creates, which must come out owned as described for {@code VaultFileStore}.</li>
 * </ul>
 */
public final class OwnerOnly {
    private static final Set<PosixFilePermission> FILE_MODE =
            Set.copyOf(PosixFilePermissions.fromString("rw-------"));
    private static final Set<PosixFilePermission> DIRECTORY_MODE =
            Set.copyOf(PosixFilePermissions.fromString("rwx------"));
    // Rights that let a principal add, replace, remove, or re-permission entries of a directory.
    private static final Set<AclEntryPermission> WRITE_RIGHTS = Set.copyOf(EnumSet.of(
            AclEntryPermission.WRITE_DATA, AclEntryPermission.APPEND_DATA,
            AclEntryPermission.DELETE, AclEntryPermission.DELETE_CHILD,
            AclEntryPermission.WRITE_ATTRIBUTES, AclEntryPermission.WRITE_NAMED_ATTRS,
            AclEntryPermission.WRITE_ACL, AclEntryPermission.WRITE_OWNER));
    // NIO offers no accessor for a security identifier. The JDK's Windows principals compare by
    // SID string and use that string's hash code, which makes this test independent of the
    // localised account names; a JDK that hashed differently would make it fail closed.
    private static final int SYSTEM_SID = "S-1-5-18".hashCode();
    private static final int ADMINISTRATORS_SID = "S-1-5-32-544".hashCode();

    private OwnerOnly() {
    }

    /**
     * Restricts an existing regular file or directory; never follows a symbolic link.
     * New files should instead receive restrictive attributes at creation time.
     *
     * @param path a file or directory the application is authorized to manage
     * @throws StorageException if permissions cannot be established or the path is a link
     */
    public static void apply(Path path) throws StorageException {
        Objects.requireNonNull(path, "PATH");
        try {
            BasicFileAttributes attributes = checkedAttributes(path);
            PosixFileAttributeView posix = Files.getFileAttributeView(
                    path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (posix != null) {
                posix.setPermissions(attributes.isDirectory() ? DIRECTORY_MODE : FILE_MODE);
            } else {
                AclFileAttributeView acl = aclView(path);
                acl.setAcl(ownerAcl(acl.getOwner()));
            }
            if (!isOwnerOnly(path)) {
                throw new StorageException(StorageException.Code.PERMISSIONS, null);
            }
        } catch (IOException | UnsupportedOperationException | SecurityException ex) {
            throw new StorageException(StorageException.Code.PERMISSIONS, ex);
        }
    }

    /**
     * Checks that a file or directory grants access only to its owner.
     *
     * @param path the existing path to inspect without following links
     * @return whether its permissions are restricted to the owner
     * @throws StorageException if inspection fails, is unsupported, or encounters a link
     */
    public static boolean isOwnerOnly(Path path) throws StorageException {
        Objects.requireNonNull(path, "PATH");
        try {
            BasicFileAttributes attributes = checkedAttributes(path);
            PosixFileAttributeView posix = Files.getFileAttributeView(
                    path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (posix != null) {
                Set<PosixFilePermission> permissions = posix.readAttributes().permissions();
                return (attributes.isDirectory() ? DIRECTORY_MODE : FILE_MODE)
                        .containsAll(permissions);
            }
            AclFileAttributeView acl = aclView(path);
            List<AclEntry> entries = acl.getAcl();
            UserPrincipal owner = acl.getOwner();
            return !entries.isEmpty() && entries.stream().allMatch(entry ->
                    entry.principal().equals(owner) && entry.type() == AclEntryType.ALLOW
                            && entry.flags().isEmpty());
        } catch (IOException | UnsupportedOperationException | SecurityException ex) {
            throw new StorageException(StorageException.Code.PERMISSIONS, ex);
        }
    }

    /**
     * Checks that an existing directory is secure in the FIO00-J sense described on this class,
     * without changing it.
     *
     * @param path the existing directory to inspect without following links
     * @return whether only its owner and the operating system's administrators may alter it
     * @throws StorageException if inspection fails, is unsupported, or encounters a link
     */
    static boolean isSecureDirectory(Path path) throws StorageException {
        Objects.requireNonNull(path, "PATH");
        try {
            if (!checkedAttributes(path).isDirectory()) {
                return false;
            }
            PosixFileAttributeView posix = Files.getFileAttributeView(
                    path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            if (posix != null) {
                PosixFileAttributes attributes = posix.readAttributes();
                Set<PosixFilePermission> permissions = attributes.permissions();
                if (permissions.contains(PosixFilePermission.GROUP_WRITE)
                        || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
                    return false;
                }
                // An account database that cannot name the user leaves the check to the store,
                // which refuses any file it creates that is not owned like the directory.
                UserPrincipal owner = attributes.owner();
                return currentUser(path).map(owner::equals).orElse(true);
            }
            AclFileAttributeView acl = aclView(path);
            Set<UserPrincipal> trusted = trustedWriters(path, acl.getOwner());
            List<AclEntry> entries = acl.getAcl();
            // An empty list is either "nobody" or a missing DACL ("everybody"): refuse both.
            return !entries.isEmpty() && entries.stream().noneMatch(entry ->
                    grantsWrite(entry) && !trusted.contains(entry.principal())
                            && !administrative(entry.principal()));
        } catch (IOException | UnsupportedOperationException | SecurityException ex) {
            throw new StorageException(StorageException.Code.PERMISSIONS, ex);
        }
    }

    /**
     * Checks that a file is owned the way files of its directory must be: by the directory's
     * owner or, on Windows, by the current user when an administrative account owns the
     * directory.
     *
     * @param file an existing file, inspected without following links
     * @param directory the directory holding it
     * @return whether the file's owner is acceptable
     * @throws StorageException if either owner cannot be read
     */
    static boolean ownedLike(Path file, Path directory) throws StorageException {
        try {
            UserPrincipal fileOwner = Files.getOwner(file, LinkOption.NOFOLLOW_LINKS);
            UserPrincipal directoryOwner = Files.getOwner(directory, LinkOption.NOFOLLOW_LINKS);
            if (fileOwner.equals(directoryOwner)) {
                return true;
            }
            return Files.getFileAttributeView(directory, PosixFileAttributeView.class,
                            LinkOption.NOFOLLOW_LINKS) == null
                    && administrative(directoryOwner)
                    && currentUser(directory).filter(fileOwner::equals).isPresent();
        } catch (IOException | UnsupportedOperationException | SecurityException ex) {
            throw new StorageException(StorageException.Code.PERMISSIONS, ex);
        }
    }

    /**
     * Whether a Windows principal is {@code NT AUTHORITY\SYSTEM} or
     * {@code BUILTIN\Administrators}, judged by security identifier rather than by name.
     *
     * @param principal a principal read from a Windows ACL or owner field
     * @return whether it is one of the two administrative accounts
     */
    static boolean administrative(UserPrincipal principal) {
        if (!(principal instanceof GroupPrincipal)) {
            return false;
        }
        int sid = principal.hashCode();
        return sid == SYSTEM_SID || sid == ADMINISTRATORS_SID;
    }

    /**
     * Attributes that make a new file or directory owner-only from the moment it exists: the
     * owner-only mode where the parent supports POSIX permissions, otherwise an ACL naming only the
     * parent's owner. Restrictive attributes must be supplied before a new entry becomes visible;
     * {@link #apply} then makes them exact for the entry's own owner.
     *
     * @throws StorageException if the parent's file system offers neither permission model
     */
    public static FileAttribute<?>[] creationAttributes(Path parent, boolean directory)
            throws IOException, StorageException {
        if (Files.getFileAttributeView(parent, PosixFileAttributeView.class) != null) {
            return new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(
                    directory ? DIRECTORY_MODE : FILE_MODE)};
        }
        List<AclEntry> entries = ownerAcl(aclView(parent).getOwner());
        FileAttribute<List<AclEntry>> attribute = new FileAttribute<>() {
            @Override public String name() { return "acl:acl"; }
            @Override public List<AclEntry> value() { return entries; }
        };
        return new FileAttribute<?>[] {attribute};
    }

    private static boolean grantsWrite(AclEntry entry) {
        return entry.type() == AclEntryType.ALLOW
                && !entry.flags().contains(AclEntryFlag.INHERIT_ONLY)
                && !Collections.disjoint(entry.permissions(), WRITE_RIGHTS);
    }

    private static Set<UserPrincipal> trustedWriters(Path directory, UserPrincipal owner) {
        if (administrative(owner)) {
            Optional<UserPrincipal> self = currentUser(directory);
            if (self.isPresent() && !self.get().equals(owner)) {
                return Set.of(owner, self.get());
            }
        }
        return Set.of(owner);
    }

    // The account named by user.name, or empty if the account database does not know it.
    private static Optional<UserPrincipal> currentUser(Path path) {
        String name = System.getProperty("user.name");
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(path.getFileSystem().getUserPrincipalLookupService()
                    .lookupPrincipalByName(name));
        } catch (IOException unknown) {
            return Optional.empty();
        }
    }

    private static List<AclEntry> ownerAcl(UserPrincipal owner) {
        return List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW)
                .setPrincipal(owner).setPermissions(EnumSet.allOf(AclEntryPermission.class))
                .build());
    }

    private static AclFileAttributeView aclView(Path path) throws StorageException {
        AclFileAttributeView view = Files.getFileAttributeView(
                path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new StorageException(StorageException.Code.PERMISSIONS, null);
        }
        return view;
    }

    private static BasicFileAttributes checkedAttributes(Path path)
            throws IOException, StorageException {
        BasicFileAttributes attributes = Files.readAttributes(
                path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (attributes.isSymbolicLink()) {
            throw new StorageException(StorageException.Code.SYMLINK_REFUSED, null);
        }
        if (!attributes.isRegularFile() && !attributes.isDirectory()) {
            throw new StorageException(StorageException.Code.PERMISSIONS, null);
        }
        return attributes;
    }
}
