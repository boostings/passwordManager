package pm.storage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Owner-only POSIX permissions or Windows ACLs for SR-040 and CERT FIO01-J. */
public final class OwnerOnly {
    private static final Set<PosixFilePermission> FILE_MODE =
            Set.copyOf(PosixFilePermissions.fromString("rw-------"));
    private static final Set<PosixFilePermission> DIRECTORY_MODE =
            Set.copyOf(PosixFilePermissions.fromString("rwx------"));

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

    // Restrictive attributes must be supplied before a newly created file becomes visible.
    static FileAttribute<?>[] creationAttributes(Path parent, boolean directory)
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
