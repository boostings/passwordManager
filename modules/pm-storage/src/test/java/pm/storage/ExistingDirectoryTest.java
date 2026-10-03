package pm.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * FIO00-J / SR-040: a parent directory that already exists is accepted when only its owner and
 * the system's administrators can alter it, is refused otherwise, and is never modified.
 */
final class ExistingDirectoryTest {
    @TempDir Path root;

    @Test
    void posixDirectoryThatOthersCanOnlyReadIsAcceptedUnchanged()
            throws IOException, StorageException {
        assumeTrue(posix());
        Path directory = Files.createDirectory(root.resolve("existing"));
        Set<PosixFilePermission> readable = mode("rwxr-xr-x");
        Path changed = Files.setPosixFilePermissions(directory, readable);
        assertFalse(OwnerOnly.isOwnerOnly(changed));
        saveTwice(changed.resolve("vault.pmv"));
        assertEquals(readable, Files.getPosixFilePermissions(directory));
    }

    @Test
    void windowsDirectoryWithInheritedSystemEntriesIsAcceptedUnchanged()
            throws IOException, StorageException {
        assumeTrue(windowsAcl());
        Path directory = Files.createDirectory(root.resolve("existing"));
        // An ordinary new folder inherits entries for SYSTEM and Administrators besides the user.
        assumeFalse(OwnerOnly.isOwnerOnly(directory), "directory inherited nothing to tolerate");
        AclFileAttributeView view = aclView(directory);
        List<AclEntry> before = view.getAcl();
        saveTwice(directory.resolve("vault.pmv"));
        assertEquals(before, view.getAcl());
    }

    @Test
    void windowsDirectoryWritableByAnotherPrincipalIsRefusedUnchanged() throws IOException {
        assumeTrue(windowsAcl());
        Path directory = Files.createDirectory(root.resolve("shared"));
        AclFileAttributeView view = aclView(directory);
        AclEntry grant = entry(AclEntryType.ALLOW, stranger(view.getOwner()),
                AclEntryPermission.ADD_FILE);
        view.setAcl(Stream.concat(view.getAcl().stream(), Stream.of(grant)).toList());
        List<AclEntry> before = view.getAcl();
        assertEquals(StorageException.Code.PERMISSIONS, openFailure(directory.resolve("vault.pmv")));
        assertEquals(before, view.getAcl());
        try (Stream<Path> children = Files.list(directory)) {
            assertEquals(0, children.count());
        }
    }

    @Test
    void windowsReadOnlyGrantToAnotherPrincipalIsAccepted() throws IOException, StorageException {
        assumeTrue(windowsAcl());
        Path directory = Files.createDirectory(root.resolve("listed"));
        AclFileAttributeView view = aclView(directory);
        AclEntry grant = entry(AclEntryType.ALLOW, stranger(view.getOwner()),
                AclEntryPermission.LIST_DIRECTORY);
        view.setAcl(Stream.concat(view.getAcl().stream(), Stream.of(grant)).toList());
        List<AclEntry> before = view.getAcl();
        saveTwice(directory.resolve("vault.pmv"));
        assertEquals(before, view.getAcl());
    }

    @Test
    void windowsDenyEntryIsNotMistakenForAGrant() throws IOException, StorageException {
        assumeTrue(windowsAcl());
        Path directory = Files.createDirectory(root.resolve("denied"));
        AclFileAttributeView view = aclView(directory);
        // Denying "take ownership" names a write right without getting in the store's way.
        AclEntry denial = entry(AclEntryType.DENY, stranger(view.getOwner()),
                AclEntryPermission.WRITE_OWNER);
        view.setAcl(Stream.concat(Stream.of(denial), view.getAcl().stream()).toList());
        List<AclEntry> before = view.getAcl();
        assertTrue(before.stream().anyMatch(entry -> entry.type() == AclEntryType.DENY));
        saveTwice(directory.resolve("vault.pmv"));
        assertEquals(before, view.getAcl());
    }

    @Test
    void administrativeAccountsAreRecognisedBySecurityIdentifier() throws IOException {
        assumeTrue(windowsAcl());
        var lookup = root.getFileSystem().getUserPrincipalLookupService();
        // The English names resolve only on an English system; the test under scrutiny does
        // not use names at all, which is why it also works where these lookups fail.
        Optional<UserPrincipal> system = lookedUp(() -> lookup.lookupPrincipalByName("SYSTEM"));
        Optional<UserPrincipal> administrators =
                lookedUp(() -> lookup.lookupPrincipalByName("BUILTIN\\Administrators"));
        assumeTrue(system.isPresent() && administrators.isPresent(), "localised account names");
        assertTrue(OwnerOnly.administrative(system.get()));
        assertTrue(OwnerOnly.administrative(administrators.get()));
        Optional<UserPrincipal> everyone = lookedUp(() -> lookup.lookupPrincipalByName("Everyone"));
        Optional<UserPrincipal> user =
                lookedUp(() -> lookup.lookupPrincipalByName(System.getProperty("user.name")));
        assumeTrue(everyone.isPresent() && user.isPresent(), "localised account names");
        assertFalse(OwnerOnly.administrative(everyone.get()));
        assertFalse(OwnerOnly.administrative(user.get()));
    }

    // One backup and two writes: every kind of file the store creates must come out owner-only.
    private static void saveTwice(Path file) throws StorageException {
        Path name = Objects.requireNonNull(file.getFileName(), "NAME");
        try (VaultFileStore store = VaultFileStore.open(file)) {
            store.writeAtomically(new byte[] {1});
            store.backup();
            store.writeAtomically(new byte[] {2});
            assertArrayEquals(new byte[] {2}, store.readAll());
            assertTrue(OwnerOnly.isOwnerOnly(file));
            assertTrue(OwnerOnly.isOwnerOnly(file.resolveSibling(name + ".bak.1")));
            assertTrue(OwnerOnly.isOwnerOnly(file.resolveSibling(name + ".lock")));
        }
        try (VaultFileStore reopened = VaultFileStore.open(file)) {
            assertArrayEquals(new byte[] {2}, reopened.readAll());
        }
    }

    private static StorageException.Code openFailure(Path file) {
        return assertThrows(StorageException.class, () -> {
            try (VaultFileStore store = VaultFileStore.open(file)) {
                assertFalse(store.exists());
            }
        }).code();
    }

    // A principal that is neither the owner nor administrative, found without relying on account
    // names: the root of the volume lists ordinary groups such as Users.
    private UserPrincipal stranger(UserPrincipal owner) throws IOException {
        Path volume = Objects.requireNonNull(root.getRoot(), "ROOT");
        Optional<UserPrincipal> found = aclView(volume).getAcl().stream()
                .map(AclEntry::principal)
                .filter(principal -> !principal.equals(owner) && !OwnerOnly.administrative(principal))
                .findFirst();
        assumeTrue(found.isPresent(), "the volume root lists no ordinary principal");
        return found.get();
    }

    private static AclEntry entry(AclEntryType type, UserPrincipal principal,
            AclEntryPermission permission) {
        return AclEntry.newBuilder().setType(type).setPrincipal(principal)
                .setPermissions(permission).build();
    }

    private static AclFileAttributeView aclView(Path path) {
        return Objects.requireNonNull(Files.getFileAttributeView(
                path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS), "ACL");
    }

    private static Optional<UserPrincipal> lookedUp(Lookup lookup) {
        try {
            return Optional.of(lookup.find());
        } catch (IOException unknown) {
            return Optional.empty();
        }
    }

    @FunctionalInterface
    private interface Lookup {
        UserPrincipal find() throws IOException;
    }

    private boolean posix() {
        return root.getFileSystem().supportedFileAttributeViews().contains("posix");
    }

    private boolean windowsAcl() {
        Set<String> views = root.getFileSystem().supportedFileAttributeViews();
        return views.contains("acl") && !views.contains("posix");
    }

    // The deliberately shared mode is test data handed in as an argument.
    private static Set<PosixFilePermission> mode(String text) {
        return PosixFilePermissions.fromString(text);
    }
}
