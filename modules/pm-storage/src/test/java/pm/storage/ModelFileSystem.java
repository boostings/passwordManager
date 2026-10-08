package pm.storage;

import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.ProviderMismatchException;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.nio.file.spi.FileSystemProvider;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A test file system that keeps file contents, links and locks on the real disk but models
 * ownership and permissions in memory, either as POSIX modes or as Windows ACLs. It lets the
 * storage layer's checks for the other platform, and for states the real platform will not
 * produce on demand (another owner, an empty ACL, a write that makes no progress), run on every
 * operating system, so no branch is left to the CI host that happens to have the feature
 * (M7.10). Principals behave like the JDK's Windows principals: they compare by security
 * identifier and hash as that string, which is what {@code OwnerOnly.administrative} relies on.
 * Like the tests that build it, an instance is used by one thread only.
 */
final class ModelFileSystem extends FileSystem {
    /** Which permission model the file system offers; BASIC offers neither. */
    enum Kind { POSIX, ACL, BASIC }

    /** A user or group, compared by security identifier like {@code WindowsUserPrincipals}. */
    static class Principal implements UserPrincipal {
        private final String sid;
        private final String name;

        Principal(String sid, String name) {
            this.sid = sid;
            this.name = name;
        }

        @Override public String getName() {
            return name;
        }

        @Override public boolean equals(Object other) {
            return other instanceof Principal principal && principal.sid.equals(sid);
        }

        @Override public int hashCode() {
            return sid.hashCode();
        }

        @Override public String toString() {
            return name;
        }
    }

    /** A group principal; {@code SYSTEM} and {@code Administrators} are groups in the JDK too. */
    static final class Group extends Principal implements GroupPrincipal {
        Group(String sid, String name) {
            super(sid, name);
        }
    }

    static final Principal ME = new Principal("S-1-5-21-1-1001", "model-me");
    static final Principal OTHER = new Principal("S-1-5-21-1-1002", "model-other");
    static final Group SYSTEM = new Group("S-1-5-18", "NT AUTHORITY\\SYSTEM");
    static final Group ADMINISTRATORS = new Group("S-1-5-32-544", "BUILTIN\\Administrators");
    static final Group USERS = new Group("S-1-5-32-545", "BUILTIN\\Users");

    /** What the model records for one path, keyed by its real location. */
    static final class Meta {
        UserPrincipal owner = ME;
        Set<PosixFilePermission> permissions;
        List<AclEntry> acl;
        Long reportedSize;
        boolean reportOther;
        boolean reportLink;
        boolean ignoreChanges;
        boolean zeroWrites;
        boolean lockHeld;
        boolean raceCreate;
        Path raceLink;
        boolean absent;
        Path realPath;
        FaultChannel channel;

        /** The last channel opened on this entry; a test that expects one fails without it. */
        FaultChannel openedChannel() {
            if (channel == null) {
                throw new IllegalStateException("no channel was opened");
            }
            return channel;
        }
    }

    private static final String POSIX_PERMISSIONS = "posix:permissions";
    private static final String ACL_ENTRIES = "acl:acl";

    private final Kind kind;
    private final FileSystem real;
    private final Provider modelProvider = new Provider();
    private final Map<Path, Meta> metas = new HashMap<>();
    private final Map<String, UserPrincipal> principalsByName = new HashMap<>();

    ModelFileSystem(Kind kind, FileSystem real) {
        this.kind = kind;
        this.real = real;
        String self = System.getProperty("user.name");
        if (self != null && !self.isBlank()) {
            principalsByName.put(self, ME);
        }
    }

    /** The permission model's name, which tests use to tell their per-kind files apart. */
    @Override public String toString() {
        return kind.name();
    }

    /** The model counterpart of a real path. */
    Path wrap(Path path) {
        return path == null ? null : new ModelPath(this, path);
    }

    /** The recorded state of a path, created with owner-only defaults on first use. */
    Meta meta(Path path) {
        return metas.computeIfAbsent(key(unwrap(path)), k -> {
            Meta meta = new Meta();
            boolean directory = Files.isDirectory(k, LinkOption.NOFOLLOW_LINKS);
            meta.permissions = mode(directory ? "rwx------" : "rw-------");
            meta.acl = ownerAcl(ME);
            return meta;
        });
    }

    // The record of an entry that exists on disk; a missing one fails as the platform would.
    private Meta live(Path path) throws IOException {
        if (!Files.exists(unwrap(path), LinkOption.NOFOLLOW_LINKS) || meta(path).absent) {
            throw new NoSuchFileException(path.toString());
        }
        return meta(path);
    }

    // The real path of an entry, unless the test made the model resolve it somewhere else.
    private Path realPath(ModelPath path, LinkOption... options) throws IOException {
        Meta meta = metas.get(key(path.delegate));
        if (meta != null && meta.realPath != null) {
            return meta.realPath;
        }
        return wrap(path.delegate.toRealPath(options));
    }

    /** Lets the account database forget the current user, or learn another name. */
    void accounts(Map<String, UserPrincipal> known) {
        principalsByName.clear();
        principalsByName.putAll(known);
    }

    static List<AclEntry> ownerAcl(UserPrincipal owner) {
        return List.of(entry(owner, AclEntryType.ALLOW, EnumSet.allOf(AclEntryPermission.class)));
    }

    static AclEntry entry(UserPrincipal who, AclEntryType type, Set<AclEntryPermission> rights,
                          AclEntryFlag... flags) {
        AclEntry.Builder builder = AclEntry.newBuilder().setType(type).setPrincipal(who)
                .setPermissions(rights);
        if (flags.length > 0) {
            builder.setFlags(flags);
        }
        return builder.build();
    }

    private static Path unwrap(Path path) {
        if (path instanceof ModelPath model) {
            return model.delegate;
        }
        throw new ProviderMismatchException();
    }

    // A file's entry follows its real parent, so /var and /private/var on macOS share one record.
    private static Path key(Path real) {
        Path absolute = real.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        Path name = absolute.getFileName();
        if (parent == null || name == null) {
            return absolute;
        }
        try {
            return parent.toRealPath().resolve(name);
        } catch (IOException missing) {
            return absolute;
        }
    }

    // A new entry records the attributes it was created with, as the platform would apply them.
    // Fault flags and an owner set before the entry existed are kept.
    private void created(Path path, boolean directory, FileAttribute<?>... attributes) {
        Meta meta = metas.getOrDefault(key(unwrap(path)), new Meta());
        meta.permissions = mode(directory ? "rwxr-xr-x" : "rw-r--r--");
        meta.acl = List.of(entry(ME, AclEntryType.ALLOW, EnumSet.allOf(AclEntryPermission.class)),
                entry(USERS, AclEntryType.ALLOW, EnumSet.of(AclEntryPermission.READ_DATA)));
        for (FileAttribute<?> attribute : attributes) {
            if (POSIX_PERMISSIONS.equals(attribute.name())) {
                @SuppressWarnings("unchecked")
                Set<PosixFilePermission> value = (Set<PosixFilePermission>) attribute.value();
                meta.permissions = EnumSet.copyOf(value);
            } else if (ACL_ENTRIES.equals(attribute.name())) {
                @SuppressWarnings("unchecked")
                List<AclEntry> value = (List<AclEntry>) attribute.value();
                meta.acl = List.copyOf(value);
            } else {
                throw new UnsupportedOperationException(attribute.name());
            }
        }
        metas.put(key(unwrap(path)), meta);
    }

    @Override public FileSystemProvider provider() {
        return modelProvider;
    }

    @Override public void close() {
        // Nothing is held open by the model itself.
    }

    @Override public boolean isOpen() {
        return true;
    }

    @Override public boolean isReadOnly() {
        return false;
    }

    @Override public String getSeparator() {
        return real.getSeparator();
    }

    @Override public Iterable<Path> getRootDirectories() {
        List<Path> roots = new ArrayList<>();
        real.getRootDirectories().forEach(root -> roots.add(wrap(root)));
        return roots;
    }

    @Override public Iterable<FileStore> getFileStores() {
        return real.getFileStores();
    }

    @Override public Set<String> supportedFileAttributeViews() {
        return switch (kind) {
            case POSIX -> Set.of("basic", "owner", "posix");
            case ACL -> Set.of("basic", "owner", "acl");
            case BASIC -> Set.of("basic");
        };
    }

    @Override public Path getPath(String first, String... more) {
        return wrap(real.getPath(first, more));
    }

    @Override public PathMatcher getPathMatcher(String syntaxAndPattern) {
        throw new UnsupportedOperationException();
    }

    @Override public UserPrincipalLookupService getUserPrincipalLookupService() {
        return new UserPrincipalLookupService() {
            @Override public UserPrincipal lookupPrincipalByName(String name) throws IOException {
                UserPrincipal found = principalsByName.get(name);
                if (found == null) {
                    throw new UserPrincipalNotFoundException(name);
                }
                return found;
            }

            @Override public GroupPrincipal lookupPrincipalByGroupName(String group) throws IOException {
                throw new UserPrincipalNotFoundException(group);
            }
        };
    }

    @Override public WatchService newWatchService() {
        throw new UnsupportedOperationException();
    }

    /** A path of the model; every operation is answered by the real path it wraps. */
    static final class ModelPath implements Path {
        final ModelFileSystem fs;
        final Path delegate;

        ModelPath(ModelFileSystem fs, Path delegate) {
            this.fs = fs;
            this.delegate = delegate;
        }

        @Override public FileSystem getFileSystem() {
            return fs;
        }

        @Override public boolean isAbsolute() {
            return delegate.isAbsolute();
        }

        @Override public Path getRoot() {
            return fs.wrap(delegate.getRoot());
        }

        @Override public Path getFileName() {
            return fs.wrap(delegate.getFileName());
        }

        @Override public Path getParent() {
            return fs.wrap(delegate.getParent());
        }

        @Override public int getNameCount() {
            return delegate.getNameCount();
        }

        @Override public Path getName(int index) {
            return fs.wrap(delegate.getName(index));
        }

        @Override public Path subpath(int beginIndex, int endIndex) {
            return fs.wrap(delegate.subpath(beginIndex, endIndex));
        }

        @Override public boolean startsWith(Path other) {
            return delegate.startsWith(unwrap(other));
        }

        @Override public boolean endsWith(Path other) {
            return delegate.endsWith(unwrap(other));
        }

        @Override public Path normalize() {
            return fs.wrap(delegate.normalize());
        }

        @Override public Path resolve(Path other) {
            return fs.wrap(delegate.resolve(unwrap(other)));
        }

        @Override public Path relativize(Path other) {
            return fs.wrap(delegate.relativize(unwrap(other)));
        }

        @Override public URI toUri() {
            return delegate.toUri();
        }

        @Override public Path toAbsolutePath() {
            return fs.wrap(delegate.toAbsolutePath());
        }

        @Override public Path toRealPath(LinkOption... options) throws IOException {
            return fs.realPath(this, options);
        }

        @Override public WatchKey register(WatchService watcher, WatchEvent.Kind<?>[] events,
                                           WatchEvent.Modifier... modifiers) {
            throw new UnsupportedOperationException();
        }

        @Override public int compareTo(Path other) {
            return delegate.compareTo(unwrap(other));
        }

        @Override public boolean equals(Object other) {
            return other instanceof ModelPath path && path.fs == fs && path.delegate.equals(delegate);
        }

        @Override public int hashCode() {
            return delegate.hashCode();
        }

        @Override public String toString() {
            return delegate.toString();
        }
    }

    private final class Provider extends FileSystemProvider {
        private FileSystemProvider realProvider() {
            return real.provider();
        }

        @Override public String getScheme() {
            return "model";
        }

        @Override public FileSystem newFileSystem(URI uri, Map<String, ?> env) {
            throw new UnsupportedOperationException();
        }

        @Override public FileSystem getFileSystem(URI uri) {
            throw new UnsupportedOperationException();
        }

        @Override public Path getPath(URI uri) {
            throw new UnsupportedOperationException();
        }

        @Override public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options,
                                                            FileAttribute<?>... attrs) throws IOException {
            return newFileChannel(path, options, attrs);
        }

        @Override public FileChannel newFileChannel(Path path, Set<? extends OpenOption> options,
                                                    FileAttribute<?>... attrs) throws IOException {
            Path target = unwrap(path);
            boolean existed = Files.exists(target, LinkOption.NOFOLLOW_LINKS);
            Meta meta = meta(path);
            FaultChannel faulty = new FaultChannel(realProvider().newFileChannel(target, options),
                    meta.zeroWrites, meta.lockHeld);
            if (!existed) {
                created(path, false, attrs);
            }
            meta.channel = faulty;
            return faulty;
        }

        @Override public DirectoryStream<Path> newDirectoryStream(
                Path dir, DirectoryStream.Filter<? super Path> filter) throws IOException {
            return new Listing(realProvider().newDirectoryStream(unwrap(dir), entry -> true));
        }

        @Override public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
            Path link = meta(dir).raceLink;
            if (link != null) {
                // Another process put a link there first.
                realProvider().createSymbolicLink(unwrap(dir), unwrap(link));
                throw new FileAlreadyExistsException(dir.toString());
            }
            realProvider().createDirectory(unwrap(dir));
            boolean raced = meta(dir).raceCreate;
            created(dir, true, raced ? new FileAttribute<?>[0] : attrs);
            if (raced) {
                // Another process created the entry first; the caller sees what it left.
                throw new FileAlreadyExistsException(dir.toString());
            }
        }

        @Override public void createSymbolicLink(Path link, Path target, FileAttribute<?>... attrs)
                throws IOException {
            realProvider().createSymbolicLink(unwrap(link), unwrap(target));
        }

        @Override public Path readSymbolicLink(Path link) throws IOException {
            return wrap(realProvider().readSymbolicLink(unwrap(link)));
        }

        @Override public void delete(Path path) throws IOException {
            realProvider().delete(unwrap(path));
            metas.remove(key(unwrap(path)));
        }

        @Override public void copy(Path source, Path target, CopyOption... options) {
            throw new UnsupportedOperationException();
        }

        @Override public void move(Path source, Path target, CopyOption... options) throws IOException {
            Meta moved = meta(source);
            realProvider().move(unwrap(source), unwrap(target), options);
            metas.remove(key(unwrap(source)));
            metas.put(key(unwrap(target)), moved);
        }

        @Override public boolean isSameFile(Path path, Path path2) throws IOException {
            return realProvider().isSameFile(unwrap(path), unwrap(path2));
        }

        @Override public boolean isHidden(Path path) throws IOException {
            return realProvider().isHidden(unwrap(path));
        }

        @Override public FileStore getFileStore(Path path) throws IOException {
            return realProvider().getFileStore(unwrap(path));
        }

        @Override public void checkAccess(Path path, AccessMode... modes) throws IOException {
            if (meta(path).absent) {
                throw new NoSuchFileException(path.toString());
            }
            realProvider().checkAccess(unwrap(path), modes);
        }

        @Override public <V extends FileAttributeView> V getFileAttributeView(
                Path path, Class<V> type, LinkOption... options) {
            Object view = null;
            boolean owner = type == FileOwnerAttributeView.class;
            if (kind == Kind.POSIX && (owner || type == PosixFileAttributeView.class)) {
                view = new PosixView(path);
            } else if (kind == Kind.ACL && (owner || type == AclFileAttributeView.class)) {
                view = new AclView(path);
            }
            return view == null ? null : type.cast(view);
        }

        @Override public <A extends BasicFileAttributes> A readAttributes(
                Path path, Class<A> type, LinkOption... options) throws IOException {
            BasicFileAttributes basic = realProvider().readAttributes(
                    unwrap(path), BasicFileAttributes.class, options);
            if (meta(path).absent) {
                throw new NoSuchFileException(path.toString());
            }
            if (type == BasicFileAttributes.class) {
                return type.cast(new Attributes(basic, meta(path)));
            }
            if (type == PosixFileAttributes.class && kind == Kind.POSIX) {
                return type.cast(new PosixView(path).readAttributes());
            }
            throw new UnsupportedOperationException(type.getName());
        }

        @Override public Map<String, Object> readAttributes(Path path, String attributes,
                                                            LinkOption... options) {
            throw new UnsupportedOperationException();
        }

        @Override public void setAttribute(Path path, String attribute, Object value,
                                           LinkOption... options) {
            throw new UnsupportedOperationException();
        }
    }

    /** Basic attributes from the disk, except a size or a kind the test asks the model to report. */
    private static class Attributes implements BasicFileAttributes {
        private final BasicFileAttributes basic;
        private final Meta meta;

        Attributes(BasicFileAttributes basic, Meta meta) {
            this.basic = basic;
            this.meta = meta;
        }

        @Override public FileTime lastModifiedTime() {
            return basic.lastModifiedTime();
        }

        @Override public FileTime lastAccessTime() {
            return basic.lastAccessTime();
        }

        @Override public FileTime creationTime() {
            return basic.creationTime();
        }

        @Override public boolean isRegularFile() {
            return !meta.reportOther && !meta.reportLink && basic.isRegularFile();
        }

        @Override public boolean isDirectory() {
            return !meta.reportOther && !meta.reportLink && basic.isDirectory();
        }

        @Override public boolean isSymbolicLink() {
            return meta.reportLink || basic.isSymbolicLink();
        }

        @Override public boolean isOther() {
            return meta.reportOther || basic.isOther();
        }

        @Override public long size() {
            return meta.reportedSize == null ? basic.size() : meta.reportedSize;
        }

        @Override public Object fileKey() {
            return basic.fileKey();
        }
    }

    private final class PosixView implements PosixFileAttributeView {
        private final Path path;

        PosixView(Path path) {
            this.path = path;
        }

        @Override public String name() {
            return "posix";
        }

        @Override public PosixFileAttributes readAttributes() throws IOException {
            BasicFileAttributes basic = real.provider().readAttributes(
                    unwrap(path), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            Meta meta = meta(path);
            Set<PosixFilePermission> permissions = EnumSet.noneOf(PosixFilePermission.class);
            permissions.addAll(meta.permissions);
            UserPrincipal owner = meta.owner;
            return new PosixAttributes(basic, meta, owner, permissions);
        }

        @Override public void setPermissions(Set<PosixFilePermission> perms) throws IOException {
            Meta meta = live(path);
            if (!meta.ignoreChanges) {
                meta.permissions = EnumSet.copyOf(perms);
            }
        }

        @Override public void setGroup(GroupPrincipal group) {
            throw new UnsupportedOperationException();
        }

        @Override public void setTimes(FileTime lastModifiedTime, FileTime lastAccessTime, FileTime createTime) {
            throw new UnsupportedOperationException();
        }

        @Override public UserPrincipal getOwner() throws IOException {
            return live(path).owner;
        }

        @Override public void setOwner(UserPrincipal owner) throws IOException {
            live(path).owner = owner;
        }
    }

    private static final class PosixAttributes extends Attributes implements PosixFileAttributes {
        private final UserPrincipal ownerPrincipal;
        private final Set<PosixFilePermission> modes;

        PosixAttributes(BasicFileAttributes basic, Meta meta, UserPrincipal owner,
                        Set<PosixFilePermission> permissions) {
            super(basic, meta);
            this.ownerPrincipal = owner;
            this.modes = permissions;
        }

        @Override public UserPrincipal owner() {
            return ownerPrincipal;
        }

        @Override public GroupPrincipal group() {
            return USERS;
        }

        @Override public Set<PosixFilePermission> permissions() {
            return new HashSet<>(modes);
        }
    }

    private final class AclView implements AclFileAttributeView {
        private final Path path;

        AclView(Path path) {
            this.path = path;
        }

        @Override public String name() {
            return "acl";
        }

        @Override public List<AclEntry> getAcl() throws IOException {
            return new ArrayList<>(live(path).acl);
        }

        @Override public void setAcl(List<AclEntry> acl) throws IOException {
            Meta meta = live(path);
            if (!meta.ignoreChanges) {
                meta.acl = List.copyOf(Objects.requireNonNull(acl));
            }
        }

        @Override public UserPrincipal getOwner() throws IOException {
            return live(path).owner;
        }

        @Override public void setOwner(UserPrincipal owner) throws IOException {
            live(path).owner = owner;
        }
    }

    /**
     * A POSIX mode from its text. Modes are test data handed in as an argument, so a deliberately
     * shared one is visible where a test asks for it; the model keeps it in memory, never on disk.
     */
    static Set<PosixFilePermission> mode(String text) {
        return EnumSet.copyOf(PosixFilePermissions.fromString(text));
    }

    // A real directory listing whose entries come back as model paths; closing it closes the real one.
    private final class Listing implements DirectoryStream<Path> {
        private final DirectoryStream<Path> entries;

        Listing(DirectoryStream<Path> entries) {
            this.entries = entries;
        }

        @Override public Iterator<Path> iterator() {
            Iterator<Path> inner = entries.iterator();
            return new Iterator<>() {
                @Override public boolean hasNext() {
                    return inner.hasNext();
                }

                @Override public Path next() {
                    return wrap(inner.next());
                }
            };
        }

        @Override public void close() throws IOException {
            entries.close();
        }
    }

    /**
     * A real channel with the faults a test asked for: writes that make no progress, which a real
     * file channel never does, or a lock that another process holds. The last lock it handed out
     * is kept so a test can release it behind its holder's back.
     */
    static final class FaultChannel extends FileChannel {
        private final FileChannel inner;
        private final boolean stalled;
        private final boolean lockHeld;
        FileLock lastLock;

        FaultChannel(FileChannel inner, boolean stalled, boolean lockHeld) {
            this.inner = inner;
            this.stalled = stalled;
            this.lockHeld = lockHeld;
        }

        /** The last lock this channel handed out; a test that expects one fails without it. */
        FileLock heldLock() {
            if (lastLock == null) {
                throw new IllegalStateException("no lock was taken");
            }
            return lastLock;
        }

        @Override public int read(ByteBuffer dst) throws IOException {
            return inner.read(dst);
        }

        @Override public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
            return inner.read(dsts, offset, length);
        }

        @Override public int write(ByteBuffer src) throws IOException {
            return stalled ? 0 : inner.write(src);
        }

        @Override public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
            return stalled ? 0 : inner.write(srcs, offset, length);
        }

        @Override public long position() throws IOException {
            return inner.position();
        }

        @Override public FileChannel position(long newPosition) throws IOException {
            inner.position(newPosition);
            return this;
        }

        @Override public long size() throws IOException {
            return inner.size();
        }

        @Override public FileChannel truncate(long size) throws IOException {
            inner.truncate(size);
            return this;
        }

        @Override public void force(boolean metaData) throws IOException {
            inner.force(metaData);
        }

        @Override public long transferTo(long position, long count, WritableByteChannel target) {
            throw new UnsupportedOperationException();
        }

        @Override public long transferFrom(ReadableByteChannel src, long position, long count) {
            throw new UnsupportedOperationException();
        }

        @Override public int read(ByteBuffer dst, long position) throws IOException {
            return inner.read(dst, position);
        }

        @Override public int write(ByteBuffer src, long position) throws IOException {
            return stalled ? 0 : inner.write(src, position);
        }

        @Override public MappedByteBuffer map(MapMode mode, long position, long size) {
            throw new UnsupportedOperationException();
        }

        @Override public FileLock lock(long position, long size, boolean shared) throws IOException {
            lastLock = inner.lock(position, size, shared);
            return lastLock;
        }

        @Override public FileLock tryLock(long position, long size, boolean shared) throws IOException {
            if (lockHeld) {
                return null;
            }
            lastLock = inner.tryLock(position, size, shared);
            return lastLock;
        }

        @Override protected void implCloseChannel() throws IOException {
            inner.close();
        }
    }
}
