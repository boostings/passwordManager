package pm.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import pm.crypto.Argon2Params;
import pm.crypto.CryptoException;
import pm.crypto.Csprng;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.storage.OwnerOnly;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;
import pm.vault.envelope.EnvelopeCodec;

/**
 * Encrypted backup, verified restore and rotation (ADR 0015, T-BKP-01, SR-700, SR-703, SR-704).
 */
@Tag("T-BKP-01")
final class VaultBackupsTest {

    private static final Instant T = Instant.parse("2026-10-03T08:09:10Z");

    @TempDir
    Path dir;

    private Path source;
    private Path backups;
    private VaultFileStore sourceStore;
    private CreatedVault created;

    @BeforeEach
    void createSourceVault() throws StorageException, VaultException {
        source = dir.resolve("src/vault.pmv");
        backups = dir.resolve("backups");
        sourceStore = VaultFileStore.open(source);
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            created = new VaultService(sourceStore, Fixtures.CLOCK, Argon2Params.FLOOR).create(pw);
        }
        Formats.goldenRecords().forEach(created.vault()::put);
        created.vault().save();
    }

    @AfterEach
    void closeSource() {
        created.close();
        sourceStore.close();
    }

    // ---- round trip ------------------------------------------------------------------------

    @Test
    void backupThenRestoreReproducesTheVaultExactly() throws IOException, StorageException, VaultException {
        VaultBackups.Created made = service(T).create(created.vault(), backups, 3);

        assertEquals("pm-backup-20261003T080910Z-000.pmbackup", String.valueOf(made.file().getFileName()));
        assertEquals(new VaultBackups.Info(T, EnvelopeCodec.VERSION, Files.size(source), 2), made.info());
        assertEquals(new VaultBackups.Rotation(List.of(), List.of(), true), made.rotation());
        assertOwnerOnly(made.file());
        assertOwnerOnly(backups);
        assertEquals(made.info(), service(T).inspect(made.file()));

        byte[] backup = Files.readAllBytes(made.file());
        for (String secret : List.of("golden-login-value", "golden-wifi-value", "golden-env-value", "Golden login")) {
            assertFalse(contains(backup, secret.getBytes(StandardCharsets.UTF_8)), "plaintext in backup: " + secret);
        }

        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            assertEquals(new VaultBackups.Verified(made.info(), 4), service(T).verify(made.file(), pw));
            Path target = dir.resolve("restored/vault.pmv");
            VaultBackups.Restored restored = service(T).restore(made.file(), target, pw, false);
            assertEquals(new VaultBackups.Restored(made.info(), false, false), restored);
            assertArrayEquals(Files.readAllBytes(source), Files.readAllBytes(target));
            assertOwnerOnly(target);
            try (VaultFileStore store = VaultFileStore.open(target)) {
                GoldenFixtureTest.assertGoldenContent(new VaultService(store, Fixtures.CLOCK, Argon2Params.FLOOR));
            }
        }
    }

    @Test
    void backupHoldsTheLastSaveNotUnsavedEdits() throws IOException, VaultException {
        byte[] saved = Files.readAllBytes(source);
        created.vault().remove(created.vault().records().get(0).id());
        VaultBackups.Created made = service(T).create(created.vault(), backups, 3);
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            assertEquals(4, service(T).verify(made.file(), pw).records());
        }
        assertArrayEquals(saved, BackupFormat.parse(Files.readAllBytes(made.file())).vault());
    }

    @Test
    void lockedVaultCannotBeBackedUp() {
        created.vault().close();
        assertCode(VaultException.Code.LOCKED, () -> service(T).create(created.vault(), backups, 3));
        assertFalse(Files.exists(backups));
    }

    @Test
    void damagedSavedFileIsNeverBackedUp() throws IOException {
        byte[] file = Files.readAllBytes(source);
        file[file.length - 1] ^= 1;
        Files.write(source, file);
        assertCode(VaultException.Code.CORRUPT, () -> service(T).create(created.vault(), backups, 3));
        assertFalse(Files.exists(backups));
    }

    // ---- refusal: tamper, truncation, password, version -------------------------------------

    @Test
    void everySingleByteChangeIsRefused() throws IOException, VaultException {
        Path backup = service(T).create(created.vault(), backups, 3).file();
        byte[] good = Files.readAllBytes(backup);
        Path bad = dir.resolve("bad.pmbackup");
        int needingKey = 0;
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            for (int offset = 0; offset < good.length; offset++) {
                byte[] tampered = good.clone();
                tampered[offset] ^= 0x01;
                Files.write(bad, tampered);
                if (inspectFails(bad)) {
                    continue;
                }
                // Header fields such as the time pass the hash check; only the HMAC catches them.
                needingKey++;
                assertCode(VaultException.Code.CORRUPT, () -> service(T).verify(bad, pw));
            }
        }
        assertTrue(needingKey >= 32, "the tag bytes, at least, need the key: " + needingKey);
    }

    @Test
    void forgedHeaderWithAMatchingHashFailsTheMac() throws IOException, VaultException {
        Path backup = service(T).create(created.vault(), backups, 3).file();
        byte[] vaultFile = BackupFormat.parse(Files.readAllBytes(backup)).vault();
        BackupFormat.Header forgedHeader = BackupFormat.Header.of(1L, vaultFile, Csprng.bytes(32));
        byte[] forged;
        try (SecretBytes otherKey = Csprng.secretBytes(32)) {
            forged = BackupFormat.assemble(forgedHeader, vaultFile, otherKey);
        }
        Path bad = dir.resolve("forged.pmbackup");
        Files.write(bad, forged);
        assertEquals(Instant.ofEpochSecond(1), service(T).inspect(bad).created(), "inspect is unauthenticated");
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            assertCode(VaultException.Code.CORRUPT, () -> service(T).verify(bad, pw));
            assertCode(VaultException.Code.CORRUPT,
                    () -> service(T).restore(bad, dir.resolve("t/vault.pmv"), pw, true));
        }
        assertFalse(Files.exists(dir.resolve("t")));
    }

    @Test
    void everyTruncationIsRefusedAndNeverRestored() throws IOException, VaultException {
        Path backup = service(T).create(created.vault(), backups, 3).file();
        byte[] good = Files.readAllBytes(backup);
        Path bad = dir.resolve("short.pmbackup");
        for (int length = 0; length < good.length; length++) {
            Files.write(bad, Arrays.copyOf(good, length));
            assertCode(VaultException.Code.CORRUPT, () -> service(T).inspect(bad));
        }
        Files.write(bad, Arrays.copyOf(good, good.length - 1));
        Path target = dir.resolve("t/vault.pmv");
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            assertCode(VaultException.Code.CORRUPT, () -> service(T).restore(bad, target, pw, true));
        }
        assertFalse(Files.exists(target.getParent()));
        byte[] longer = Arrays.copyOf(good, good.length + 1);
        Files.write(bad, longer);
        assertCode(VaultException.Code.CORRUPT, () -> service(T).inspect(bad));
    }

    @Test
    void wrongPassphraseIsRefusedAndNothingIsWritten() throws VaultException {
        Path backup = service(T).create(created.vault(), backups, 3).file();
        Path target = dir.resolve("t/vault.pmv");
        try (SecretChars pw = Fixtures.chars("not the phrase")) {
            assertCode(VaultException.Code.WRONG_CREDENTIAL, () -> service(T).verify(backup, pw));
            assertCode(VaultException.Code.WRONG_CREDENTIAL, () -> service(T).restore(backup, target, pw, true));
        }
        assertFalse(Files.exists(target.getParent()));
    }

    @Test
    void newerBackupLayoutAndUnreadableVaultFormatsAreUnsupported()
            throws CryptoException, IOException, VaultException {
        Path backup = service(T).create(created.vault(), backups, 3).file();
        byte[] newer = Files.readAllBytes(backup);
        newer[9] = 2;
        Path bad = dir.resolve("newer.pmbackup");
        Files.write(bad, newer);
        assertCode(VaultException.Code.UNSUPPORTED_VERSION, () -> service(T).inspect(bad));
        newer[9] = 0;
        Files.write(bad, newer);
        assertCode(VaultException.Code.CORRUPT, () -> service(T).inspect(bad));

        // A backup whose embedded vault is a format this build has no migration for.
        byte[] v0 = Formats.v0File(Formats.GOLDEN_PHRASE, null, List.of());
        try (SecretBytes anyKey = Csprng.secretBytes(32)) {
            Files.write(bad, BackupFormat.assemble(BackupFormat.Header.of(0, v0, Csprng.bytes(32)), v0, anyKey));
        }
        assertCode(VaultException.Code.UNSUPPORTED_VERSION, () -> service(T).inspect(bad));
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            assertCode(VaultException.Code.UNSUPPORTED_VERSION, () -> service(T).verify(bad, pw));
        }
        assertEquals(0, new VaultBackups(Fixtures.CLOCK, Formats.WITH_V0, PayloadCodec.RECORDS, VaultFileStore::open)
                .inspect(bad).formatVersion());
    }

    @Test
    void missingOrLinkedBackupIsAStorageFailure() throws IOException, VaultException {
        assertCode(VaultException.Code.STORAGE, () -> service(T).inspect(dir.resolve("absent.pmbackup")));
        Path backup = service(T).create(created.vault(), backups, 3).file();
        Path link = dir.resolve("link.pmbackup");
        Files.createSymbolicLink(link, backup);
        assertCode(VaultException.Code.STORAGE, () -> service(T).inspect(link));
    }

    // ---- restore onto an existing vault ------------------------------------------------------

    @Test
    void restoreReplacesAnExistingVaultOnlyWithExplicitConfirmation() throws IOException, VaultException {
        Path backup = service(T).create(created.vault(), backups, 3).file();
        byte[] backedUp = Files.readAllBytes(source);
        created.vault().remove(created.vault().records().get(0).id());
        created.vault().save();
        byte[] newer = Files.readAllBytes(source);

        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            // The source vault is open, so its store lock refuses the restore.
            assertCode(VaultException.Code.STORAGE, () -> service(T).restore(backup, source, pw, true));
            assertArrayEquals(newer, Files.readAllBytes(source));
            created.close();
            sourceStore.close();

            assertCode(VaultException.Code.ALREADY_EXISTS, () -> service(T).restore(backup, source, pw, false));
            assertArrayEquals(newer, Files.readAllBytes(source));

            VaultBackups.Restored restored = service(T).restore(backup, source, pw, true);
            assertTrue(restored.replacedExisting());
            assertTrue(restored.lowersSaveSeq(), "save_seq 3 replaced by 2");
        }
        assertArrayEquals(backedUp, Files.readAllBytes(source));
        assertArrayEquals(newer, Files.readAllBytes(source.resolveSibling("vault.pmv.bak.1")));
    }

    @Test
    void unreadableExistingVaultCanBeReplacedWithConfirmation() throws IOException, VaultException {
        Path backup = service(T).create(created.vault(), backups, 3).file();
        Path target = dir.resolve("other/vault.pmv");
        try (VaultFileStore store = VaultFileStore.open(target)) {
            store.writeAtomically(new byte[] {1, 2, 3});
        } catch (StorageException e) {
            throw new AssertionError(e);
        }
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            VaultBackups.Restored restored = service(T).restore(backup, target, pw, true);
            assertEquals(new VaultBackups.Restored(restored.info(), true, false), restored);
        }
        assertArrayEquals(new byte[] {1, 2, 3}, Files.readAllBytes(target.resolveSibling("vault.pmv.bak.1")));
    }

    @Test
    void writeFailureDuringRestoreLeavesTheTargetUnchangedAndNoPartialFile() throws IOException, VaultException {
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
        Path backup = service(T).create(created.vault(), backups, 3).file();
        Path targetDir = dir.resolve("ro");
        Path target = targetDir.resolve("vault.pmv");
        VaultBackups readOnlyAfterOpen = new VaultBackups(Fixtures.CLOCK, MigrationRegistry.PRODUCTION,
                PayloadCodec.RECORDS, path -> {
                    VaultFileStore store = VaultFileStore.open(path);
                    try {
                        Files.setPosixFilePermissions(targetDir, PosixFilePermissions.fromString("r-x------"));
                    } catch (IOException e) {
                        store.close();
                        throw new AssertionError(e);
                    }
                    return store;
                });
        try (SecretChars pw = Fixtures.chars(Formats.GOLDEN_PHRASE)) {
            assertCode(VaultException.Code.STORAGE, () -> readOnlyAfterOpen.restore(backup, target, pw, false));
            assertFalse(Files.exists(target, LinkOption.NOFOLLOW_LINKS));
            assertNoStaging(targetDir);

            Files.setPosixFilePermissions(targetDir, PosixFilePermissions.fromString("rwx------"));
            Files.write(target, new byte[] {7});
            OwnerOnly.apply(target);
            assertCode(VaultException.Code.STORAGE, () -> readOnlyAfterOpen.restore(backup, target, pw, true));
            assertArrayEquals(new byte[] {7}, Files.readAllBytes(target));
            assertNoStaging(targetDir);
        } catch (StorageException e) {
            throw new AssertionError(e);
        } finally {
            Files.setPosixFilePermissions(targetDir, PosixFilePermissions.fromString("rwx------"));
        }
    }

    @Test
    void aThousandBackupsInOneSecondLeaveNoNameForTheNext() throws IOException, StorageException {
        Files.createDirectories(backups);
        OwnerOnly.apply(backups);
        for (int counter = 0; counter < 1000; counter++) {
            Path taken = backups.resolve(String.format(java.util.Locale.ROOT,
                    "pm-backup-20261003T080910Z-%03d.pmbackup", counter));
            Files.write(taken, new byte[] {1});
            OwnerOnly.apply(taken);
        }
        assertCode(VaultException.Code.STORAGE, () -> service(T).create(created.vault(), backups, 3));
    }

    // ---- rotation ----------------------------------------------------------------------------

    @Test
    void rotationKeepsTheNewestNAndOnlyTouchesBackups() throws IOException, StorageException, VaultException {
        Files.createDirectories(backups);
        OwnerOnly.apply(backups);
        Path unrelated = backups.resolve("notes.txt");
        Path lookalike = backups.resolve("pm-backup-manual.pmbackup");
        Files.write(unrelated, new byte[] {1});
        Files.write(lookalike, new byte[] {2});

        List<Path> made = new ArrayList<>();
        List<Path> removed = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            VaultBackups.Created c = service(T.plusSeconds(i)).create(created.vault(), backups, 3);
            made.add(c.file());
            removed.addAll(c.rotation().removed());
            assertTrue(service(T).list(backups).size() <= 3);
        }
        assertEquals(made.subList(0, 2), removed);
        assertEquals(made.subList(2, 5), service(T).list(backups));
        assertTrue(Files.exists(unrelated) && Files.exists(lookalike));
        for (Path kept : made.subList(2, 5)) {
            assertOwnerOnly(kept);
        }

        assertEquals(made.subList(2, 4), service(T).rotate(backups, 1).removed());
        assertEquals(made.subList(4, 5), service(T).list(backups));
        assertThrows(IllegalArgumentException.class, () -> service(T).rotate(backups, 0));
        assertThrows(IllegalArgumentException.class, () -> service(T).create(created.vault(), backups, 0));
    }

    @Test
    void backupsInTheSameSecondGetDistinctNamesAndTheNewOneIsNeverRotatedOut() throws VaultException {
        Path first = service(T).create(created.vault(), backups, 1).file();
        VaultBackups.Created second = service(T).create(created.vault(), backups, 1);
        assertEquals("pm-backup-20261003T080910Z-001.pmbackup", String.valueOf(second.file().getFileName()));
        assertEquals(List.of(first), second.rotation().removed());
        assertEquals(List.of(second.file()), service(T).list(backups));
        // A clock that went backwards: the new backup sorts first but still survives.
        VaultBackups.Created earlier = service(T.minusSeconds(60)).create(created.vault(), backups, 1);
        assertEquals(List.of(second.file()), earlier.rotation().removed());
        assertEquals(List.of(earlier.file()), service(T).list(backups));
    }

    @Test
    void backupNamedFileThatIsNotOwnerOnlyIsSkippedNotFatal() throws IOException, VaultException {
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
        Path old = service(T.minusSeconds(10)).create(created.vault(), backups, 3).file();
        Files.setPosixFilePermissions(old, PosixFilePermissions.fromString("rw-rw----"));

        VaultBackups.Created made = service(T).create(created.vault(), backups, 1);
        assertTrue(Files.exists(made.file()));
        assertEquals(new VaultBackups.Rotation(List.of(), List.of(old), true), made.rotation());
        assertEquals(List.of(made.file()), service(T).list(backups), "list applies the same check");
        assertTrue(Files.exists(old), "never deleted");

        VaultBackups.Created next = service(T.plusSeconds(1)).create(created.vault(), backups, 1);
        assertEquals(new VaultBackups.Rotation(List.of(made.file()), List.of(old), true), next.rotation());
    }

    @Test
    void futureDatedAndImpossiblyDatedBackupsRotateFirst() throws IOException, StorageException, VaultException {
        Path skewed = service(Instant.parse("2099-01-01T00:00:00Z")).create(created.vault(), backups, 5).file();
        Path impossible = skewed.resolveSibling("pm-backup-20261399T000000Z-000.pmbackup");
        Files.copy(skewed, impossible);
        OwnerOnly.apply(impossible);
        Path a = service(T).create(created.vault(), backups, 5).file();
        Path b = service(T.plusSeconds(1)).create(created.vault(), backups, 5).file();

        VaultBackups.Created c = service(T.plusSeconds(2)).create(created.vault(), backups, 3);
        assertEquals(List.of(impossible, skewed), c.rotation().removed());
        assertEquals(List.of(a, b, c.file()), service(T).list(backups));
        // Within a day of now is not misdated.
        assertFalse(VaultBackups.misdated("pm-backup-20261004T080910Z-000.pmbackup", T.getEpochSecond()));
        assertTrue(VaultBackups.misdated("pm-backup-20261004T080911Z-000.pmbackup", T.getEpochSecond()));
    }

    @Test
    void createdTimeOutsideTheInstantRangeIsCorrupt() throws IOException, CborException, VaultException {
        Path backup = service(T).create(created.vault(), backups, 3).file();
        byte[] good = Files.readAllBytes(backup);
        int headerLength = ByteBuffer.wrap(good).getInt(10);
        CborValue.MapV header = (CborValue.MapV) CborReader.decode(
                Arrays.copyOfRange(good, 14, 14 + headerLength), CborLimits.HEADER);
        for (long created : new long[] {BackupFormat.MAX_CREATED + 1, Long.MAX_VALUE}) {
            Map<String, CborValue> entries = new HashMap<>(header.entries());
            entries.put("created", new CborValue.UInt(created));
            byte[] forgedHeader = CborWriter.encode(new CborValue.MapV(entries), CborLimits.HEADER);
            ByteBuffer out = ByteBuffer.allocate(good.length - headerLength + forgedHeader.length);
            out.put(good, 0, 10).putInt(forgedHeader.length).put(forgedHeader)
                    .put(good, 14 + headerLength, good.length - 14 - headerLength);
            Path bad = dir.resolve("late.pmbackup");
            Files.write(bad, out.array());
            assertCode(VaultException.Code.CORRUPT, () -> service(T).inspect(bad));
        }
        assertThrows(IllegalArgumentException.class, () -> new BackupFormat.Header(BackupFormat.MAX_CREATED + 1, 1, 0,
                new CborValue.Bytes(new byte[32]), new CborValue.Bytes(new byte[32])));
    }

    @Test
    void missingBackupDirectoryListsNothingAndInsecureOneIsRefused() throws IOException, VaultException {
        assertEquals(List.of(), service(T).list(dir.resolve("none")));
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
        Path open = dir.resolve("shared");
        Files.createDirectory(open);
        Files.setPosixFilePermissions(open, PosixFilePermissions.fromString("rwxrwx---"));
        assertCode(VaultException.Code.STORAGE, () -> service(T).create(created.vault(), open, 3));
        assertCode(VaultException.Code.STORAGE, () -> service(T).list(open));
        try (Stream<Path> entries = Files.list(open)) {
            assertEquals(0, entries.count());
        }
    }

    // ---- helpers -----------------------------------------------------------------------------

    private static VaultBackups service(Instant now) {
        return new VaultBackups(Clock.fixed(now, ZoneOffset.UTC));
    }

    private static boolean inspectFails(Path backup) {
        try {
            service(T).inspect(backup);
            return false;
        } catch (VaultException e) {
            assertTrue(Set.of(VaultException.Code.CORRUPT, VaultException.Code.UNSUPPORTED_VERSION).contains(e.code()));
            return true;
        }
    }

    private static void assertCode(VaultException.Code expected, Executable action) {
        assertEquals(expected, assertThrows(VaultException.class, action).code());
    }

    private static void assertOwnerOnly(Path path) {
        try {
            assertTrue(OwnerOnly.isOwnerOnly(path), path::toString);
        } catch (StorageException e) {
            throw new AssertionError(e);
        }
    }

    private static void assertNoStaging(Path directory) throws IOException {
        try (Stream<Path> entries = Files.list(directory)) {
            assertFalse(entries.anyMatch(p -> String.valueOf(p.getFileName()).endsWith(".tmp")));
        }
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
