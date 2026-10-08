package pm.cli;

import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import pm.crypto.Argon2Params;
import pm.crypto.SecretChars;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.Vault;
import pm.vault.VaultBackups;
import pm.vault.VaultException;
import pm.vault.VaultService;

/**
 * {@code pm backup create}, {@code pm backup verify} and {@code pm restore}: thin wrappers over
 * {@link VaultBackups}, whose semantics they keep exactly (SR-134). Creating unlocks the vault
 * (the backup is of the vault as last saved); verifying writes nothing; restoring verifies first
 * and replaces an existing vault only with {@code --overwrite}, keeping it as {@code <vault>.bak.1}.
 * The passphrase is read from the prompt only and closed here, as the API does not close it.
 */
final class BackupCommands {
    static final String KEEP = "--keep";
    static final String OVERWRITE = "--overwrite";
    static final int DEFAULT_KEEP = 10;
    static final int MAX_KEEP = 999;
    private static final int ONE = 1;
    private static final String BAK_1 = ".bak.1";

    private final Clock clock;

    BackupCommands(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** {@code pm backup create <folder> [--keep <n>]}. */
    int create(List<String> words, Path vaultPath, ConsoleIo io) throws UsageException, VaultException {
        CommandArgs args = CommandArgs.parse(words, Set.of(), Set.of(KEEP)).arity(ONE);
        Path dir = path(args.operand(0));
        int keep = keepCount(args);
        VaultBackups.Created created;
        try (VaultFileStore store = FileVaultPort.openExisting(vaultPath);
                SecretChars passphrase = Cli.readSecret(io, Messages.PROMPT_PASSPHRASE, Messages.EMPTY_PASSPHRASE);
                Vault vault = new VaultService(store, clock, Argon2Params.FLOOR).unlockWithPassphrase(passphrase)) {
            created = new VaultBackups(clock).create(vault, dir, keep);
        }
        io.out().println(Messages.BACKUP_WRITTEN.text() + shown(created.file()));
        created.rotation().removed().forEach(file -> io.out().println(Messages.BACKUP_DELETED.text() + shown(file)));
        created.rotation().skipped().forEach(file -> io.out().println(Messages.BACKUP_LEFT.text() + shown(file)));
        if (!created.rotation().complete()) {
            io.err().println(Messages.BACKUP_OVER_KEEP.text());
        }
        return ExitCodes.OK;
    }

    /** {@code pm backup verify <file>}: authenticates and decodes the whole backup; writes nothing. */
    int verify(List<String> words, ConsoleIo io) throws UsageException, VaultException {
        CommandArgs args = CommandArgs.parse(words, Set.of(), Set.of()).arity(ONE);
        Path backup = path(args.operand(0));
        if (missing(backup, io)) {
            return ExitCodes.STORAGE;
        }
        VaultBackups.Verified verified;
        try (SecretChars passphrase =
                Cli.readSecret(io, Messages.PROMPT_BACKUP_PASSPHRASE, Messages.EMPTY_PASSPHRASE)) {
            verified = new VaultBackups(clock).verify(backup, passphrase);
        } catch (VaultException e) {
            return backupFailure(e, backup, io);
        }
        io.out().println(Messages.BACKUP_VERIFIED.text());
        io.out().println(Messages.BACKUP_MADE.text() + verified.info().created());
        io.out().println(Messages.BACKUP_RECORDS.text() + verified.records());
        return ExitCodes.OK;
    }

    /** {@code pm restore <file> [--overwrite]}: restores to the {@code --vault} path. */
    int restore(List<String> words, Path vaultPath, ConsoleIo io) throws UsageException, VaultException {
        CommandArgs args = CommandArgs.parse(words, Set.of(OVERWRITE), Set.of()).arity(ONE);
        Path backup = path(args.operand(0));
        if (missing(backup, io)) {
            return ExitCodes.STORAGE;
        }
        VaultBackups.Restored restored;
        try (SecretChars passphrase =
                Cli.readSecret(io, Messages.PROMPT_BACKUP_PASSPHRASE, Messages.EMPTY_PASSPHRASE)) {
            restored = new VaultBackups(clock).restore(backup, vaultPath, passphrase, args.has(OVERWRITE));
        } catch (VaultException e) {
            if (e.code() == VaultException.Code.ALREADY_EXISTS) {
                throw new UsageException(Messages.RESTORE_EXISTS);
            }
            return backupFailure(e, backup, io);
        }
        io.out().println(Messages.RESTORED.text() + shown(vaultPath));
        io.out().println(Messages.RESTORE_OPENS_WITH.text());
        if (restored.replacedExisting()) {
            io.out().println(Messages.RESTORE_KEPT.text() + shown(vaultPath) + BAK_1);
        }
        if (restored.lowersSaveSeq()) {
            io.err().println(Messages.RESTORE_ROLLBACK.text());
        }
        return ExitCodes.OK;
    }

    /**
     * Checked before the passphrase prompt and the key derivation (m77-003): a mistyped backup
     * path is named as the backup, not reported as a missing vault after the prompt.
     */
    private static boolean missing(Path backup, ConsoleIo io) {
        if (Files.exists(backup, LinkOption.NOFOLLOW_LINKS)) {
            return false;
        }
        io.err().println(Messages.BACKUP_NOT_FOUND.text() + shown(backup));
        return true;
    }

    /**
     * A damaged, unreadable or missing backup is named as the backup, not the vault, and a vault
     * held by another process gets the shared lock message; every other failure keeps the shared
     * message and exit code.
     */
    private static int backupFailure(VaultException e, Path backup, ConsoleIo io) throws VaultException {
        String message = switch (e.code()) {
            case CORRUPT -> Messages.BACKUP_CORRUPT.text();
            case UNSUPPORTED_VERSION -> Messages.BACKUP_UNSUPPORTED.text();
            case STORAGE -> switch (storageCode(e)) {
                case NOT_FOUND -> Messages.BACKUP_NOT_FOUND.text() + shown(backup);
                case LOCKED_BY_OTHER -> Messages.ERR_LOCKED.text();
                default -> throw e;
            };
            default -> throw e;
        };
        io.err().println(message);
        return ExitCodes.of(e.code());
    }

    /** The storage failure behind a {@code STORAGE} failure, or {@code IO} when there is none. */
    private static StorageException.Code storageCode(VaultException e) {
        return e.getCause() instanceof StorageException se ? se.code() : StorageException.Code.IO;
    }

    private static int keepCount(CommandArgs args) throws UsageException {
        if (args.value(KEEP).isEmpty()) {
            return DEFAULT_KEEP;
        }
        String text = args.value(KEEP).get();
        int keep;
        try {
            keep = Integer.parseInt(text);
        } catch (NumberFormatException e) {
            throw new UsageException(Messages.BAD_KEEP);
        }
        if (keep < ONE || keep > MAX_KEEP) {
            throw new UsageException(Messages.BAD_KEEP);
        }
        return keep;
    }

    private static Path path(String text) throws UsageException {
        try {
            return Path.of(text);
        } catch (InvalidPathException e) {
            throw new UsageException(Messages.BAD_PATH);
        }
    }

    private static String shown(Path path) {
        return Cli.displaySafe(path.toString());
    }
}
