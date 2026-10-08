package pm.cli;

import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import pm.approval.AuditEvent;
import pm.approval.AuditException;
import pm.approval.AuditLog;
import pm.crypto.Argon2Params;
import pm.crypto.SecretChars;
import pm.storage.VaultFileStore;
import pm.vault.Vault;
import pm.vault.VaultException;
import pm.vault.VaultService;

/**
 * {@code pm passphrase [--recovery]} and {@code pm recover}: change the master passphrase with
 * {@link VaultService#changePassphrase} (ADR 0004 addendum, SR-130, SR-131, SR-134). The vault
 * layer asks for nothing, so this class adds what it leaves to the caller: the current passphrase
 * or the recovery key unlocks the vault first (a wrong one changes nothing and asks for no new
 * passphrase), the new passphrase is typed twice, the change is audited, and the user is told that
 * earlier {@code .bak} files and backups still open with the old passphrase. Every secret comes
 * from the no-echo prompt and is closed on every path.
 */
final class PassphraseCommands {
    static final String RECOVERY = "--recovery";
    /** The audit kind for a key-slot change (approval-model §7). */
    static final String AUDIT_KIND = "slot";
    static final String CHANGED = "PASSPHRASE_CHANGED";
    static final String CHANGED_WITH_RECOVERY_KEY = "PASSPHRASE_CHANGED_WITH_RECOVERY_KEY";

    private final Function<String, String> properties;
    private final Clock clock;

    PassphraseCommands(Function<String, String> properties, Clock clock) {
        this.properties = Objects.requireNonNull(properties, "properties");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** {@code pm passphrase [--recovery]}. */
    int passphrase(List<String> words, Path vaultPath, ConsoleIo io) throws UsageException, VaultException {
        CommandArgs args = CommandArgs.parse(words, Set.of(RECOVERY), Set.of()).arity(0);
        return change(vaultPath, io, args.has(RECOVERY), "pm passphrase");
    }

    /** {@code pm recover}: the same change, unlocked with the recovery key. */
    int recover(List<String> words, Path vaultPath, ConsoleIo io) throws UsageException, VaultException {
        CommandArgs.parse(words, Set.of(), Set.of()).arity(0);
        return change(vaultPath, io, true, "pm recover");
    }

    private int change(Path vaultPath, ConsoleIo io, boolean withRecoveryKey, String program)
            throws UsageException, VaultException {
        try (VaultFileStore store = FileVaultPort.openExisting(vaultPath)) {
            // The header's own Argon2id parameters are used; this one is never applied (ADR 0007).
            VaultService service = new VaultService(store, clock, Argon2Params.FLOOR);
            try (Vault vault = unlock(service, io, withRecoveryKey);
                    SecretChars fresh = typedTwice(io)) {
                service.changePassphrase(vault, fresh);
            } catch (IllegalArgumentException e) {
                // Nothing was written. Empty and malformed input are refused above; this is the rest.
                throw new UsageException(Messages.MALFORMED_SECRET);
            }
        }
        io.out().println(Messages.CHANGE_DONE.text());
        io.out().println(Messages.CHANGE_OLD_BACKUPS.text());
        return audited(vaultPath, withRecoveryKey ? CHANGED_WITH_RECOVERY_KEY : CHANGED, program, io)
                ? ExitCodes.OK : ExitCodes.NOT_AUDITED;
    }

    private static Vault unlock(VaultService service, ConsoleIo io, boolean withRecoveryKey)
            throws UsageException, VaultException {
        if (withRecoveryKey) {
            try (SecretChars key = Cli.readSecret(io, Messages.PROMPT_RECOVERY_KEY, Messages.EMPTY_RECOVERY_KEY)) {
                return service.unlockWithRecoveryKey(key);
            }
        }
        try (SecretChars current =
                Cli.readSecret(io, Messages.PROMPT_CURRENT_PASSPHRASE, Messages.EMPTY_PASSPHRASE)) {
            return service.unlockWithPassphrase(current);
        }
    }

    /** The new passphrase, typed twice and compared in constant time; the copy is closed. */
    private static SecretChars typedTwice(ConsoleIo io) throws UsageException {
        SecretChars first = Cli.readSecret(io, Messages.PROMPT_NEW_PASSPHRASE, Messages.EMPTY_PASSPHRASE);
        try (SecretChars second = Cli.readSecret(io, Messages.PROMPT_REPEAT_PASSPHRASE, Messages.EMPTY_PASSPHRASE)) {
            if (!Cli.sameSecret(first, second)) {
                throw new UsageException(Messages.CHANGE_MISMATCH);
            }
            return first;
        } catch (UsageException | RuntimeException e) {
            first.close();
            throw e;
        }
    }

    /**
     * Appends the change to the vault's audit log. The passphrase has already changed, so a
     * failure says so rather than that nothing happened, and the command exits
     * {@link ExitCodes#NOT_AUDITED}, never a code that reads as "not changed".
     *
     * @return whether the entry was written
     */
    private boolean audited(Path vaultPath, String decision, String program, ConsoleIo io) {
        Path dir = Objects.requireNonNull(vaultPath.toAbsolutePath().getParent(), "vault dir");
        try {
            AuditLog.append(dir.resolve(AuditLog.FILE_NAME), clock, new AuditEvent(AUDIT_KIND, Optional.empty(),
                    Optional.of("CLI"), Optional.ofNullable(properties.apply("user.name")), Optional.empty(),
                    Optional.empty(), -1, Optional.of(decision), Optional.of(program)));
            return true;
        } catch (AuditException e) {
            io.err().println(Messages.CHANGE_AUDIT_FAILED.text());
            return false;
        }
    }
}
