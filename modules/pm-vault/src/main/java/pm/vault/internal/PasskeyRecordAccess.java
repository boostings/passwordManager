package pm.vault.internal;

import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import pm.crypto.SecretBytes;
import pm.vault.record.PasskeyRecord;
import pm.vault.record.RecordException;
import pm.vault.record.VaultRecord;

/**
 * The one link from {@code pm.vault} to the parts of {@link PasskeyRecord} that no other module may
 * use (ADR 0016 addendum, SR-085 to SR-087): the stored private key, the counter advance, the
 * keyless view, the merge of an edit, and the payload codec that may write and read passkey
 * records. {@code PasskeyRecord} installs its hook here from its static initializer. This package
 * is not exported, so the domain, browser, CLI and TUI modules, which receive record views from
 * the vault, can neither read the private scalar nor build or persist a record with a different
 * counter for the same key.
 */
public final class PasskeyRecordAccess {
    private static final AtomicReference<Hook> INSTALLED = new AtomicReference<>();

    private PasskeyRecordAccess() {
    }

    /** The hidden operations of {@link PasskeyRecord}. */
    public interface Hook {
        /** The 98-byte storage form owned by {@code record}; the caller must not close it. */
        SecretBytes privateKey(PasskeyRecord record);

        /**
         * A copy of {@code record} with counter {@code nextCount}, last use {@code usedAt} and its
         * own copy of the key.
         *
         * @throws IllegalArgumentException unless {@code nextCount} is above the current counter
         *     and at most 2^32 - 1
         */
        PasskeyRecord advanced(PasskeyRecord record, long nextCount, Instant usedAt);

        /** The public fields of {@code record} with no key; closing the view changes nothing else. */
        PasskeyRecord view(PasskeyRecord record);

        /**
         * {@code live} with the title, names and update time of {@code edit}, and its own copy of
         * {@code live}'s key; identity, counter, creation and last use stay {@code live}'s.
         */
        PasskeyRecord edited(PasskeyRecord live, PasskeyRecord edit);

        /**
         * A new passkey record (M6.3 enrollment and edits): the package-private constructor, for
         * {@code Vault.createPasskey} and {@code Vault.editPasskey} only. Takes ownership of
         * {@code privateKey}; a closed secret makes a keyless record (an edit).
         *
         * @throws IllegalArgumentException if a field breaks the record's rules; the caller keeps
         *     {@code privateKey} and must close it
         */
        PasskeyRecord create(UUID id, String title, String rpId, byte[] credentialId, byte[] userHandle,
                             String accountName, String displayName, SecretBytes privateKey, long signCount,
                             Instant created, Instant updated, Instant lastUsed);

        /** Whether the stored key loads (d in range, d·G equal to the stored point); false for a view. */
        boolean keyIsValid(PasskeyRecord record);

        /** The vault payload, passkey records included; the caller closes the result. */
        SecretBytes encodeVaultPayload(List<VaultRecord> records);

        /**
         * Decodes the vault payload, passkey records included, with every passkey key checked.
         *
         * @throws RecordException as {@code RecordCodec.decodePayload}
         */
        List<VaultRecord> decodeVaultPayload(SecretBytes plaintext) throws RecordException;
    }

    /**
     * Installs the hook; called once, by {@code PasskeyRecord}'s static initializer.
     *
     * @throws IllegalStateException {@code ALREADY_INSTALLED} on any later call
     */
    public static void install(Hook hook) {
        if (!INSTALLED.compareAndSet(null, Objects.requireNonNull(hook, "hook"))) {
            throw new IllegalStateException("ALREADY_INSTALLED");
        }
    }

    /** The hook, after making sure {@code PasskeyRecord} has been initialized and installed it. */
    public static Hook hook() {
        try {
            MethodHandles.lookup().ensureInitialized(PasskeyRecord.class);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("PASSKEY_RECORD_INIT", e);
        }
        return INSTALLED.get();
    }
}
