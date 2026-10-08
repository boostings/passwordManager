package pm.vault;

import java.util.List;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.Aead;
import pm.crypto.CryptoException;
import pm.crypto.KeyWrap;
import pm.crypto.RecoveryKey;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.envelope.EnvelopeHeader;
import pm.vault.envelope.KdfHeader;
import pm.vault.envelope.ParsedEnvelope;
import pm.vault.envelope.SlotHeader;
import pm.vault.record.RecordException;
import pm.vault.record.VaultRecord;
import pm.vault.slot.SlotCrypto;

/**
 * Reads a vault file of any version this build supports (ADR 0003, ADR 0015). Shared by unlock,
 * migration and backup verification so all three apply the same order:
 * <ol>
 *   <li>structural decode at the file's own version; a newer version, or an older one with no
 *       registered migration chain, is {@code UNSUPPORTED_VERSION} (SR-701);</li>
 *   <li>slot unwrap of the VK ({@code WRONG_CREDENTIAL} on failure);</li>
 *   <li>AES-GCM open over the AAD, which includes the version ({@code CORRUPT} on failure);</li>
 *   <li>only then the migration chain and the record decode (SR-020).</li>
 * </ol>
 */
final class VaultReader {

    private final MigrationRegistry migrations;
    private final PayloadCodec codec;

    VaultReader(MigrationRegistry migrations, PayloadCodec codec) {
        this.migrations = Objects.requireNonNull(migrations, "migrations");
        this.codec = Objects.requireNonNull(codec, "codec");
    }

    /** A structurally valid, unauthenticated file and the version it was parsed at. */
    record Envelope(int version, ParsedEnvelope parsed) {
        /** Rejects a null envelope. */
        Envelope {
            Objects.requireNonNull(parsed, "parsed");
        }

        /** Returns the unauthenticated header. */
        EnvelopeHeader header() {
            return parsed.header();
        }

        /** Returns whether this file predates the current format. */
        boolean needsMigration() {
            return version < EnvelopeCodec.VERSION;
        }
    }

    /**
     * Returns the file's format version after checking the frozen prefix only.
     *
     * @throws VaultException {@code CORRUPT} for a short file or wrong magic
     */
    static int versionOf(byte[] file) throws VaultException {
        return EnvelopeCodec.peekVersion(file);
    }

    /**
     * Structural decode at the file's own version.
     *
     * @throws VaultException {@code UNSUPPORTED_VERSION} if this build cannot read the version
     *                        (newer: downgrade refused; older: no migration chain), otherwise
     *                        {@code CORRUPT}
     */
    Envelope parse(byte[] file) throws VaultException {
        int version = versionOf(file);
        if (!migrations.canRead(version)) {
            throw new VaultException(VaultException.Code.UNSUPPORTED_VERSION, null);
        }
        return new Envelope(version, EnvelopeCodec.decode(file, version));
    }

    /**
     * Authenticates the payload, runs the migration chain from the file's version, and decodes
     * the records with the current codec. Nothing is parsed before the tag verifies (SR-020).
     *
     * @param env parsed file
     * @param vk  vault key; not closed
     * @return the records, owned by the caller
     * @throws VaultException {@code CORRUPT} if authentication, a migration step or the decode
     *                        fails
     */
    List<VaultRecord> records(Envelope env, SecretBytes vk) throws VaultException {
        try (SecretBytes payload = currentPayload(env, vk)) {
            return codec.decode(payload);
        } catch (RecordException | IllegalArgumentException | IllegalStateException e) {
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
    }

    /** Opens the payload, then applies each step; intermediate payloads are closed. */
    private SecretBytes currentPayload(Envelope env, SecretBytes vk) throws VaultException, RecordException {
        SecretBytes current;
        try (SecretBytes dk = Vault.dataKey(vk, env.parsed().dataSalt())) {
            current = Aead.openWithFreshKey(dk, env.parsed().ciphertext(), env.parsed().aad());
        } catch (CryptoException e) {
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
        for (Migration step : migrations.chainFrom(env.version())) {
            try (SecretBytes previous = current) {
                current = step.apply(previous);
            }
        }
        return current;
    }

    /**
     * Derives the VK from the master passphrase: Argon2id to completion, then AES-KWP unwrap.
     *
     * @param header parsed header; {@code decode} guarantees exactly one passphrase slot
     * @param pw     passphrase; not closed
     * @return the VK, owned by the caller
     * @throws VaultException {@code WRONG_CREDENTIAL}, {@code INSUFFICIENT_MEMORY} or
     *                        {@code CORRUPT}
     */
    static SecretBytes keyFromPassphrase(EnvelopeHeader header, SecretChars pw) throws VaultException {
        Objects.requireNonNull(pw, "pw");
        SlotHeader slot = header.firstSlot(SlotHeader.MASTER);
        try (SecretBytes kek = passphraseKek(pw, header.kdf(), slot.id())) {
            return unwrap(kek, slot);
        } catch (CryptoException e) {
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
    }

    /**
     * Derives the VK from the recovery key. A key that fails to parse is {@code WRONG_CREDENTIAL}
     * whose cause is the {@code BAD_INPUT} {@link CryptoException}; so is a vault with no recovery
     * slot.
     *
     * @param header parsed header
     * @param typed  typed recovery key; not closed
     * @return the VK, owned by the caller
     */
    static SecretBytes keyFromRecovery(EnvelopeHeader header, SecretChars typed) throws VaultException {
        Objects.requireNonNull(typed, "typed");
        SlotHeader slot = header.firstSlot(SlotHeader.RECOVERY);
        try (SecretBytes rk = parseRecoveryKey(typed)) {
            if (slot == null) {
                throw new VaultException(VaultException.Code.WRONG_CREDENTIAL, null);
            }
            try (SecretBytes kek = SlotCrypto.kekFromRecovery(rk, slot.id())) {
                return unwrap(kek, slot);
            }
        } catch (CryptoException e) {
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
    }

    /**
     * Derives the passphrase KEK. {@code EnvelopeCodec.decode} and {@code Argon2Params} already
     * bound m, t and p, so the only {@code BAD_PARAMS} left is {@code Kdf} refusing an Argon2id run
     * larger than the free heap (ADR 0007). That is a JVM sizing problem, not a corrupt vault.
     */
    static SecretBytes passphraseKek(SecretChars pw, KdfHeader kdfHeader, UUID slot)
            throws VaultException, CryptoException {
        try {
            return SlotCrypto.kekFromPassphrase(pw, kdfHeader, slot);
        } catch (CryptoException e) {
            if (e.code() == CryptoException.Code.BAD_PARAMS) {
                throw new VaultException(VaultException.Code.INSUFFICIENT_MEMORY, e);
            }
            throw e;
        }
    }

    /** Unwraps the vault key; package-private so tests can hand it a malformed slot. */
    static SecretBytes unwrap(SecretBytes kek, SlotHeader slot) throws VaultException, CryptoException {
        SecretBytes vk;
        try {
            vk = KeyWrap.unwrap(kek, slot.wrappedKey());
        } catch (CryptoException e) {
            if (e.code() == CryptoException.Code.AUTH_FAILED) {
                throw new VaultException(VaultException.Code.WRONG_CREDENTIAL, e);
            }
            throw e;
        }
        if (vk.length() != Vault.KEY_LENGTH) {
            vk.close();
            throw new VaultException(VaultException.Code.CORRUPT, null);
        }
        return vk;
    }

    private static SecretBytes parseRecoveryKey(SecretChars chars) throws VaultException {
        try {
            return RecoveryKey.parse(chars);
        } catch (CryptoException e) {
            throw new VaultException(VaultException.Code.WRONG_CREDENTIAL, e);
        }
    }
}
