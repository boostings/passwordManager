package pm.vault;

import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import pm.crypto.Aead;
import pm.crypto.Argon2Params;
import pm.crypto.CryptoException;
import pm.crypto.Csprng;
import pm.crypto.KeyWrap;
import pm.crypto.RecoveryKey;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.storage.StorageException;
import pm.storage.VaultFileStore;
import pm.vault.envelope.EnvelopeCodec;
import pm.vault.envelope.EnvelopeHeader;
import pm.vault.envelope.KdfHeader;
import pm.vault.envelope.ParsedEnvelope;
import pm.vault.envelope.SlotHeader;
import pm.vault.record.RecordException;
import pm.vault.record.VaultRecord;
import pm.vault.slot.SlotCrypto;

/**
 * Creates and unlocks the vault file behind one {@link VaultFileStore} (ADR 0003, ADR 0004).
 *
 * <p>Unlock order is fixed and security-relevant:
 * <ol>
 *   <li>Structural decode of the envelope; failures are {@code CORRUPT} or
 *       {@code UNSUPPORTED_VERSION} and reveal nothing about the credential.</li>
 *   <li>KEK derivation. For a passphrase this runs Argon2id to completion every time.</li>
 *   <li>AES-KWP unwrap of the VK. An integrity failure is {@code WRONG_CREDENTIAL}.</li>
 *   <li>DK = HKDF(VK, dataSalt, "pm/data/v1"), then AES-GCM open over the AAD. A tag
 *       failure is {@code CORRUPT}.</li>
 *   <li>Only after the tag verifies are the records decoded (SR-020).</li>
 * </ol>
 *
 * <p>Internal crypto failures (for example HKDF or wrap errors) have no dedicated code in
 * the frozen contract. They surface as {@code CORRUPT}, with the {@link CryptoException}
 * code in the cause. Messages never carry key material or paths (SR-501).
 */
public final class VaultService {

    private final VaultFileStore store;
    private final Clock clock;
    private final Argon2Params kdf;
    private final PayloadCodec codec;

    /**
     * Creates a service for one vault file.
     *
     * @param store open file store for the vault path
     * @param clock source of {@code created}/{@code saved} timestamps
     * @param kdf   Argon2id parameters for new vaults; production passes
     *              {@code Kdf.tune(500 ms)}, tests pass {@link Argon2Params#FLOOR}
     */
    public VaultService(VaultFileStore store, Clock clock, Argon2Params kdf) {
        this(store, clock, kdf, PayloadCodec.RECORDS);
    }

    /** Test seam: injects the payload codec. */
    VaultService(VaultFileStore store, Clock clock, Argon2Params kdf, PayloadCodec codec) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.kdf = Objects.requireNonNull(kdf, "kdf");
        this.codec = Objects.requireNonNull(codec, "codec");
        if (kdf.parallelism() > EnvelopeCodec.MAX_PARALLELISM) {
            throw new IllegalArgumentException("parallelism");
        }
    }

    /**
     * Creates a new vault with a passphrase slot and a recovery slot, then saves it with
     * {@code save_seq = 1}.
     *
     * @param pw master passphrase; not closed by this method
     * @return the unlocked vault and the formatted recovery key, both owned by the caller
     * @throws VaultException {@code ALREADY_EXISTS} if a vault file exists, {@code STORAGE}
     *                        if the write fails
     */
    public CreatedVault create(SecretChars pw) throws VaultException {
        Objects.requireNonNull(pw, "pw");
        if (store.exists()) {
            throw new VaultException(VaultException.Code.ALREADY_EXISTS, null);
        }
        long now = epochSeconds(clock);
        UUID masterSlot = Csprng.uuid();
        UUID recoverySlot = Csprng.uuid();
        KdfHeader kdfHeader = new KdfHeader(EnvelopeCodec.KDF_ALG,
                kdf.memoryKiB(), kdf.iterations(), kdf.parallelism(),
                Csprng.bytes(EnvelopeCodec.SALT_LENGTH));
        try (SecretBytes vk = Csprng.secretBytes(Vault.KEY_LENGTH);
             SecretBytes rk = RecoveryKey.generate();
             SecretBytes kekP = SlotCrypto.kekFromPassphrase(pw, kdfHeader, masterSlot);
             SecretBytes kekR = SlotCrypto.kekFromRecovery(rk, recoverySlot)) {
            List<SlotHeader> slots = List.of(
                    new SlotHeader(masterSlot, SlotHeader.MASTER, KeyWrap.wrap(kekP, vk)),
                    new SlotHeader(recoverySlot, SlotHeader.RECOVERY, KeyWrap.wrap(kekR, vk)));
            // save_seq 0 is never written: the first save() bumps it to 1.
            EnvelopeHeader header = new EnvelopeHeader(kdfHeader, slots, now, now, 0L);
            return saveNew(new Vault(store, clock, codec, header, vk, List.of()), rk);
        } catch (CryptoException e) {
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
    }

    /**
     * Unlocks with the master passphrase.
     *
     * @param pw master passphrase; not closed by this method
     * @return the unlocked vault, owned by the caller
     * @throws VaultException {@code WRONG_CREDENTIAL}, {@code CORRUPT},
     *                        {@code UNSUPPORTED_VERSION} or {@code STORAGE}
     */
    public Vault unlockWithPassphrase(SecretChars pw) throws VaultException {
        Objects.requireNonNull(pw, "pw");
        ParsedEnvelope env = EnvelopeCodec.decode(readFile());
        EnvelopeHeader header = env.header();
        // decode() guarantees exactly one passphrase slot.
        SlotHeader slot = header.firstSlot(SlotHeader.MASTER);
        try (SecretBytes kek = SlotCrypto.kekFromPassphrase(pw, header.kdf(), slot.id());
             SecretBytes vk = unwrap(kek, slot)) {
            return open(env, vk);
        } catch (CryptoException e) {
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
    }

    /**
     * Unlocks with the recovery key. A key that fails to parse (typo, bad checksum) is
     * {@code WRONG_CREDENTIAL} whose cause is the {@code BAD_INPUT} {@link CryptoException}.
     *
     * @param typed the typed recovery key; not closed by this method
     * @return the unlocked vault, owned by the caller
     * @throws VaultException {@code WRONG_CREDENTIAL}, {@code CORRUPT},
     *                        {@code UNSUPPORTED_VERSION} or {@code STORAGE}
     */
    public Vault unlockWithRecoveryKey(SecretChars typed) throws VaultException {
        Objects.requireNonNull(typed, "typed");
        ParsedEnvelope env = EnvelopeCodec.decode(readFile());
        SlotHeader slot = env.header().firstSlot(SlotHeader.RECOVERY);
        try (SecretBytes rk = parseRecoveryKey(typed)) {
            if (slot == null) {
                throw new VaultException(VaultException.Code.WRONG_CREDENTIAL, null);
            }
            try (SecretBytes kek = SlotCrypto.kekFromRecovery(rk, slot.id());
                 SecretBytes vk = unwrap(kek, slot)) {
                return open(env, vk);
            }
        } catch (CryptoException e) {
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
    }

    /**
     * Opens a vault file at the VK layer, skipping slot unwrap. Test seam for TamperTest,
     * which flips every byte without paying for Argon2 each time.
     *
     * @param file complete file bytes
     * @param vk   vault key; copied, the caller keeps ownership
     */
    Vault openWithVaultKey(byte[] file, SecretBytes vk) throws VaultException {
        return open(EnvelopeCodec.decode(file), vk);
    }

    /** Returns the clock time in epoch seconds; a clock before 1970 is a configuration error. */
    static long epochSeconds(Clock clock) {
        long now = clock.instant().getEpochSecond();
        if (now < 0) {
            throw new IllegalStateException("clock before epoch");
        }
        return now;
    }

    /**
     * Authenticates, then decodes. No record byte is parsed unless the GCM tag verified
     * (SR-020). A record that fails its own validation after authentication is CORRUPT.
     */
    private Vault open(ParsedEnvelope env, SecretBytes vk) throws VaultException {
        List<VaultRecord> decoded;
        try (SecretBytes dk = Vault.dataKey(vk, env.dataSalt());
             SecretBytes plaintext = Aead.openWithFreshKey(dk, env.ciphertext(), env.aad())) {
            decoded = codec.decode(plaintext);
        } catch (CryptoException | RecordException | IllegalArgumentException e) {
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
        try {
            return new Vault(store, clock, codec, env.header(), vk, decoded);
        } catch (IllegalArgumentException e) {
            decoded.forEach(VaultRecord::close);
            throw new VaultException(VaultException.Code.CORRUPT, e);
        }
    }

    /** Saves a freshly created vault; locks it again if anything fails. */
    private CreatedVault saveNew(Vault vault, SecretBytes rk) throws VaultException {
        try {
            vault.save();
            return new CreatedVault(vault, RecoveryKey.format(rk));
        } catch (VaultException | RuntimeException e) {
            vault.close();
            throw e;
        }
    }

    private static SecretBytes unwrap(SecretBytes kek, SlotHeader slot) throws VaultException, CryptoException {
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

    private byte[] readFile() throws VaultException {
        try {
            return store.readAll();
        } catch (StorageException e) {
            throw new VaultException(VaultException.Code.STORAGE, e);
        }
    }
}
