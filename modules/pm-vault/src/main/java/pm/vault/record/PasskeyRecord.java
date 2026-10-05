package pm.vault.record;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;
import pm.crypto.passkey.PasskeyKey;
import pm.crypto.passkey.storage.PasskeyStorage;
import pm.vault.internal.PasskeyRecordAccess;

/**
 * A WebAuthn passkey credential (ADR 0016 addendum, {@code passkey-record} in
 * {@code docs/schemas/records.cddl}, SR-085).
 *
 * <p>The private key is the 98-byte storage form of {@link PasskeyStorage}, held only in a
 * {@link SecretBytes} owned by this record and zero-filled by {@link #close()}. It never becomes a
 * {@code String}, and {@link #toString()} shows no key material and no identifying bytes.
 *
 * <p><b>Vault-owned (SR-085).</b> The constructor is package-private, so no other module can build
 * a passkey record, and no public method returns or encodes the key: only {@code pm.vault}
 * reads it, through the unexported {@code pm.vault.internal.PasskeyRecordAccess}, and the public
 * {@link RecordCodec} refuses passkey records ({@code VAULT_ONLY}). A record handed out by
 * {@code Vault.records()} or to an {@code AssertionPort} is a <em>view</em>: the same public
 * fields with no key, so closing it or putting it back cannot change the vault's key or counter
 * (SR-080, SR-402). The counter only advances in {@code pm.vault.Vault#signWithPasskey}.
 *
 * <p>Not a Java {@code record}: the credential ID and user handle are byte arrays, which are
 * copied in and out here (OBJ05-J, OBJ06-J). Equality is identity, as for every record that holds
 * a secret.
 */
public final class PasskeyRecord implements VaultRecord {
    /** Shortest credential ID accepted (WebAuthn recommends at least 16 bytes of entropy). */
    public static final int MIN_CREDENTIAL_ID_BYTES = 16;
    /** Longest credential ID (WebAuthn Level 3: at most 1023 bytes). */
    public static final int MAX_CREDENTIAL_ID_BYTES = 1023;
    /** Shortest user handle (WebAuthn: the user handle must not be empty). */
    public static final int MIN_USER_HANDLE_BYTES = 1;
    /** Longest user handle (WebAuthn: at most 64 bytes). */
    public static final int MAX_USER_HANDLE_BYTES = 64;
    /** Longest RP ID (RFC 1035 host name). */
    public static final int MAX_RP_ID_CHARS = 253;
    /** Longest user name or display name, in UTF-16 code units. */
    public static final int MAX_NAME_CHARS = 256;
    /** Largest signature counter: the counter is an unsigned 32-bit value in authenticator data. */
    public static final long MAX_SIGN_COUNT = 0xFFFF_FFFFL;
    /** Length of the stored private key (the {@link PasskeyStorage} form). */
    public static final int PRIVATE_KEY_BYTES = PasskeyStorage.STORAGE_BYTES;

    /** One LDH label, lower case, no leading or trailing hyphen (RFC 1035, A-labels included). */
    private static final Pattern LABEL = Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");
    private static final Pattern NUMERIC = Pattern.compile("[0-9]+");
    private static final String LABEL_SEPARATOR = "\\.";
    /**
     * Letters and symbols that render as nothing: the Hangul fillers, the braille blank and the
     * blank musical noteheads. Excluded from the visible set even though their category is L or S.
     */
    private static final Set<Integer> BLANK_LETTERS =
            Set.of(0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x1D159, 0x1D15A);

    static {
        // The key and the counter advance cross into pm.vault only through this unexported hook.
        PasskeyRecordAccess.install(new Hook());
    }

    private final UUID idValue;
    private final String titleValue;
    private final String rpIdValue;
    private final byte[] credentialIdValue;
    private final byte[] userHandleValue;
    private final String accountNameValue;
    private final String displayNameValue;
    private final SecretBytes privateKeyValue;
    private final long signCountValue;
    private final Instant createdValue;
    private final Instant updatedValue;
    private final Instant lastUsedValue;

    /**
     * Validates every field and copies the byte arrays (MET00-J, OBJ06-J). The record takes
     * ownership of {@code privateKey}.
     *
     * @param id record identity
     * @param title display title, at most 256 characters
     * @param rpId relying-party ID: a lower-case ASCII host name (internationalised names only as
     *     {@code xn--} A-labels), at most 253 characters, no trailing dot, not an IP address
     * @param credentialId credential ID, 16 to 1023 bytes; copied
     * @param userHandle WebAuthn user handle, 1 to 64 bytes; copied
     * @param accountName account name (WebAuthn {@code user.name}), at most 256 characters, no
     *     control, format or separator characters (see {@link #displaySafe}), and at least one
     *     visible character
     * @param displayName account display name, same rules as {@code accountName} except that it
     *     may be empty
     * @param privateKey the 98-byte {@link PasskeyStorage} form; owned by this record. A closed
     *     secret makes a keyless view
     * @param signCount signature counter, 0 to 2^32 - 1
     * @param created creation time, truncated to whole seconds
     * @param updated last edit, truncated to whole seconds
     * @param lastUsed last assertion, truncated to whole seconds
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if a field is out of bounds; the message names the field,
     *     never its content
     */
    PasskeyRecord(UUID id, String title, String rpId, byte[] credentialId, byte[] userHandle,
                         String accountName, String displayName, SecretBytes privateKey, long signCount,
                         Instant created, Instant updated, Instant lastUsed) {
        this.idValue = Objects.requireNonNull(id, "id");
        this.titleValue = FieldRules.text(title, FieldRules.MAX_TITLE_CHARS, "title");
        this.rpIdValue = checkRpId(rpId);
        this.credentialIdValue = bytes(credentialId, MIN_CREDENTIAL_ID_BYTES, MAX_CREDENTIAL_ID_BYTES, "credentialId");
        this.userHandleValue = bytes(userHandle, MIN_USER_HANDLE_BYTES, MAX_USER_HANDLE_BYTES, "userHandle");
        this.accountNameValue = visibleName(accountName, "accountName");
        this.displayNameValue = Objects.requireNonNull(displayName, "displayName").isEmpty()
                ? displayName : visibleName(displayName, "displayName");
        this.privateKeyValue = key(privateKey);
        this.signCountValue = count(signCount);
        this.createdValue = FieldRules.instant(created, "created");
        this.updatedValue = FieldRules.instant(updated, "updated");
        this.lastUsedValue = FieldRules.instant(lastUsed, "lastUsed");
    }

    /**
     * A copy of this record with the counter and last-use time advanced and its own copy of the
     * key. Reached only through {@link PasskeyRecordAccess}.
     */
    private PasskeyRecord advanced(long nextCount, Instant usedAt) {
        if (nextCount <= signCountValue) {
            throw new IllegalArgumentException("signCount must increase");
        }
        return new PasskeyRecord(idValue, titleValue, rpIdValue, credentialIdValue, userHandleValue,
                accountNameValue, displayNameValue, copyOfKey(), nextCount, createdValue, updatedValue, usedAt);
    }

    /** The public fields of this record with no key: what leaves the vault. */
    private PasskeyRecord view() {
        return new PasskeyRecord(idValue, titleValue, rpIdValue, credentialIdValue, userHandleValue,
                accountNameValue, displayNameValue, noKey(), signCountValue, createdValue, updatedValue,
                lastUsedValue);
    }

    /**
     * This record (the vault's) with the user-editable fields of {@code edit}: title, account
     * name, display name and update time. Identity, key, counter, creation and last use stay
     * this record's, so putting back an old view can never lower the counter.
     */
    private PasskeyRecord editedBy(PasskeyRecord edit) {
        return new PasskeyRecord(idValue, edit.titleValue, rpIdValue, credentialIdValue, userHandleValue,
                edit.accountNameValue, edit.displayNameValue, copyOfKey(), signCountValue, createdValue,
                edit.updatedValue, lastUsedValue);
    }

    private SecretBytes copyOfKey() {
        return privateKeyValue.apply(SecretBytes::copyOf);
    }

    private static SecretBytes noKey() {
        SecretBytes none = SecretBytes.takeOwnership(new byte[PRIVATE_KEY_BYTES]);
        none.close();
        return none;
    }

    /**
     * Whether the stored key is a valid storage form: d in [1, n-1] and d·G equal to the stored
     * point (SR-081). A view has no key and is not valid.
     */
    private boolean keyIsValid() {
        if (privateKeyValue.isClosed()) {
            return false;
        }
        try (PasskeyKey loaded = PasskeyStorage.fromStorage(privateKeyValue)) {
            return loaded != null;
        } catch (CryptoException e) {
            return false;
        }
    }

    /**
     * {@code raw} made safe for a user or display name: every control, format (bidi overrides,
     * zero-width characters), line or paragraph separator and unpaired surrogate code point is
     * dropped, and the result is cut to {@link #MAX_NAME_CHARS} without splitting a surrogate
     * pair. The WebAuthn layer (M6.3) applies this to names a relying party sends before it
     * builds a record; the constructor refuses anything this would change.
     */
    public static String displaySafe(String raw) {
        Objects.requireNonNull(raw, "raw");
        StringBuilder out = new StringBuilder(Math.min(raw.length(), MAX_NAME_CHARS));
        raw.codePoints().filter(cp -> !isUnsafe(cp)).forEach(cp -> {
            if (out.length() + Character.charCount(cp) <= MAX_NAME_CHARS) {
                out.appendCodePoint(cp);
            }
        });
        return out.toString();
    }

    @Override
    public UUID id() {
        return idValue;
    }

    @Override
    public String title() {
        return titleValue;
    }

    /** Returns the relying-party ID. */
    public String rpId() {
        return rpIdValue;
    }

    /** Returns a copy of the credential ID. */
    public byte[] credentialId() {
        return credentialIdValue.clone();
    }

    /** Returns a copy of the user handle. */
    public byte[] userHandle() {
        return userHandleValue.clone();
    }

    /** Returns the account name (WebAuthn {@code user.name}). */
    public String accountName() {
        return accountNameValue;
    }

    /** Returns the account display name (WebAuthn {@code user.displayName}). */
    public String displayName() {
        return displayNameValue;
    }

    /** The private key storage form, owned by this record; for the codec only. */
    SecretBytes privateKey() {
        return privateKeyValue;
    }

    /** Returns the signature counter of the last assertion (0 before the first). */
    public long signCount() {
        return signCountValue;
    }

    @Override
    public Instant created() {
        return createdValue;
    }

    @Override
    public Instant updated() {
        return updatedValue;
    }

    /** Returns when the last assertion was signed, in whole seconds. */
    public Instant lastUsed() {
        return lastUsedValue;
    }

    /** Zero-fills the private key. Idempotent. */
    @Override
    public void close() {
        privateKeyValue.close();
    }

    /** The id, RP ID and counter only: never key material, the credential ID or the user handle. */
    @Override
    public String toString() {
        return "PasskeyRecord[id=" + idValue + ", rpId=" + rpIdValue + ", signCount=" + signCountValue + "]";
    }

    /** The hook handed to {@link PasskeyRecordAccess}; private so no other class can construct it. */
    private static final class Hook implements PasskeyRecordAccess.Hook {
        @Override
        public SecretBytes privateKey(PasskeyRecord record) {
            return record.privateKeyValue;
        }

        @Override
        public PasskeyRecord advanced(PasskeyRecord record, long nextCount, Instant usedAt) {
            return record.advanced(nextCount, usedAt);
        }

        @Override
        public PasskeyRecord view(PasskeyRecord record) {
            return record.view();
        }

        @Override
        public PasskeyRecord edited(PasskeyRecord live, PasskeyRecord edit) {
            return live.editedBy(edit);
        }

        @Override
        public PasskeyRecord create(UUID id, String title, String rpId, byte[] credentialId, byte[] userHandle,
                                    String accountName, String displayName, SecretBytes privateKey, long signCount,
                                    Instant created, Instant updated, Instant lastUsed) {
            return new PasskeyRecord(id, title, rpId, credentialId, userHandle, accountName, displayName, privateKey,
                    signCount, created, updated, lastUsed);
        }

        @Override
        public boolean keyIsValid(PasskeyRecord record) {
            return record.keyIsValid();
        }

        @Override
        public SecretBytes encodeVaultPayload(List<VaultRecord> records) {
            return RecordCodec.encodeVaultPayload(records);
        }

        @Override
        public List<VaultRecord> decodeVaultPayload(SecretBytes plaintext) throws RecordException {
            return RecordCodec.decodeVaultPayload(plaintext);
        }
    }

    private static String checkRpId(String value) {
        Objects.requireNonNull(value, "rpId");
        if (value.length() > MAX_RP_ID_CHARS) {
            throw new IllegalArgumentException("rpId is too long");
        }
        // An empty RP ID, an empty label and a trailing dot all leave an empty label here.
        String[] labels = value.split(LABEL_SEPARATOR, -1);
        for (String label : labels) {
            if (!LABEL.matcher(label).matches()) {
                throw new IllegalArgumentException("rpId is not a canonical host name");
            }
        }
        // A numeric last label means an IPv4 literal (canonical or not); WebAuthn RP IDs are domains.
        String last = labels[labels.length - 1];
        if (NUMERIC.matcher(last).matches()) {
            throw new IllegalArgumentException("rpId is not a canonical host name");
        }
        return value;
    }

    private static byte[] bytes(byte[] value, int min, int max, String field) {
        byte[] copy = Objects.requireNonNull(value, field).clone();
        if (copy.length < min || copy.length > max) {
            throw new IllegalArgumentException(field + " has the wrong length");
        }
        return copy;
    }

    private static String visibleName(String value, String field) {
        FieldRules.text(value, MAX_NAME_CHARS, field);
        if (value.codePoints().anyMatch(PasskeyRecord::isUnsafe)) {
            throw new IllegalArgumentException(field + " has characters that are unsafe to display");
        }
        if (value.codePoints().noneMatch(PasskeyRecord::isVisible)) {
            throw new IllegalArgumentException(field + " has no visible character");
        }
        return value;
    }

    /**
     * Whether {@code codePoint} draws something on its own: an allowlist of the letter, number,
     * punctuation and symbol categories (L, N, P, S), minus {@link #BLANK_LETTERS}. Separators,
     * marks, controls, format characters, unassigned and private-use code points are not visible.
     * A name of only such characters would show as blank and could hide which account a prompt
     * is for.
     */
    private static boolean isVisible(int codePoint) {
        if (BLANK_LETTERS.contains(codePoint)) {
            return false;
        }
        return switch (Character.getType(codePoint)) {
            case Character.UPPERCASE_LETTER, Character.LOWERCASE_LETTER, Character.TITLECASE_LETTER,
                 Character.MODIFIER_LETTER, Character.OTHER_LETTER, Character.DECIMAL_DIGIT_NUMBER,
                 Character.LETTER_NUMBER, Character.OTHER_NUMBER, Character.CONNECTOR_PUNCTUATION,
                 Character.DASH_PUNCTUATION, Character.START_PUNCTUATION, Character.END_PUNCTUATION,
                 Character.INITIAL_QUOTE_PUNCTUATION, Character.FINAL_QUOTE_PUNCTUATION,
                 Character.OTHER_PUNCTUATION, Character.MATH_SYMBOL, Character.CURRENCY_SYMBOL,
                 Character.MODIFIER_SYMBOL, Character.OTHER_SYMBOL -> true;
            default -> false;
        };
    }

    private static SecretBytes key(SecretBytes value) {
        Objects.requireNonNull(value, "privateKey");
        if (!value.isClosed() && value.length() != PRIVATE_KEY_BYTES) {
            throw new IllegalArgumentException("privateKey has the wrong length");
        }
        return value;
    }

    private static long count(long value) {
        if (value < 0 || value > MAX_SIGN_COUNT) {
            throw new IllegalArgumentException("signCount is out of range");
        }
        return value;
    }

    /**
     * Whether {@code codePoint} must not reach a terminal or a prompt: an ISO control, a format
     * character (bidi controls such as U+202E, zero-width U+200B), a line or paragraph separator,
     * or a lone surrogate (IDS01-J, same set as the CLI's list output).
     */
    private static boolean isUnsafe(int codePoint) {
        if (Character.isISOControl(codePoint)) {
            return true;
        }
        int type = Character.getType(codePoint);
        return type == Character.FORMAT || type == Character.LINE_SEPARATOR
                || type == Character.PARAGRAPH_SEPARATOR || type == Character.SURROGATE;
    }
}
