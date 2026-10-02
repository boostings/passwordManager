package pm.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Recovery key (ADR 0004): 32 random bytes plus a 3-byte SHA-256 checksum, shown as 56 base32
 * characters in 8 dash-separated groups of 7.
 *
 * <p>Encoding is RFC 4648 base32 (alphabet {@code A-Z2-7}, no padding), hand-rolled over
 * {@code char[]} so the key never becomes a {@code String} (MSC03-J, ADR 0008). Every buffer this
 * class allocates is zero-filled before return, and the JDK SHA-256 engine's internal block buffer
 * and message schedule are overwritten after use (see {@code sha256OfKey}). Parsing accepts only
 * ASCII letters and digits; non-ASCII look-alikes are rejected.
 *
 * <p>What remains outside our control: the returned {@link SecretBytes}/{@link SecretChars} own
 * their own copies (the caller closes them), and the SHA-256 engine's chaining state holds a hash
 * of the key, not key bytes. The heap-dump harness found no other copy of the key after close.
 */
public final class RecoveryKey {
    private static final int KEY_LEN = 32;
    private static final int CHECKSUM_LEN = 3;
    private static final int RAW_LEN = KEY_LEN + CHECKSUM_LEN;
    private static final int ENCODED_LEN = 56;
    private static final int GROUP_LEN = 7;
    private static final int DISPLAY_LEN = ENCODED_LEN + ENCODED_LEN / GROUP_LEN - 1;
    private static final int BITS_PER_CHAR = 5;
    private static final int BITS_PER_BYTE = 8;
    private static final int CHAR_MASK = 0x1F;
    private static final int BYTE_MASK = 0xFF;
    private static final int DIGIT_OFFSET = 26;
    private static final char SEPARATOR = '-';
    private static final char SPACE = ' ';
    private static final char FIRST_LETTER = 'A';
    private static final char LAST_LETTER = 'Z';
    private static final char FIRST_DIGIT = '2';
    private static final char LAST_DIGIT = '7';
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final char FIRST_LOWER = 'a';
    private static final char LAST_LOWER = 'z';
    private static final int CASE_OFFSET = 'a' - 'A';
    private static final int SHA256_BLOCK_LEN = 64;

    private RecoveryKey() {
    }

    /** Generates a new 32-byte recovery key. */
    public static SecretBytes generate() {
        return Csprng.secretBytes(KEY_LEN);
    }

    /**
     * Formats {@code key} for one-time display: 63 chars, 8 groups of 7 joined by {@code -}.
     *
     * @throws IllegalArgumentException {@code BAD_LENGTH} if {@code key} is not 32 bytes
     */
    public static SecretChars format(SecretBytes key) {
        Objects.requireNonNull(key, "key");
        if (key.length() != KEY_LEN) {
            throw new IllegalArgumentException("BAD_LENGTH");
        }
        byte[] raw = new byte[RAW_LEN];
        char[] display = new char[DISPLAY_LEN];
        try {
            key.withBytes(b -> System.arraycopy(b, 0, raw, 0, KEY_LEN));
            // Nested try/finally: each buffer is wiped by the block that created it, so no null checks.
            byte[] digest = sha256OfKey(raw);
            try {
                System.arraycopy(digest, 0, raw, KEY_LEN, CHECKSUM_LEN);
            } finally {
                Arrays.fill(digest, (byte) 0);
            }
            char[] encoded = encode(raw);
            try {
                int o = 0;
                for (int i = 0; i < ENCODED_LEN; i++) {
                    if (i > 0 && i % GROUP_LEN == 0) {
                        display[o++] = SEPARATOR;
                    }
                    display[o++] = encoded[i];
                }
                return SecretChars.takeOwnership(display);
            } finally {
                Arrays.fill(encoded, '\0');
            }
        } finally {
            Arrays.fill(raw, (byte) 0);
            Arrays.fill(display, '\0');
        }
    }

    /**
     * Parses typed input (case, space, and dash tolerant); a wrong length, a non-base32 character,
     * or a bad checksum yields BAD_INPUT.
     */
    public static SecretBytes parse(SecretChars typed) throws CryptoException {
        Objects.requireNonNull(typed, "typed");
        char[] input = new char[typed.length()];
        char[] cleaned = new char[ENCODED_LEN];
        byte[] raw = null;
        byte[] digest = null;
        byte[] expected = new byte[CHECKSUM_LEN];
        byte[] actual = new byte[CHECKSUM_LEN];
        try {
            typed.withChars(c -> System.arraycopy(c, 0, input, 0, input.length));
            int n = 0;
            for (char c : input) {
                if (c == SPACE || c == SEPARATOR) {
                    continue;
                }
                if (n == ENCODED_LEN) {
                    throw new CryptoException(CryptoException.Code.BAD_INPUT);
                }
                cleaned[n++] = toAsciiUpper(c);
            }
            if (n != ENCODED_LEN) {
                throw new CryptoException(CryptoException.Code.BAD_INPUT);
            }
            raw = decode(cleaned);
            digest = sha256OfKey(raw);
            System.arraycopy(digest, 0, expected, 0, CHECKSUM_LEN);
            System.arraycopy(raw, KEY_LEN, actual, 0, CHECKSUM_LEN);
            if (!MessageDigest.isEqual(expected, actual)) {
                throw new CryptoException(CryptoException.Code.BAD_INPUT);
            }
            return SecretBytes.takeOwnership(Arrays.copyOf(raw, KEY_LEN));
        } finally {
            Arrays.fill(input, '\0');
            Arrays.fill(cleaned, '\0');
            Arrays.fill(expected, (byte) 0);
            Arrays.fill(actual, (byte) 0);
            if (raw != null) {
                Arrays.fill(raw, (byte) 0);
            }
            if (digest != null) {
                Arrays.fill(digest, (byte) 0);
            }
        }
    }

    /** RFC 4648 base32 without padding; {@code data.length * 8} must be a multiple of 5. */
    private static char[] encode(byte[] data) {
        char[] out = new char[ENCODED_LEN];
        int acc = 0;
        int bits = 0;
        int o = 0;
        for (byte b : data) {
            acc = (acc << BITS_PER_BYTE) | (b & BYTE_MASK);
            bits += BITS_PER_BYTE;
            while (bits >= BITS_PER_CHAR) {
                bits -= BITS_PER_CHAR;
                out[o++] = ALPHABET.charAt((acc >>> bits) & CHAR_MASK);
            }
        }
        return out;
    }

    /** Decodes exactly {@link #ENCODED_LEN} upper-case base32 chars into {@link #RAW_LEN} bytes. */
    private static byte[] decode(char[] chars) throws CryptoException {
        byte[] out = new byte[RAW_LEN];
        int acc = 0;
        int bits = 0;
        int o = 0;
        for (char c : chars) {
            int v = valueOf(c);
            if (v < 0) {
                Arrays.fill(out, (byte) 0);
                throw new CryptoException(CryptoException.Code.BAD_INPUT);
            }
            acc = (acc << BITS_PER_CHAR) | v;
            bits += BITS_PER_CHAR;
            if (bits >= BITS_PER_BYTE) {
                bits -= BITS_PER_BYTE;
                out[o++] = (byte) (acc >> bits);
            }
        }
        return out;
    }

    /** Base32 value of {@code c}, or -1 if {@code c} is outside {@code A-Z2-7}. */
    private static int valueOf(char c) {
        if (c >= FIRST_LETTER && c <= LAST_LETTER) {
            return c - FIRST_LETTER;
        }
        if (c >= FIRST_DIGIT && c <= LAST_DIGIT) {
            return c - FIRST_DIGIT + DIGIT_OFFSET;
        }
        return -1;
    }

    /**
     * ASCII-only upper-casing. {@link Character#toUpperCase} would map U+0131 (dotless i) to 'I'
     * and U+017F (long s) to 'S', so look-alike input would parse; here they stay invalid.
     */
    private static char toAsciiUpper(char c) {
        if (c >= FIRST_LOWER && c <= LAST_LOWER) {
            return (char) (c - CASE_OFFSET);
        }
        return c;
    }

    /**
     * SHA-256 over the key part of {@code raw}, then scrubs the engine. The JDK's SHA-256 keeps the
     * last partial input block in its internal buffer and the last block's words in its message
     * schedule after {@code digest()}; neither is cleared by reset. Digesting a block of zeros one
     * byte short of the block size copies zeros over the buffer and runs the compression again,
     * overwriting both.
     */
    private static byte[] sha256OfKey(byte[] raw) {
        MessageDigest sha = sha256();
        sha.update(raw, 0, KEY_LEN);
        byte[] digest = sha.digest();
        Arrays.fill(sha.digest(new byte[SHA256_BLOCK_LEN - 1]), (byte) 0);
        return digest;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
