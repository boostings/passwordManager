package pm.vault.envelope;

/** Byte-array helpers for the envelope value classes. */
final class Bytes {

    private Bytes() {
    }

    /**
     * Compares contents in time that depends only on the length (SR-016). Used for header
     * fields, which are public, so this is defence in depth. {@code MessageDigest.isEqual}
     * is unavailable here because only pm-crypto may import {@code java.security} (SR-017).
     */
    static boolean sameContents(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
}
