package pm.crypto;

import java.util.Arrays;

/** Test-only access to secret contents. Production code never copies a secret out like this. */
final class TestBytes {
    private TestBytes() {
    }

    /** Returns a fresh copy of the secret's bytes (never the internal buffer). */
    static byte[] copyOut(SecretBytes s) {
        return s.apply(b -> Arrays.copyOf(b, b.length));
    }
}
