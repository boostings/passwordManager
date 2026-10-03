package pm.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class HashTest {
    @Test
    void fipsVectors() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                HexFormat.of().formatHex(Hash.sha256(new byte[0])));
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                HexFormat.of().formatHex(Hash.sha256("abc".getBytes(StandardCharsets.US_ASCII))));
    }

    @Test
    void sha1ForBreachRangeVectors() throws CryptoException {
        try (SecretBytes abc = SecretBytes.copyOf("abc".getBytes(StandardCharsets.US_ASCII));
                SecretBytes digest = Hash.sha1ForBreachRange(abc)) {
            assertEquals(Hash.SHA1_BYTES, digest.length());
            assertEquals("a9993e364706816aba3e25717850c26c9cd0d89d", digest.apply(HexFormat.of()::formatHex));
        }
        try (SecretBytes pw = SecretBytes.copyOf("password".getBytes(StandardCharsets.US_ASCII));
                SecretBytes digest = Hash.sha1ForBreachRange(pw)) {
            assertEquals("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", digest.apply(HexFormat.of()::formatHex));
        }
    }
}
