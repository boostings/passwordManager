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
}
