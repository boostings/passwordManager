package pm.vault.record;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import pm.crypto.SecretBytes;

class RecordCodecTest {
    @Test
    void encodeAndDecodeRoundTrip() throws Exception {
        LoginRecord record = new LoginRecord(
            UUID.fromString("11111111-1111-4111-8111-111111111111"),
            "alpha",
            "alice",
            SecretBytes.copyOf("hunter2".getBytes(java.nio.charset.StandardCharsets.UTF_8)),
            List.of("https://example.com"),
            "note",
            List.of("work"),
            Instant.EPOCH,
            Instant.EPOCH.plusSeconds(5),
            Instant.EPOCH.plusSeconds(10)
        );

        SecretBytes payload = RecordCodec.encodePayload(List.of(record));
        List<VaultRecord> decoded = RecordCodec.decodePayload(payload);

        assertEquals(1, decoded.size());
        assertEquals(record, decoded.get(0));
        assertNotNull(decoded.get(0));
    }
}
