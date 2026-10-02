package pm.vault.record;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import pm.crypto.SecretBytes;

class RecordCodecTest {
    private static final Instant T0 = Instant.EPOCH.plusSeconds(1_000);

    private static SecretBytes secret(String s) {
        return SecretBytes.copyOf(s.getBytes(StandardCharsets.UTF_8));
    }

    private static LoginRecord login() {
        return new LoginRecord(UUID.fromString("11111111-1111-4111-8111-111111111111"), "alpha",
                "alice", secret("hunter2"), List.of("https://example.com"), "note",
                List.of("work"), T0, T0.plusSeconds(5), T0.plusSeconds(10));
    }

    private static List<VaultRecord> allTypes() {
        return List.of(
                login(),
                new WifiRecord(UUID.randomUUID(), "home", "homenet", "WPA3", secret("wifi-pw"), true,
                        "", T0, T0),
                new SshKeyRecord(UUID.randomUUID(), "deploy", "ssh-ed25519", secret("PRIVATE"),
                        "ssh-ed25519 AAAA", "SHA256:x", "me@host", List.of("github.com"), T0, T0),
                new ProjectRecord(UUID.randomUUID(), "proj", "/src/proj", "git@example:p.git",
                        Map.of("TOKEN", secret("t0k3n")), Map.of("env", "dev"), T0, T0));
    }

    @Test
    void encodeAndDecodeRoundTripAllTypes() throws RecordException {
        List<VaultRecord> records = allTypes();
        try (SecretBytes payload = RecordCodec.encodePayload(records)) {
            List<VaultRecord> decoded = RecordCodec.decodePayload(payload);
            assertEquals(records, decoded);
            decoded.forEach(VaultRecord::close);
        } finally {
            records.forEach(VaultRecord::close);
        }
    }

    @Test
    void truncatedPayloadNeverYieldsAPartialList() {
        List<VaultRecord> records = allTypes();
        byte[] full;
        try (SecretBytes payload = RecordCodec.encodePayload(records)) {
            full = payload.apply(b -> Arrays.copyOf(b, b.length));
        } finally {
            records.forEach(VaultRecord::close);
        }
        for (int len = 0; len < full.length; len++) {
            try (SecretBytes cut = SecretBytes.copyOf(Arrays.copyOf(full, len))) {
                List<VaultRecord> decoded = RecordCodec.decodePayload(cut);
                decoded.forEach(VaultRecord::close);
                fail("truncated payload decoded at length " + len);
            } catch (RecordException expected) {
                assertFalse(expected.getMessage().isEmpty());
            }
        }
    }

    @Test
    void searchNeverMatchesSecrets() {
        List<VaultRecord> records = allTypes();
        try {
            assertTrue(records.stream().noneMatch(r -> RecordSearch.matches(r, "hunter")));
            assertTrue(records.stream().noneMatch(r -> RecordSearch.matches(r, "PRIVATE")));
            assertTrue(RecordSearch.matches(records.get(0), "ALICE"));
            assertTrue(RecordSearch.matches(records.get(1), "HomeNet"));
            assertTrue(RecordSearch.matches(records.get(2), "github"));
            assertTrue(records.stream().allMatch(r -> RecordSearch.matches(r, "")));
        } finally {
            records.forEach(VaultRecord::close);
        }
    }

    @Test
    void rejectsOverlongTitle() {
        String longTitle = "t".repeat(RecordLimits.MAX_TITLE + 1);
        try (SecretBytes pw = secret("x")) {
            assertThrows(IllegalArgumentException.class, () -> new LoginRecord(UUID.randomUUID(),
                    longTitle, "u", pw, List.of(), "", List.of(), T0, T0, T0));
        }
    }

    @Test
    void exceptionMessagesAreCodesOnly() {
        for (RecordException.Code c : RecordException.Code.values()) {
            assertEquals(c.name(), new RecordException(c).getMessage());
        }
    }
}
