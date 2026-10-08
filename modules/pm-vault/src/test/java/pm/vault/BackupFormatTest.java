package pm.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import pm.crypto.SecretBytes;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/** Every check the backup header and framing make (ADR 0015), one crafted value or file each. */
class BackupFormatTest {
    private static final CborValue.Bytes SHA = new CborValue.Bytes(new byte[32]);
    private static final CborValue.Bytes SALT = new CborValue.Bytes(new byte[BackupFormat.SALT_LENGTH]);
    private static final CborValue.Bytes SHORT = new CborValue.Bytes(new byte[31]);

    @Test
    void aHeaderRefusesEveryOutOfRangeField() {
        List<Runnable> bad = List.of(
                () -> new BackupFormat.Header(-1, 1, 0, SHA, SALT),
                () -> new BackupFormat.Header(BackupFormat.MAX_CREATED + 1, 1, 0, SHA, SALT),
                () -> new BackupFormat.Header(0, -1, 0, SHA, SALT),
                () -> new BackupFormat.Header(0, 0x1_0000, 0, SHA, SALT),
                () -> new BackupFormat.Header(0, 1, -1, SHA, SALT),
                () -> new BackupFormat.Header(0, 1, 0, SHORT, SALT),
                () -> new BackupFormat.Header(0, 1, 0, SHA, SHORT));
        for (Runnable r : bad) {
            assertThrows(IllegalArgumentException.class, r::run);
        }
        assertEquals(0xFFFF, new BackupFormat.Header(BackupFormat.MAX_CREATED, 0xFFFF, 0, SHA, SALT).formatVersion());
    }

    @Test
    void assembleRefusesAVaultOfAnotherLength() {
        try (SecretBytes vk = SecretBytes.copyOf(new byte[32])) {
            BackupFormat.Header header = new BackupFormat.Header(0, 1, 5, SHA, SALT);
            assertThrows(IllegalArgumentException.class, () -> BackupFormat.assemble(header, new byte[4], vk));
        }
    }

    @Test
    void anOlderLayoutVersionIsCorrupt() {
        byte[] file = backup(new CborValue.MapV(fields()), 0);
        assertEquals(VaultException.Code.CORRUPT, assertThrows(VaultException.class, () -> BackupFormat.parse(file)).code());
        for (int length : new int[] {0, 4097, 1_000}) {
            byte[] framed = backup(new CborValue.MapV(fields()), BackupFormat.VERSION);
            ByteBuffer.wrap(framed).putInt(10, length);
            assertEquals(VaultException.Code.CORRUPT,
                    assertThrows(VaultException.class, () -> BackupFormat.parse(framed)).code(), "length " + length);
        }
    }

    @Test
    void everyMalformedHeaderIsCorrupt() {
        List<CborValue> bad = new java.util.ArrayList<>();
        bad.add(new CborValue.Array(List.of()));
        Map<String, CborValue> fewer = fields();
        fewer.remove("mac_salt");
        bad.add(new CborValue.MapV(fewer));
        Map<String, CborValue> renamed = fields();
        renamed.remove("mac_salt");
        renamed.put("salt", SALT);
        bad.add(new CborValue.MapV(renamed));
        Map<String, CborValue> replacements = Map.of(
                "created", new CborValue.Text("0"),
                "format_version", new CborValue.Text("1"),
                "vault_length", new CborValue.Text("0"),
                "content_sha256", new CborValue.Text("x"),
                "mac_salt", new CborValue.Text("x"));
        for (Map.Entry<String, CborValue> e : replacements.entrySet()) {
            bad.add(with(e.getKey(), e.getValue()));
        }
        bad.add(with("created", new CborValue.UInt(BackupFormat.MAX_CREATED + 1)));
        bad.add(with("format_version", new CborValue.UInt(0x1_0000)));
        bad.add(with("content_sha256", SHORT));
        bad.add(with("mac_salt", SHORT));
        for (CborValue header : bad) {
            byte[] file = backup(header, BackupFormat.VERSION);
            assertEquals(VaultException.Code.CORRUPT,
                    assertThrows(VaultException.class, () -> BackupFormat.parse(file)).code(), header.toString());
        }
    }

    private static Map<String, CborValue> fields() {
        Map<String, CborValue> m = new HashMap<>();
        m.put("created", new CborValue.UInt(0));
        m.put("format_version", new CborValue.UInt(1));
        m.put("vault_length", new CborValue.UInt(0));
        m.put("content_sha256", SHA);
        m.put("mac_salt", SALT);
        return m;
    }

    private static CborValue with(String key, CborValue value) {
        Map<String, CborValue> m = fields();
        m.put(key, value);
        return new CborValue.MapV(m);
    }

    /** {@code "PMBACKUP" ‖ version ‖ len ‖ header ‖ (no vault) ‖ 32-byte tag}. */
    private static byte[] backup(CborValue header, int version) {
        byte[] cbor = CborWriter.encode(header);
        return ByteBuffer.allocate(14 + cbor.length + 32)
                .put("PMBACKUP".getBytes(StandardCharsets.US_ASCII))
                .putShort((short) version).putInt(cbor.length).put(cbor).array();
    }
}
