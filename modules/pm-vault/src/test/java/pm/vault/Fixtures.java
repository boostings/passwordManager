package pm.vault;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.vault.record.LoginRecord;
import pm.vault.record.RecordException;
import pm.vault.record.VaultRecord;

/** Shared test helpers for pm.vault tests. */
final class Fixtures {

    static final Instant T0 = Instant.parse("2026-10-02T12:00:00Z");
    static final Clock CLOCK = Clock.fixed(T0, ZoneOffset.UTC);
    static final String PHRASE = "correct horse battery staple";

    private Fixtures() {
    }

    static SecretChars chars(String s) {
        return SecretChars.takeOwnership(s.toCharArray());
    }

    static LoginRecord login(String title, String username, String value) {
        return new LoginRecord(UUID.nameUUIDFromBytes(title.getBytes(StandardCharsets.UTF_8)), title, username,
                SecretBytes.copyOf(value.getBytes(StandardCharsets.UTF_8)),
                List.of("https://" + title + ".example"), "", List.of("tag-" + title),
                T0, T0, T0);
    }

    /** The record's secret field; keeps secret-named expressions out of assertion arguments. */
    static SecretBytes pwOf(LoginRecord r) {
        return r.password();
    }

    /** Payload codec seam that counts decode calls (SR-020 proof). */
    static final class CountingCodec implements PayloadCodec {
        final AtomicInteger decodes = new AtomicInteger();

        @Override
        public SecretBytes encode(List<VaultRecord> records) {
            return PayloadCodec.RECORDS.encode(records);
        }

        @Override
        public List<VaultRecord> decode(SecretBytes plaintext) throws RecordException {
            decodes.incrementAndGet();
            return PayloadCodec.RECORDS.decode(plaintext);
        }
    }
}
