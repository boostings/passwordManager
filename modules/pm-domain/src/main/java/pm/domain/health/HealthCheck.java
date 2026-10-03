package pm.domain.health;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import pm.crypto.SecretBytes;
import pm.vault.record.LoginRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/**
 * Runs the weak, reused and old checks over vault records, entirely offline (ADR 0012).
 *
 * <p>Logins and Wi-Fi networks carry a password; SSH keys and projects are skipped, as are empty
 * passwords (open networks). The breach check is deliberately not part of this class: it needs the
 * network, so a caller must construct a {@link BreachClient} and invoke it explicitly.
 *
 * <p>The caller owns the records and their secrets; nothing here closes or retains them. Records
 * and passwords are passed as method arguments rather than held in locals so that ownership stays
 * visible to PMD's {@code CloseResource} rule without a suppression.
 */
public final class HealthCheck {
    private final AgeCheck age;

    /** Returns a check with {@link AgeCheck#DEFAULT_MAX_AGE}. */
    public HealthCheck(Clock clock) {
        this(clock, AgeCheck.DEFAULT_MAX_AGE);
    }

    /** Returns a check that flags records older than {@code maxAge}. */
    public HealthCheck(Clock clock, Duration maxAge) {
        this.age = new AgeCheck(clock, maxAge);
    }

    /** Examines {@code records}; the caller keeps ownership of them. */
    public HealthReport run(List<? extends VaultRecord> records) {
        Objects.requireNonNull(records, "records");
        Findings findings = new Findings();
        for (int i = 0; i < records.size(); i++) {
            examine(records.get(i), password(records.get(i)), findings);
        }
        return new HealthReport(findings.entries.size(), findings.weak, ReuseCheck.find(findings.entries), findings.old);
    }

    private void examine(VaultRecord record, SecretBytes password, Findings findings) {
        if (password == null || password.length() == 0) {
            return;
        }
        findings.entries.add(new ReuseCheck.Entry(record.id(), password));
        StrengthEstimate estimate = StrengthMeter.estimate(password);
        if (estimate.isWeak()) {
            findings.weak.add(new HealthReport.Weak(record.id(), estimate));
        }
        if (age.isOld(record)) {
            findings.old.add(new HealthReport.Old(record.id(), age.age(record)));
        }
    }

    /** The record's password, or null for record types without one. */
    static SecretBytes password(VaultRecord record) {
        if (record instanceof LoginRecord) {
            return LoginRecord.class.cast(record).password();
        }
        return record instanceof WifiRecord ? WifiRecord.class.cast(record).password() : null;
    }

    /** Accumulator for one run. */
    private static final class Findings {
        private final List<HealthReport.Weak> weak = new ArrayList<>();
        private final List<HealthReport.Old> old = new ArrayList<>();
        private final List<ReuseCheck.Entry> entries = new ArrayList<>();
    }
}
