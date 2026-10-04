package pm.cli;

import java.io.PrintWriter;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import pm.crypto.SecretBytes;
import pm.domain.health.AgeCheck;
import pm.domain.health.BreachCheckException;
import pm.domain.health.BreachClient;
import pm.domain.health.HealthCheck;
import pm.domain.health.HealthReport;
import pm.domain.health.ReuseGroup;
import pm.tui.Session;
import pm.tui.VaultPort;
import pm.vault.VaultException;
import pm.vault.record.LoginRecord;
import pm.vault.record.VaultRecord;
import pm.vault.record.WifiRecord;

/**
 * {@code pm health [--max-age-days N] [--breach]} (plan.md §13 M4.4, ADR 0012).
 *
 * <p>Without {@code --breach} the report is entirely offline: weak, reused and old passwords from
 * {@link HealthCheck}, and no {@link BreachClient} is ever constructed, so no socket is opened
 * (SR-078). With {@code --breach}, after the offline report, pm states exactly what will leave the
 * machine (the first five hex characters of each password's SHA-1, nothing else) and asks for a
 * typed {@code y}; only then does it build the client and look each distinct password up. Members
 * of a reuse group share one lookup, so a password is never sent twice. Output carries record
 * titles (made terminal-safe), counts and ratings, never a password or hash (SR-501).
 */
@SuppressWarnings("PMD.CloseResource") // CE-045: records and their passwords stay owned by the session (ADR 0008)
final class HealthCommand {
    static final String BREACH = "--breach";
    static final String MAX_AGE_DAYS = "--max-age-days";
    static final String CONFIRM = "y";

    private static final Set<String> FLAGS = Set.of(BREACH);
    private static final Set<String> VALUED = Set.of(MAX_AGE_DAYS);
    private static final String INDENT = "  ";
    private static final String GAP = "  ";

    private final Clock clock;
    private final Supplier<BreachClient> breachClients;

    /**
     * Creates the command.
     *
     * @param breachClients builds the breach client; called only after the user confirmed {@code --breach}
     */
    HealthCommand(Clock clock, Supplier<BreachClient> breachClients) {
        this.clock = clock;
        this.breachClients = breachClients;
    }

    /** Runs {@code pm health} with the arguments after the command word. */
    int run(List<String> sub, VaultPort port, ConsoleIo io) throws UsageException, VaultException {
        CommandArgs args = CommandArgs.parse(sub, FLAGS, VALUED).arity(0);
        Duration maxAge = AgeCheck.DEFAULT_MAX_AGE;
        Optional<String> days = args.value(MAX_AGE_DAYS);
        if (days.isPresent()) {
            int n = CommandArgs.number(days.get(), Messages.BAD_MAX_AGE);
            if (n == 0) {
                throw new UsageException(Messages.BAD_MAX_AGE);
            }
            maxAge = Duration.ofDays(n);
        }
        try (Session session = Cli.unlock(port, io)) {
            List<VaultRecord> records = session.records();
            HealthReport report = new HealthCheck(clock, maxAge).run(records);
            printReport(io.out(), report, titles(records), maxAge);
            if (!args.has(BREACH)) {
                return ExitCodes.OK;
            }
            return checkBreaches(io, records, report);
        }
    }

    // ---- offline report ------------------------------------------------------------------------

    private static Map<UUID, String> titles(List<VaultRecord> records) {
        Map<UUID, String> titles = new HashMap<>();
        records.forEach(r -> titles.put(r.id(), Cli.displaySafe(r.title())));
        return titles;
    }

    private static void printReport(PrintWriter out, HealthReport report, Map<UUID, String> titles, Duration maxAge) {
        out.println(Messages.HEALTH_CHECKED.text() + report.checked());
        if (report.isClean()) {
            out.println(Messages.HEALTH_CLEAN.text());
            return;
        }
        if (!report.weak().isEmpty()) {
            out.println(Messages.HEALTH_WEAK.text() + report.weak().size());
            for (HealthReport.Weak w : report.weak()) {
                String why = w.estimate().weaknesses().stream().map(Enum::name).sorted()
                        .map(s -> s.toLowerCase(Locale.ROOT)).collect(Collectors.joining(","));
                out.println(INDENT + titles.get(w.id()) + GAP + w.estimate().strength().name().toLowerCase(Locale.ROOT)
                        + GAP + String.format(Locale.ROOT, "~%.0f bits", w.estimate().bits())
                        + (why.isEmpty() ? "" : GAP + why));
            }
        }
        if (!report.reused().isEmpty()) {
            out.println(Messages.HEALTH_REUSED.text() + report.reused().size());
            for (ReuseGroup g : report.reused()) {
                out.println(INDENT + g.ids().stream().map(titles::get).collect(Collectors.joining(", ")));
            }
        }
        if (!report.old().isEmpty()) {
            out.println(Messages.HEALTH_OLD.text() + maxAge.toDays() + " days: " + report.old().size());
            for (HealthReport.Old o : report.old()) {
                out.println(INDENT + titles.get(o.id()) + GAP + o.age().toDays() + " days");
            }
        }
    }

    // ---- opt-in breach check -------------------------------------------------------------------

    /**
     * The breach lookup, after an explicit confirmation. One lookup per distinct password: a reuse
     * group is represented by its first record. Nothing is sent unless the user types {@code y}.
     */
    private int checkBreaches(ConsoleIo io, List<VaultRecord> records, HealthReport report) throws UsageException {
        Map<UUID, List<UUID>> sharedWith = new HashMap<>();
        Set<UUID> skip = new HashSet<>();
        for (ReuseGroup g : report.reused()) {
            sharedWith.put(g.ids().get(0), g.ids());
            skip.addAll(g.ids().subList(1, g.ids().size()));
        }
        List<VaultRecord> lookups = records.stream()
                .filter(r -> hasPassword(r) && !skip.contains(r.id())).toList();
        if (lookups.isEmpty()) {
            io.out().println(Messages.BREACH_NOTHING.text()); // no prompt, no client, no request
            return ExitCodes.OK;
        }
        io.out().println(Messages.BREACH_NOTICE.text());
        io.out().println(Messages.BREACH_COUNT.text() + lookups.size());
        io.out().flush();
        String answer = io.readLine(Messages.BREACH_CONFIRM.text());
        if (answer == null) {
            throw new UsageException(Messages.INPUT_CLOSED);
        }
        if (!CONFIRM.equals(answer)) { // exactly "y": " y" or "yes" is not consent
            io.out().println(Messages.BREACH_SKIPPED.text());
            return ExitCodes.OK;
        }
        Map<UUID, String> titles = titles(records);
        int found = 0;
        try (BreachClient client = breachClients.get()) {
            for (VaultRecord r : lookups) {
                long seen = client.occurrences(password(r));
                if (seen > 0) {
                    found++;
                    for (UUID id : sharedWith.getOrDefault(r.id(), List.of(r.id()))) {
                        io.out().println(Messages.BREACH_FOUND.text() + titles.get(id) + GAP + seen + " times");
                    }
                }
            }
        } catch (BreachCheckException e) {
            io.err().println(breachMessage(e.code()).text());
            return ExitCodes.EXTERNAL;
        }
        io.out().println(Messages.BREACH_SUMMARY.text() + found + " of " + lookups.size());
        return ExitCodes.OK;
    }

    /** Catalogue text for a failed lookup; the offline report above it stays valid. */
    static Messages breachMessage(BreachCheckException.Code code) {
        return switch (code) {
            case TIMEOUT -> Messages.BREACH_TIMEOUT;
            case MALFORMED, TOO_LARGE -> Messages.BREACH_MALFORMED;
            case HTTP_STATUS -> Messages.BREACH_HTTP_STATUS;
            case NETWORK -> Messages.BREACH_NETWORK;
            case INTERRUPTED, INTERNAL -> Messages.BREACH_FAILED;
        };
    }

    private static boolean hasPassword(VaultRecord r) {
        SecretBytes p = password(r);
        return p != null && p.length() > 0;
    }

    /** The record's password, or null for record types without one (same rule as {@link HealthCheck}). */
    private static SecretBytes password(VaultRecord r) {
        if (r instanceof LoginRecord) {
            return LoginRecord.class.cast(r).password();
        }
        return r instanceof WifiRecord ? WifiRecord.class.cast(r).password() : null;
    }
}
