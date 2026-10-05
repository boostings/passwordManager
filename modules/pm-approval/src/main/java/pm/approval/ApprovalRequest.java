package pm.approval;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.UUID;
import pm.domain.env.DotEnv;
import pm.domain.env.ProjectEnv;

/**
 * One request to release secrets (approval-model.md §1). Every component is validated here, so a
 * request that exists is well formed (decision-table row 4 is enforced by construction). The
 * session token is not part of the request: the transport presents it to
 * {@link ApprovalBroker#submit} separately, and the broker fills in the OS user itself.
 *
 * @param requestId random, single-use identifier (SR-104)
 * @param requester who is asking
 * @param operation what would happen to the secrets
 * @param scope exactly one project (SR-103)
 * @param duration validity the requester would like if the user creates a policy; at most 24 h
 * @param display what the prompt shows; for {@code env-inject} the exact argv that will run (SR-102)
 * @param created when the requester built the request
 */
public record ApprovalRequest(UUID requestId, Requester requester, Operation operation, Scope scope,
        Duration duration, Display display, Instant created) {

    /** Longest policy a request may ask for, and longest any policy may last. */
    public static final Duration MAX_DURATION = Duration.ofHours(24);
    /** Longest caller-supplied label; longer labels are rejected, not truncated, at this layer. */
    public static final int MAX_LABEL_CHARS = 64;
    /** Most argv elements accepted. */
    public static final int MAX_ARGS = 256;
    /** Longest single argv element. */
    public static final int MAX_ARG_CHARS = 4_096;
    /** Most variables or records one request may name. */
    public static final int MAX_ITEMS = 1_024;

    /** The operations of approval-model.md §1. */
    public enum Operation {
        /** Inject variables into a child process. */
        ENV_INJECT,
        /** Show secrets on screen. */
        REVEAL,
        /** Write secrets to a file. */
        EXPORT,
        /** Fill a browser form. */
        AUTOFILL,
        /** Send secrets to a paired device. */
        SHARE,
        /** Sign with an SSH key. */
        SSH_SIGN,
        /**
         * Enroll or sign in with a passkey (WebAuthn, ADR 0016 M6.3 addendum). The authenticator
         * data pm returns claims user presence, so every enrollment and every sign-in needs its
         * own prompt (WebAuthn L3 §6.3.2 step 3, §6.3.3).
         */
        PASSKEY;

        /** Export, share and passkey always prompt; no policy may cover them (decision-table row 5). */
        boolean alwaysPrompts() {
            return this == EXPORT || this == SHARE || this == PASSKEY;
        }
    }

    /** What kind of program is asking. */
    public enum Kind {
        /** The pm command line. */
        CLI,
        /** A local agent or tool. */
        AGENT,
        /** The browser extension. */
        EXTENSION,
        /** A paired device. */
        DEVICE
    }

    /** What the user is told will happen. */
    public enum Effect {
        /** Values go into a process environment. */
        INJECT,
        /** Values are shown. */
        SHOW,
        /** Values are written to a file. */
        WRITE_FILE,
        /** Values are sent elsewhere. */
        SEND
    }

    /**
     * Who is asking.
     *
     * @param kind requester kind
     * @param label caller-supplied name, untrusted, shown quoted; 1–64 chars, no control characters
     */
    public record Requester(Kind kind, String label) {
        public Requester {
            Objects.requireNonNull(kind, "kind");
            label = checkText(label, MAX_LABEL_CHARS, "label");
        }
    }

    /**
     * Which secrets are wanted.
     *
     * @param project exact project title (one project per request, SR-103)
     * @param profile profile name; the default profile when the caller named none
     * @param vars the variables wanted, or empty for the whole profile (shown as such)
     * @param records record ids for reveal, autofill and share
     */
    public record Scope(String project, String profile, Optional<SortedSet<String>> vars, List<UUID> records) {
        public Scope {
            project = checkText(project, 256, "project");
            if (!ProjectEnv.isValidProfile(Objects.requireNonNull(profile, "profile"))) {
                throw new IllegalArgumentException("BAD_PROFILE");
            }
            vars = Objects.requireNonNull(vars, "vars").map(v -> {
                if (v.isEmpty() || v.size() > MAX_ITEMS || !v.stream().allMatch(DotEnv::isValidName)) {
                    throw new IllegalArgumentException("BAD_VARS");
                }
                return java.util.Collections.unmodifiableSortedSet(new TreeSet<>(v));
            });
            records = List.copyOf(records);
            if (records.size() > MAX_ITEMS) {
                throw new IllegalArgumentException("BAD_RECORDS");
            }
        }

        /** A whole-profile scope for {@code project}. */
        public static Scope profile(String project, String profile) {
            return new Scope(project, profile, Optional.empty(), List.of());
        }

        /** True if this scope is covered by {@code policy}: same project and profile, vars a subset. */
        boolean isWithin(Scope policy) {
            if (!project.equals(policy.project) || !profile.equals(policy.profile)) {
                return false;
            }
            if (policy.vars.isEmpty()) {
                return records.isEmpty();
            }
            // A whole-profile request never matches a policy that lists variables (§3).
            return vars.isPresent() && policy.vars.get().containsAll(vars.get()) && records.isEmpty();
        }
    }

    /**
     * What the prompt shows.
     *
     * @param argv for {@code env-inject}: the exact argv the broker will execute, the only argv it
     *     will execute (SR-102); empty otherwise
     * @param origin for autofill: the page origin
     * @param effect what happens to the secrets
     */
    public record Display(List<String> argv, Optional<String> origin, Effect effect) {
        public Display {
            argv = List.copyOf(argv);
            if (argv.size() > MAX_ARGS || argv.stream().anyMatch(a -> a.length() > MAX_ARG_CHARS || a.indexOf('\0') >= 0)) {
                throw new IllegalArgumentException("BAD_ARGV");
            }
            origin = Objects.requireNonNull(origin, "origin").map(o -> checkText(o, 2048, "origin"));
            Objects.requireNonNull(effect, "effect");
        }
    }

    public ApprovalRequest {
        Objects.requireNonNull(requestId, "requestId");
        Objects.requireNonNull(requester, "requester");
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(display, "display");
        Objects.requireNonNull(created, "created");
        if (duration.isNegative() || duration.compareTo(MAX_DURATION) > 0) {
            throw new IllegalArgumentException("BAD_DURATION");
        }
        if (operation == Operation.ENV_INJECT && (display.argv().isEmpty() || display.effect() != Effect.INJECT)) {
            throw new IllegalArgumentException("BAD_DISPLAY"); // what is shown must be what runs
        }
    }

    /**
     * True if an approval of this request may become a session or temporary policy. False for
     * export, share and passkey (decision-table row 5): the broker counts any approval of those
     * once and keeps no policy, so a prompt should offer only approve-once and deny.
     */
    public boolean allowsStandingGrant() {
        return !operation.alwaysPrompts();
    }

    /** The program name only, for the audit log; full argv may embed secrets (approval-model §7). */
    public String argv0() {
        if (display.argv().isEmpty()) {
            return "";
        }
        String first = display.argv().get(0);
        int cut = Math.max(first.lastIndexOf('/'), first.lastIndexOf('\\'));
        return first.substring(cut + 1);
    }

    private static String checkText(String value, int maxChars, String field) {
        Objects.requireNonNull(value, field);
        if (value.isEmpty() || value.length() > maxChars
                || value.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
            throw new IllegalArgumentException("BAD_" + field.toUpperCase(java.util.Locale.ROOT));
        }
        return value;
    }
}
