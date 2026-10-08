package pm.approval.ipc;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import pm.approval.ApprovalRequest;
import pm.approval.ApprovalRequest.Display;
import pm.approval.ApprovalRequest.Effect;
import pm.approval.ApprovalRequest.Kind;
import pm.approval.ApprovalRequest.Operation;
import pm.approval.ApprovalRequest.Requester;
import pm.approval.ApprovalRequest.Scope;
import pm.approval.Decision;
import pm.crypto.SecretBytes;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborLimits;
import pm.vault.cbor.CborReader;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/**
 * Request and reply encodings: deterministic CBOR maps (approval-model §1). Decoding is strict:
 * unknown keys, wrong types and values the request constructors reject are all {@code MALFORMED}.
 */
final class IpcCodec {
    static final long VERSION = 1;
    private static final CborLimits REQUEST_LIMITS = new CborLimits(4, 4_096, ApprovalRequest.MAX_ARG_CHARS * 4,
            Frames.MAX_REQUEST);
    private static final CborLimits REPLY_LIMITS = new CborLimits(4, 4_096, 64 * 1024, Frames.MAX_REPLY);
    private static final Set<String> REQUIRED = Set.of("v", "token", "id", "kind", "label", "op", "project",
            "profile", "records", "duration", "argv", "effect", "created");
    private static final Set<String> OPTIONAL = Set.of("vars", "origin");

    private IpcCodec() {
    }

    static byte[] encodeRequest(ApprovalRequest q, SecretBytes token) {
        Map<String, CborValue> m = new LinkedHashMap<>();
        m.put("v", new CborValue.UInt(VERSION));
        token.withBytes(t -> m.put("token", new CborValue.Bytes(t)));
        m.put("id", text(q.requestId().toString()));
        m.put("kind", text(q.requester().kind().name()));
        m.put("label", text(q.requester().label()));
        m.put("op", text(q.operation().name()));
        m.put("project", text(q.scope().project()));
        m.put("profile", text(q.scope().profile()));
        q.scope().vars().ifPresent(v -> m.put("vars", texts(v)));
        m.put("records", texts(q.scope().records().stream().map(UUID::toString).toList()));
        m.put("duration", new CborValue.UInt(q.duration().toSeconds()));
        m.put("argv", texts(q.display().argv()));
        q.display().origin().ifPresent(o -> m.put("origin", text(o)));
        m.put("effect", text(q.display().effect().name()));
        m.put("created", new CborValue.UInt(q.created().getEpochSecond()));
        CborValue tree = new CborValue.MapV(m);
        try {
            return CborWriter.encode(tree, REQUEST_LIMITS);
        } finally {
            tree.wipe();
        }
    }

    /** A decoded request with the token it presented; the caller closes the token. */
    record Decoded(ApprovalRequest request, SecretBytes token) {
    }

    static Decoded decodeRequest(byte[] frame) throws IpcException {
        CborValue tree = null;
        try {
            tree = CborReader.decode(frame, REQUEST_LIMITS);
            if (!(tree instanceof CborValue.MapV map)) {
                throw malformed();
            }
            Map<String, CborValue> m = map.entries();
            if (!m.keySet().containsAll(REQUIRED) || !m.keySet().stream().allMatch(k -> REQUIRED.contains(k)
                    || OPTIONAL.contains(k)) || uint(m.get("v")) != VERSION) {
                throw malformed();
            }
            Optional<SortedSet<String>> vars = m.containsKey("vars")
                    ? Optional.of(new TreeSet<>(strings(m.get("vars")))) : Optional.empty();
            List<UUID> records = new ArrayList<>();
            for (String r : strings(m.get("records"))) {
                records.add(UUID.fromString(r));
            }
            ApprovalRequest q = new ApprovalRequest(UUID.fromString(str(m.get("id"))),
                    new Requester(Kind.valueOf(str(m.get("kind"))), str(m.get("label"))),
                    Operation.valueOf(str(m.get("op"))),
                    new Scope(str(m.get("project")), str(m.get("profile")), vars, records),
                    Duration.ofSeconds(uint(m.get("duration"))),
                    new Display(strings(m.get("argv")),
                            m.containsKey("origin") ? Optional.of(str(m.get("origin"))) : Optional.empty(),
                            Effect.valueOf(str(m.get("effect")))),
                    Instant.ofEpochSecond(uint(m.get("created"))));
            if (!(m.get("token") instanceof CborValue.Bytes t)) {
                throw malformed();
            }
            return new Decoded(q, SecretBytes.takeOwnership(t.value()));
        } catch (CborException | IllegalArgumentException | java.time.DateTimeException | ArithmeticException e) {
            throw new IpcException(IpcException.Code.MALFORMED, e);
        } finally {
            if (tree != null) {
                tree.wipe();
            }
        }
    }

    static byte[] encodeReply(Decision decision, SortedMap<String, SecretBytes> vars) {
        Map<String, CborValue> m = new LinkedHashMap<>();
        m.put("decision", text(decision.name()));
        if (!vars.isEmpty()) {
            Map<String, CborValue> values = new LinkedHashMap<>();
            vars.forEach((name, value) -> value.withBytes(b -> values.put(name, new CborValue.Bytes(b))));
            m.put("vars", new CborValue.MapV(values));
        }
        CborValue tree = new CborValue.MapV(m);
        try {
            return CborWriter.encode(tree, REPLY_LIMITS);
        } finally {
            tree.wipe();
        }
    }

    static Reply decodeReply(byte[] frame) throws IpcException {
        CborValue tree = null;
        try {
            tree = CborReader.decode(frame, REPLY_LIMITS);
            if (!(tree instanceof CborValue.MapV map) || !map.entries().containsKey("decision")
                    || !Set.of("decision", "vars").containsAll(map.entries().keySet())) {
                throw malformed();
            }
            Decision decision = Decision.valueOf(str(map.entries().get("decision")));
            SortedMap<String, SecretBytes> vars = released(map.entries().get("vars"));
            try {
                return new Reply(decision, vars);
            } catch (IllegalArgumentException e) {
                vars.values().forEach(SecretBytes::close); // a denial that carried values
                throw e;
            }
        } catch (CborException | IllegalArgumentException e) {
            throw new IpcException(IpcException.Code.MALFORMED, e);
        } finally {
            if (tree != null) {
                tree.wipe();
            }
        }
    }

    // The released values; absent is none, any other type is malformed. On a failure every value
    // already taken is wiped.
    private static SortedMap<String, SecretBytes> released(CborValue member) throws IpcException {
        SortedMap<String, SecretBytes> vars = new TreeMap<>();
        if (member == null) {
            return vars;
        }
        try {
            if (!(member instanceof CborValue.MapV values)) {
                throw malformed();
            }
            for (Map.Entry<String, CborValue> e : values.entries().entrySet()) {
                if (!(e.getValue() instanceof CborValue.Bytes b)) {
                    throw malformed();
                }
                vars.put(e.getKey(), SecretBytes.takeOwnership(b.value()));
            }
            return vars;
        } catch (IpcException e) {
            vars.values().forEach(SecretBytes::close);
            throw e;
        }
    }

    private static IpcException malformed() {
        return new IpcException(IpcException.Code.MALFORMED, null);
    }

    private static CborValue text(String s) {
        return new CborValue.Text(s);
    }

    private static CborValue texts(java.util.Collection<String> items) {
        return new CborValue.Array(items.stream().<CborValue>map(CborValue.Text::new).toList());
    }

    private static String str(CborValue v) throws IpcException {
        if (v instanceof CborValue.Text t) {
            return t.value();
        }
        throw malformed();
    }

    private static long uint(CborValue v) throws IpcException {
        if (v instanceof CborValue.UInt u) {
            return u.value();
        }
        throw malformed();
    }

    private static List<String> strings(CborValue v) throws IpcException {
        if (!(v instanceof CborValue.Array a)) {
            throw malformed();
        }
        List<String> out = new ArrayList<>();
        for (CborValue item : a.items()) {
            out.add(str(item));
        }
        return out;
    }
}
