package pm.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.IntFunction;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.approval.ApprovalBroker;
import pm.approval.ApprovalRequest;
import pm.approval.Grant;
import pm.approval.PendingApproval;
import pm.approval.PolicyStore;
import pm.browser.bridge.ApprovalPort;
import pm.browser.bridge.Bridge;
import pm.browser.bridge.Origin;
import pm.browser.bridge.PasswordGenerator;
import pm.browser.bridge.VaultPort;
import pm.browser.host.Handler;
import pm.browser.host.HostException;
import pm.browser.host.Json;
import pm.browser.host.JsonText;
import pm.browser.host.Request;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;
import pm.fuzz.JsonOracle.Refused;
import pm.fuzz.OriginOracle.Canonical;

/**
 * Fuzz harness for exact origin binding and approval-gated release (SR-300, SR-302, SR-306,
 * SR-307; T-FUZZ-ORIGIN). Each input is a small vault of logins with fuzzer-chosen URLs, titles
 * and usernames, two fuzzer-chosen page origins, and up to four requests from one of two
 * extensions. The requests go to the production handler ({@link Bridge#factory}, as the native
 * host creates it) over a real {@link ApprovalBroker} with a fixed clock; the harness plays the
 * user and answers each prompt with the input's decision (deny, once, or for the session).
 *
 * <p>The oracle is {@link OriginOracle}, written from ADR 0014 §5, plus the release rules of §6:
 *
 * <ul>
 *   <li>{@code Origin.parse} and {@code Origin.ofUrl} agree with the oracle on every page origin
 *       and every stored URL: same accept/refuse, same triple, same text;</li>
 *   <li>with the vault locked, every request is {@code DENIED_LOCKED} with no prompt and no vault
 *       read; a page origin the oracle refuses is {@code BAD_ORIGIN};</li>
 *   <li>{@code lookup} returns exactly the logins with a URL whose oracle origin equals the page's,
 *       in vault order, at most 64, with unpaired surrogates replaced;</li>
 *   <li>{@code fill} of a login not registered for that exact origin is {@code NOT_FOUND} with no
 *       prompt and no release. Otherwise, and for every {@code save} and {@code generate}, exactly
 *       one prompt is raised, with the request the ADR describes (requester, {@code AUTOFILL},
 *       project = canonical origin, profile {@code fill-<base 36>}, {@code save} or
 *       {@code generate}, display text, effect), unless an earlier session approval covers the
 *       same extension, origin and profile, in which case none is raised;</li>
 *   <li>a password leaves the vault, or a login is saved, only after that approval: a denial gives
 *       {@code DENIED} and touches nothing; an approval gives exactly one release or save and the
 *       exact reply.</li>
 * </ul>
 *
 * <p>Input layout: byte 0 bit 0 locks the vault; byte 1 is the request count (mod 5); two bytes
 * per request (kind, page, extension, decision; login index); the rest is UTF-8 text in lines.
 * Line 0 is page origin A, line 1 page origin B, and each later line one login:
 * {@code urls [U+001E title [U+001E username]]}, URLs separated by U+001F. A URL starting with
 * U+0001 or U+0002 is page A or page B followed by the rest, so near misses of the page origin are
 * one mutation away. In titles and usernames U+0004 and U+0005 stand for a lone high and low
 * surrogate.
 */
@Tag("T-FUZZ-ORIGIN")
@Tag("T-EXT-01")
@Tag("T-EXT-03")
class OriginFuzzTest {
    static final String EXT_A = NativeHostFuzzTest.EXT_A;
    static final String EXT_B = NativeHostFuzzTest.EXT_B;
    private static final Duration WAIT = Duration.ofSeconds(5);
    private static final int BYTE = 0xFF;
    private static final int MAX_STEPS = 4;
    private static final int FIRST_STEP = 2;
    private static final int STEP_BYTES = 2;
    private static final int MAX_LOGINS = 72;
    private static final int FIRST_LOGIN_LINE = 2;
    private static final String FIELD_SPLIT = "\u001E";
    private static final String URL_SPLIT = "\u001F";
    private static final char PAGE_A = '\u0001';
    private static final char PAGE_B = '\u0002';
    private static final char HIGH_MARK = '\u0004';
    private static final char LOW_MARK = '\u0005';
    private static final int TITLE_FIELD = 1;
    private static final int USERNAME_FIELD = 2;
    private static final int KINDS = 4;
    private static final int LOOKUP = 0;
    private static final int FILL = 1;
    private static final int SAVE = 2;
    private static final int PAGE_BIT = 2;
    private static final int EXT_BIT = 3;
    private static final int DECISION_SHIFT = 4;
    private static final int DECISIONS = 3;
    private static final int DENY = 0;
    private static final int SESSION = 2;
    /** ADR 0014 §6: at most 64 logins in a lookup reply. */
    private static final int MAX_LOOKUP = 64;
    /** ADR 0014 §6: titles and usernames are shown as at most 64 code points, controls as '?'. */
    private static final int MAX_SHOWN = 64;
    private static final int LAST_C0 = 0x1F;
    private static final int FIRST_DELETE = 0x7F;
    private static final int LAST_C1 = 0x9F;
    private static final char SHOWN_CONTROL = '?';
    private static final int HEX_RADIX = 16;
    private static final int PROFILE_RADIX = 36;
    private static final Request.Policy POLICY = new Request.Policy(16, true, true, true, false);
    private static final UUID UNKNOWN = new UUID(0, 0);
    private static final long SAVED_HIGH = 0x5A5AL;

    @FuzzTest
    void fuzz(byte[] in) {
        Scenario s = Scenario.of(in);
        assertParse(s.pageA);
        assertParse(s.pageB);
        for (VaultPort.Login login : s.logins) {
            login.urls().forEach(OriginFuzzTest::assertOfUrl);
        }
        new Run(s).all();
    }

    // ---- Origin against the oracle --------------------------------------------------------------

    static void assertParse(String text) {
        Canonical want = OriginOracle.parse(text);
        Canonical got;
        String gotText;
        try {
            Origin parsed = Origin.parse(text);
            got = canonical(parsed);
            gotText = parsed.text();
        } catch (HostException e) {
            assertEquals(HostException.Code.BAD_ORIGIN, e.code(), text);
            got = null;
            gotText = null;
        }
        assertEquals(want, got, () -> "parse " + text);
        assertEquals(want == null ? null : want.text(), gotText, text);
    }

    /** A stored URL: accept or refuse, triple and canonical text, as for a page origin. */
    static void assertOfUrl(String url) {
        Canonical want = OriginOracle.ofUrl(url);
        Optional<Origin> got = Origin.ofUrl(url);
        assertEquals(want, got.map(OriginFuzzTest::canonical).orElse(null), () -> "ofUrl " + url);
        assertEquals(want == null ? null : want.text(), got.map(Origin::text).orElse(null),
                () -> "ofUrl text " + url);
    }

    private static Canonical canonical(Origin o) {
        return new Canonical(o.scheme(), o.host(), o.port());
    }

    // ---- input ----------------------------------------------------------------------------------

    /** One request: kind, which page, which extension, the user's answer, which login. */
    record Step(int kind, boolean onPageB, boolean fromExtB, int decision, int login) {
    }

    /** The decoded input. */
    static final class Scenario {
        boolean locked;
        final List<Step> steps = new ArrayList<>();
        String pageA = "";
        String pageB = "";
        final List<VaultPort.Login> logins = new ArrayList<>();

        static Scenario of(byte[] in) {
            Scenario s = new Scenario();
            s.locked = in.length > 0 && (in[0] & 1) != 0;
            int count = in.length > 1 ? (in[1] & BYTE) % (MAX_STEPS + 1) : 0;
            int pos = Math.min(in.length, FIRST_STEP);
            for (int i = 0; i < count && pos + STEP_BYTES <= in.length; i++) {
                int b = in[pos] & BYTE;
                s.steps.add(new Step(b % KINDS, ((b >>> PAGE_BIT) & 1) != 0, ((b >>> EXT_BIT) & 1) != 0,
                        (b >>> DECISION_SHIFT) % DECISIONS, in[pos + 1] & BYTE));
                pos += STEP_BYTES;
            }
            String text = new String(Arrays.copyOfRange(in, pos, in.length), StandardCharsets.UTF_8);
            String[] lines = text.split("\n", -1);
            s.pageA = lines[0];
            s.pageB = lines.length > 1 ? lines[1] : "";
            for (int i = FIRST_LOGIN_LINE; i < lines.length && s.logins.size() < MAX_LOGINS; i++) {
                s.logins.add(s.login(s.logins.size(), lines[i]));
            }
            return s;
        }

        private VaultPort.Login login(int index, String line) {
            String[] fields = line.split(FIELD_SPLIT, -1);
            List<String> urls = new ArrayList<>();
            if (!fields[0].isEmpty()) {
                for (String url : fields[0].split(URL_SPLIT, -1)) {
                    urls.add(expand(url));
                }
            }
            return new VaultPort.Login(loginId(index), field(fields, TITLE_FIELD), field(fields, USERNAME_FIELD), urls);
        }

        private String expand(String url) {
            if (url.isEmpty()) {
                return url;
            }
            char first = url.charAt(0);
            if (first == PAGE_A) {
                return pageA + url.substring(1);
            }
            return first == PAGE_B ? pageB + url.substring(1) : url;
        }

        private static String field(String[] fields, int i) {
            return i < fields.length ? fields[i].replace(HIGH_MARK, '\uD800').replace(LOW_MARK, '\uDC00') : "";
        }
    }

    static UUID loginId(int index) {
        return new UUID(index + 1L, index + 1L);
    }

    /** What the vault holds for login {@code index}: UTF-8 bytes, not ASCII only. */
    static byte[] stored(int index) {
        return ("s" + index + "é").getBytes(StandardCharsets.UTF_8);
    }

    // ---- one run --------------------------------------------------------------------------------

    /** The broker, the handlers and the vault for one input, and the oracle's running state. */
    static final class Run {
        private final Scenario s;
        private final FuzzClock clock = new FuzzClock();
        private final ApprovalBroker broker;
        private final FakeVault vault;
        private final Handler forA;
        private final Handler forB;
        private final List<ApprovalRequest> prompts = new ArrayList<>();
        private final Set<String> sessions = new HashSet<>();
        private int answer;

        Run(Scenario s) {
            this.s = s;
            this.vault = new FakeVault(s.logins);
            this.broker = new ApprovalBroker(clock, e -> { }, PolicyStore.inMemory(), "alice");
            broker.setPromptListener(() -> {
                List<PendingApproval> waiting = broker.pending();
                PendingApproval last = waiting.get(waiting.size() - 1);
                prompts.add(last.request());
                if (answer == DENY) {
                    last.deny();
                } else if (answer == SESSION) {
                    last.approveForSession();
                } else {
                    last.approveOnce();
                }
            });
            if (!s.locked) {
                broker.unlock();
            }
            Handler.Factory factory = Bridge.factory(vault, ApprovalPort.inProcess(broker, WAIT), clock,
                    new PasswordGenerator(counter()));
            this.forA = factory.forCaller(EXT_A);
            this.forB = factory.forCaller(EXT_B);
        }

        void all() {
            for (int i = 0; i < s.steps.size(); i++) {
                step("r" + i, s.steps.get(i));
            }
        }

        private void step(String id, Step step) {
            String ext = step.fromExtB() ? EXT_B : EXT_A;
            String pageText = step.onPageB() ? s.pageB : s.pageA;
            Canonical page = OriginOracle.parse(pageText);
            int index = step.login();
            boolean known = index < s.logins.size();
            VaultPort.Login login = known ? s.logins.get(index) : null;
            String username = known ? login.username() : "";
            int promptsBefore = prompts.size();
            int listedBefore = vault.listed;
            int releasedBefore = vault.released;
            int savedBefore = vault.saved.size();
            answer = step.decision();
            Object got = handle(step.fromExtB() ? forB : forA, request(id, step, pageText, known ? login.id() : UNKNOWN,
                    username));
            String label = id + " " + step + " page " + pageText;

            boolean reads = step.kind() == LOOKUP || step.kind() == FILL;
            if (s.locked || page == null) {
                assertEquals(s.locked ? "DENIED:DENIED_LOCKED" : "BAD_ORIGIN:BAD_ORIGIN", got, label);
                assertUntouched(promptsBefore, listedBefore, releasedBefore, savedBefore, label);
                return;
            }
            assertEquals(listedBefore + (reads ? 1 : 0), vault.listed, label + ": vault reads");
            if (step.kind() == LOOKUP) {
                assertEquals(lookupReply(id, page), got, label);
                assertEquals(promptsBefore, prompts.size(), label + ": lookup prompts");
                assertEquals(releasedBefore, vault.released, label);
                return;
            }
            if (step.kind() == FILL && (login == null || !registered(login, page))) {
                assertEquals("NOT_FOUND:NOT_FOUND", got, label);
                assertUntouched(promptsBefore, vault.listed, releasedBefore, savedBefore, label);
                return;
            }
            String profile = step.kind() == FILL ? fillProfile(login.id()) : step.kind() == SAVE ? "save" : "generate";
            String key = ext + ' ' + page.text() + ' ' + profile;
            boolean covered = sessions.contains(key);
            if (covered) {
                assertEquals(promptsBefore, prompts.size(), label + ": covered by a session approval");
            } else {
                assertEquals(promptsBefore + 1, prompts.size(), label + ": exactly one prompt");
                assertEquals(expectedPrompt(prompts.get(promptsBefore), ext, page, profile, step, login, username),
                        prompts.get(promptsBefore), label + ": prompt");
            }
            if (!covered && step.decision() == DENY) {
                assertEquals("DENIED:DENIED", got, label);
                assertUntouched(prompts.size(), vault.listed, releasedBefore, savedBefore, label);
                return;
            }
            if (!covered && step.decision() == SESSION) {
                sessions.add(key);
            }
            released(id, step, page, login, username, got, releasedBefore, savedBefore, label);
        }

        private void released(String id, Step step, Canonical page, VaultPort.Login login, String username,
                Object got, int releasedBefore, int savedBefore, String label) {
            Map<String, Object> want = new LinkedHashMap<>();
            if (step.kind() == FILL) {
                assertEquals(releasedBefore + 1, vault.released, label + ": one release");
                assertEquals(savedBefore, vault.saved.size(), label);
                want.put("type", "fill");
                want.put("id", id);
                want.put("origin", page.text());
                want.put("username", NativeHostFuzzTest.replaceUnpaired(login.username()));
                want.put("password", new String(stored(s.logins.indexOf(login)), StandardCharsets.UTF_8));
                assertEquals(want, got, label);
                return;
            }
            assertEquals(releasedBefore, vault.released, label);
            assertEquals(savedBefore + 1, vault.saved.size(), label + ": one save");
            Saved saved = vault.saved.get(savedBefore);
            assertEquals(page, canonical(saved.origin()), label + ": saved origin");
            assertEquals(username, saved.username(), label + ": saved username");
            boolean save = step.kind() == SAVE;
            want.put("type", save ? "save" : "generate");
            want.put("id", id);
            if (!save) {
                want.put("origin", page.text());
            }
            want.put("entry", saved.entry().toString());
            if (save) {
                assertEquals(typed(id), saved.text(), label + ": saved what was typed");
            } else {
                assertEquals(POLICY.length(), saved.text().length(), label + ": generated length");
                want.put("password", saved.text());
            }
            assertEquals(want, got, label);
        }

        private void assertUntouched(int promptsBefore, int listedBefore, int releasedBefore, int savedBefore,
                String label) {
            assertEquals(promptsBefore, prompts.size(), label + ": prompts");
            assertEquals(listedBefore, vault.listed, label + ": vault reads");
            assertEquals(releasedBefore, vault.released, label + ": releases");
            assertEquals(savedBefore, vault.saved.size(), label + ": saves");
        }

        private Map<String, Object> lookupReply(String id, Canonical page) {
            List<Object> entries = new ArrayList<>();
            for (VaultPort.Login login : s.logins) {
                if (entries.size() < MAX_LOOKUP && registered(login, page)) {
                    Map<String, Object> e = new LinkedHashMap<>();
                    e.put("entry", login.id().toString());
                    e.put("title", NativeHostFuzzTest.replaceUnpaired(login.title()));
                    e.put("username", NativeHostFuzzTest.replaceUnpaired(login.username()));
                    entries.add(e);
                }
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("type", "lookup");
            m.put("id", id);
            m.put("origin", page.text());
            m.put("entries", entries);
            return m;
        }

        private ApprovalRequest expectedPrompt(ApprovalRequest seen, String ext, Canonical page, String profile,
                Step step, VaultPort.Login login, String username) {
            String what;
            ApprovalRequest.Effect effect = ApprovalRequest.Effect.WRITE_FILE;
            if (step.kind() == FILL) {
                what = "fill login \"" + shown(login.title()) + "\", username \"" + shown(login.username()) + "\"";
                effect = ApprovalRequest.Effect.SEND;
            } else if (step.kind() == SAVE) {
                what = "save a new login, username \"" + shown(username) + "\"";
            } else {
                what = "generate a password, save it as a new login (username \"" + shown(username) + "\") and fill it";
            }
            return new ApprovalRequest(seen.requestId(),
                    new ApprovalRequest.Requester(ApprovalRequest.Kind.EXTENSION, ext),
                    ApprovalRequest.Operation.AUTOFILL,
                    new ApprovalRequest.Scope(page.text(), profile, Optional.empty(), List.of()),
                    Duration.ZERO,
                    new ApprovalRequest.Display(List.of(), Optional.of(page.text() + " - " + what), effect),
                    clock.instant());
        }
    }

    private static Request request(String id, Step step, String pageText, UUID entry, String username) {
        return switch (step.kind()) {
            case LOOKUP -> new Request.Lookup(id, pageText);
            case FILL -> new Request.Fill(id, pageText, entry);
            case SAVE -> new Request.Save(id, pageText, username, SecretChars.takeOwnership(typed(id).toCharArray()));
            default -> new Request.Generate(id, pageText, username, POLICY);
        };
    }

    /** What the page "typed" for a save: not ASCII only. */
    static String typed(String id) {
        return "t-" + id + "é";
    }

    /** The reply as the oracle reads it back, or {@code CODE:message} for an error. */
    private static Object handle(Handler handler, Request request) {
        try (request) {
            Json.Obj reply = handler.handle(request);
            try (SecretBytes utf8 = JsonText.toUtf8(reply)) {
                Object[] parsed = new Object[1];
                utf8.withBytes(b -> parsed[0] = JsonOracle.utf8(b.clone()));
                assertNotNull(parsed[0], "reply is UTF-8");
                return JsonOracle.parse((String) parsed[0], false);
            } finally {
                reply.wipe();
            }
        } catch (HostException e) {
            return e.code().name() + ":" + e.getMessage();
        } catch (Refused e) {
            throw new AssertionError("reply is not JSON", e);
        }
    }

    /** ADR 0014 §5: a login matches when one of its URLs has exactly the page's canonical origin. */
    static boolean registered(VaultPort.Login login, Canonical page) {
        for (String url : login.urls()) {
            if (page.equals(OriginOracle.ofUrl(url))) {
                return true;
            }
        }
        return false;
    }

    /** ADR 0014 §6: {@code fill-} and all 128 bits of the login id in base 36. */
    static String fillProfile(UUID id) {
        return "fill-" + new BigInteger(id.toString().replace("-", ""), HEX_RADIX).toString(PROFILE_RADIX);
    }

    /** At most 64 code points, C0, DEL and C1 controls shown as '?'. */
    static String shown(String text) {
        StringBuilder out = new StringBuilder();
        int i = 0;
        int points = 0;
        while (i < text.length() && points < MAX_SHOWN) {
            char c = text.charAt(i);
            boolean pair = Character.isHighSurrogate(c) && i + 1 < text.length()
                    && Character.isLowSurrogate(text.charAt(i + 1));
            int width = pair ? 2 : 1;
            boolean control = c <= LAST_C0 || (c >= FIRST_DELETE && c <= LAST_C1);
            if (control) {
                out.append(SHOWN_CONTROL);
            } else {
                out.append(text, i, i + width);
            }
            i += width;
            points++;
        }
        return out.toString();
    }

    /** A deterministic byte source for the generator: the harness checks policy and storage, not randomness. */
    private static IntFunction<byte[]> counter() {
        int[] next = {0};
        return n -> {
            byte[] b = new byte[n];
            for (int i = 0; i < n; i++) {
                b[i] = (byte) ((next[0]++ * 0x9E3779B1) >>> (Integer.SIZE - Byte.SIZE));
            }
            return b;
        };
    }

    /** One saved login. */
    record Saved(UUID entry, Origin origin, String username, String text) {
    }

    /** Logins in memory; counts reads, releases and saves; consumes every grant it is given. */
    static final class FakeVault implements VaultPort {
        private final List<Login> all;
        private final Map<UUID, Integer> indexes = new HashMap<>();
        final List<Saved> saved = new ArrayList<>();
        int listed;
        int released;

        FakeVault(List<Login> logins) {
            this.all = List.copyOf(logins);
            for (int i = 0; i < all.size(); i++) {
                indexes.put(all.get(i).id(), i);
            }
        }

        @Override
        public List<Login> logins() {
            listed++;
            return all;
        }

        @Override
        public SecretBytes password(Grant grant, UUID entry) {
            grant.consume();
            released++;
            return SecretBytes.copyOf(stored(indexes.get(entry)));
        }

        @Override
        public UUID save(Grant grant, Origin origin, String username, SecretChars typedChars) {
            grant.consume();
            UUID entry = new UUID(SAVED_HIGH, saved.size());
            char[][] copy = new char[1][];
            typedChars.withChars(c -> copy[0] = c.clone());
            saved.add(new Saved(entry, origin, username, String.valueOf(copy[0])));
            Arrays.fill(copy[0], '\0');
            return entry;
        }
    }

    // ---- deterministic checks (run in the gate) ------------------------------------------------

    /** A registered URL, a page origin, and whether ADR 0014 §5 says they are the same origin. */
    record Pair(String url, String page, boolean same) {
    }

    /** The ADR 0014 §5 examples and their neighbours: subdomain, scheme, port and lookalike confusion. */
    static final List<Pair> PAIRS = List.of(
            new Pair("https://example.com/login", "https://example.com", true),
            new Pair("https://EXAMPLE.com:443/", "https://example.com", true),
            new Pair("HTTPS://example.com?q#f", "https://example.com", true),
            new Pair("https://example.com:8443/x", "https://example.com:8443", true),
            new Pair("http://127.0.0.1:80/", "http://127.0.0.1", true),
            new Pair("http://example.com/", "https://example.com", false),
            new Pair("https://example.com:80/", "http://example.com", false),
            new Pair("https://example.com:80/", "https://example.com:80", true),
            new Pair("http://example.com:443/", "http://example.com:443", true),
            new Pair("https://example.com:443/", "https://example.com:443", true),
            new Pair("http://example.com:80/", "http://example.com:80", true),
            new Pair("https://example.com/", "https://example.com:80", false),
            new Pair("https://example.com:80/", "https://example.com", false),
            new Pair("http://example.com/", "http://example.com:443", false),
            new Pair("http://example.com:443/", "http://example.com", false),
            new Pair("https://a.example.com/", "https://example.com", false),
            new Pair("https://example.com/", "https://a.example.com", false),
            new Pair("https://example.com:8443/", "https://example.com", false),
            new Pair("https://example.com/", "https://example.com:8443", false),
            new Pair("https://example.com.evil.net/", "https://example.com", false),
            new Pair("https://evil.net/https://example.com", "https://example.com", false),
            new Pair("https://example.com@evil.net/", "https://example.com", false),
            new Pair("https://evil.net#@example.com", "https://example.com", false),
            new Pair("https://example.com\\@evil.net/", "https://example.com", false),
            new Pair("example.com", "https://example.com", false),
            new Pair("android://example.com", "https://example.com", false),
            new Pair("https://example.com./", "https://example.com", false),
            new Pair("https://example.com:0443/", "https://example.com", false),
            new Pair("https://example.com:443:443/", "https://example.com", false),
            new Pair("https://example.com:/", "https://example.com", false),
            new Pair("https://apple.com/", "https://xn--pple-43d.com", false),
            new Pair("https://аpple.com/", "https://apple.com", false),
            new Pair("https://faß.de/", "https://fass.de", false),
            new Pair("https://EXAMPLEK.com/", "https://examplek.com", false),
            new Pair("http://0x7f.0.0.1/", "http://127.0.0.1", false),
            new Pair("http://2130706433/", "http://127.0.0.1", false),
            new Pair("http://127.1/", "http://127.0.0.1", false),
            new Pair("http://010.0.0.1/", "http://10.0.0.1", false),
            new Pair("http://[::1]/", "http://[::1]", false),
            new Pair("https://exa_mple.com/", "https://exa_mple.com", false),
            new Pair("https://-example.com/", "https://-example.com", false),
            new Pair("https://example.com/", "https://example.com/", false));

    /**
     * Each pair is the same origin exactly when ADR 0014 §5 says so, by the oracle, by the
     * production {@code Origin} and through the bridge's {@code lookup}.
     */
    @Test
    void subdomainSchemePortAndLookalikeConfusionIsRefused() {
        for (Pair p : PAIRS) {
            Canonical page = OriginOracle.parse(p.page());
            assertEquals(p.same(), page != null && page.equals(OriginOracle.ofUrl(p.url())), "oracle " + p);
            Optional<Origin> url = Origin.ofUrl(p.url());
            boolean same;
            try {
                same = url.isPresent() && url.get().equals(Origin.parse(p.page()));
            } catch (HostException e) {
                same = false;
            }
            assertEquals(p.same(), same, "Origin " + p);
            fuzz(scenario(false, new int[] {LOOKUP, 0}, p.page() + "\n\n" + p.url()));
        }
    }

    /** An input with {@code steps} (two bytes each) and the given text. */
    static byte[] scenario(boolean locked, int[] steps, String text) {
        byte[] body = text.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[FIRST_STEP + steps.length + body.length];
        out[0] = (byte) (locked ? 1 : 0);
        out[1] = (byte) (steps.length / STEP_BYTES);
        for (int i = 0; i < steps.length; i++) {
            out[FIRST_STEP + i] = (byte) steps[i];
        }
        System.arraycopy(body, 0, out, FIRST_STEP + steps.length, body.length);
        return out;
    }

    /** Each committed seed, and what the bridge must answer to each of its requests. */
    static final Map<String, List<String>> SEED_OUTCOMES = Map.of(
            "lookup-match.bin", List.of("lookup:2"),
            "fill-once.bin", List.of("fill", "NOT_FOUND:NOT_FOUND"),
            "fill-session.bin", List.of("fill", "fill", "DENIED:DENIED"),
            "save-generate.bin", List.of("save", "generate", "generate", "DENIED:DENIED"),
            "locked.bin", List.of("DENIED:DENIED_LOCKED", "DENIED:DENIED_LOCKED"),
            "bad-origin.bin", List.of("BAD_ORIGIN:BAD_ORIGIN", "BAD_ORIGIN:BAD_ORIGIN"),
            "confusables.bin", List.of("lookup:0", "lookup:1"),
            "surrogate-titles.bin", List.of("lookup:1", "fill"),
            "default-port-https.bin", List.of("lookup:1", "fill", "save", "DENIED:DENIED"),
            "default-port-http.bin", List.of("lookup:1", "generate", "DENIED:DENIED", "fill"));

    /** Every seed ends as its name says, and the full oracle accepts the bridge's behaviour on it. */
    @Test
    void everySeedEndsAsItsNameSays() throws IOException {
        for (Map.Entry<String, List<String>> seed : SEED_OUTCOMES.entrySet()) {
            byte[] file = Seeds.read(OriginFuzzTest.class, seed.getKey());
            Scenario s = Scenario.of(file);
            Run run = new Run(s);
            List<String> seen = new ArrayList<>();
            for (int i = 0; i < s.steps.size(); i++) {
                Step step = s.steps.get(i);
                String pageText = step.onPageB() ? s.pageB : s.pageA;
                boolean known = step.login() < s.logins.size();
                run.answer = step.decision();
                Object got = handle(step.fromExtB() ? run.forB : run.forA, request("r" + i, step, pageText,
                        known ? s.logins.get(step.login()).id() : UNKNOWN, known ? s.logins.get(step.login()).username()
                        : ""));
                seen.add(summary(got));
            }
            assertEquals(seed.getValue(), seen, seed.getKey());
            fuzz(file);
        }
    }

    private static String summary(Object got) {
        if (got instanceof Map<?, ?> m) {
            Object type = m.get("type");
            return "lookup".equals(type) ? type + ":" + ((List<?>) m.get("entries")).size() : (String) type;
        }
        return (String) got;
    }

    /** The oracle's shown text: 64 code points, a pair counts once, controls become '?'. */
    @Test
    void shownTextFollowsTheAdr() {
        assertEquals("a?b?c?", shown("a\u0000b\u007fc\u0085"));
        assertEquals("x".repeat(MAX_SHOWN), shown("x".repeat(MAX_SHOWN + 1)));
        String pairs = "😀".repeat(MAX_SHOWN + 1);
        assertEquals(pairs.substring(0, 2 * MAX_SHOWN), shown(pairs));
        assertTrue(shown("\uD800").equals("\uD800"), "a lone surrogate is kept for the prompt");
    }
}
