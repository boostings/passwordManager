package pm.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import pm.browser.host.ExtensionAllowlist;
import pm.browser.host.Handler;
import pm.browser.host.HostException;
import pm.browser.host.Json;
import pm.browser.host.NativeHost;
import pm.browser.host.Request;
import pm.crypto.SecretChars;
import pm.fuzz.JsonOracle.Null;
import pm.fuzz.JsonOracle.Refused;

/**
 * Fuzz harness for the native messaging host (SR-301, SR-303, SR-305; T-FUZZ-NM). Every input is
 * one browser connection to the production entry point {@link NativeHost#runWithoutPasskeys} (the
 * one {@code pm browser-host} calls; v1 serves no passkeys, so {@code webauthn.*} requests must get
 * the reply of an unknown type, which the oracle's schema already predicts): fuzzer-chosen
 * command-line arguments, a fuzzer-chosen stdin and a scripted {@link Handler} standing in for the
 * bridge. Nothing is called below {@code run}, so framing, UTF-8, JSON, schema, the caller check
 * and reply encoding are all reached the way Chrome reaches them.
 *
 * <p>The oracle is the harness's own model of ADR 0014 §2–§4, written from the ADR and the RFCs
 * it names rather than from {@code pm.browser.host} (see {@link JsonOracle}). For each input it
 * computes the exact outcome and compares:
 *
 * <ul>
 *   <li>the caller: exactly {@code chrome-extension://<32 a-p>/} with an allowlisted ID, plus at
 *       most {@code --parent-window=<digits>}. A refused caller must give exit 2 with zero stdin
 *       bytes read, zero bytes written and no handler created;</li>
 *   <li>framing: little-endian u32 length, 1..1 MiB. A length of zero or past 1 MiB must give one
 *       {@code FRAME_SIZE} reply and exit 3 after reading exactly the four header bytes;</li>
 *   <li>every reply, parsed back by the oracle, must equal the expected one exactly, including
 *       the exact error code and whether {@code id} is echoed; the handler must receive exactly
 *       the requests the oracle accepted, field by field, and every {@code save} password must be
 *       wiped once answered;</li>
 *   <li>the thread's allocation is bounded by a constant plus a per-byte term of the input, plus a
 *       fixed allowance per reply the script pads to the 1 MiB outbound limit.</li>
 * </ul>
 *
 * <p>Input layout, after {@link Stretch#apply} with a cap just over 1 MiB (so a 4 KiB libFuzzer
 * input can carry a full-size frame or one just past the limit): byte 0 picks the caller form,
 * byte 1 is the length of the handler script that follows, mode 5 then has a length byte and the
 * raw argument text, and everything after that is stdin.
 *
 * <p>Where ADR 0014 is silent the harness restates the host's documented rule, and
 * docs/security/fuzz/M5-fuzz-runs.md lists each one: {@code type} must be a 1–16 unit string
 * without controls (else {@code BAD_FIELD}, before {@code UNKNOWN_TYPE}); a {@code hello} is
 * checked for {@code VERSION} before its {@code id}; "no controls" means U+0000–U+001F and U+007F;
 * "printable ASCII" means U+0021–U+007E; the parent-window handle has 1–20 digits.
 */
@Tag("T-FUZZ-NM")
@Tag("T-EXT-02")
@Tag("T-EXT-05")
class NativeHostFuzzTest {
    /** ADR 0014 §2, SR-303: 1 MiB in each direction. */
    static final int ONE_MIB = 1 << 20;
    /** Largest run {@link Stretch} may insert: a full 1 MiB body with room past the limit. */
    static final int STRETCH_CAP = ONE_MIB + (64 << 10);
    /** ADR 0014 §2: a normal close. */
    static final int EXIT_CLOSED = 0;
    /** ADR 0014 §4: the caller is refused. */
    static final int EXIT_REFUSED = 2;
    /** ADR 0014 §2: a framing error ends the session. */
    static final int EXIT_FRAMING = 3;
    static final String EXT_A = "abcdefghijklmnopabcdefghijklmnop";
    static final String EXT_B = "ponmlkjihgfedcbaponmlkjihgfedcba";
    /** A well-formed extension ID that is not on the allowlist. */
    static final String EXT_OTHER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static final String ORIGIN_PREFIX = "chrome-extension://";
    static final String PARENT_WINDOW = "--parent-window=";

    private static final Set<String> ALLOWED = Set.of(EXT_A, EXT_B);
    private static final ExtensionAllowlist ALLOWLIST = ExtensionAllowlist.of(ALLOWED);
    private static final int ID_LENGTH = 32;
    private static final int MAX_WINDOW_DIGITS = 20;
    private static final String DIGITS = "12345678901234567890123456789012";
    private static final int HEADER = 4;
    private static final int BYTE = 0xFF;
    private static final int MODES = 8;
    private static final int MODE_A = 0;
    private static final int MODE_B = 1;
    private static final int MODE_WINDOW = 2;
    private static final int MODE_OTHER = 3;
    private static final int MODE_NEAR_MISS = 4;
    private static final int MODE_RAW = 5;
    private static final int MODE_A_AGAIN = 6;
    private static final int SELECTOR_SHIFT = 3;
    private static final int WINDOW_DIGIT_MASK = 31;

    /** ADR 0014 §3 schema. */
    private static final int MAX_TYPE = 16;
    private static final int MAX_ID = 64;
    private static final int MAX_ORIGIN = 256;
    private static final int MAX_USERNAME = 1_024;
    private static final int MAX_PASSWORD = 4_096;
    private static final long MIN_POLICY = 8;
    private static final long MAX_POLICY = 128;
    private static final int UUID_LENGTH = 36;
    private static final Set<Integer> UUID_HYPHENS = Set.of(8, 13, 18, 23);
    private static final char FIRST_PRINTABLE = 0x20;
    private static final char DELETE = 0x7F;
    private static final char FIRST_VISIBLE = 0x21;
    private static final char LAST_VISIBLE = 0x7E;
    private static final char HYPHEN = '-';
    private static final String HELLO = "hello";
    private static final Long VERSION = 1L;
    private static final Map<String, Set<String>> MEMBERS = Map.of(
            HELLO, Set.of("type", "id", "version"),
            "lookup", Set.of("type", "id", "origin"),
            "fill", Set.of("type", "id", "origin", "entry"),
            "save", Set.of("type", "id", "origin", "username", "password"),
            "generate", Set.of("type", "id", "origin", "username", "policy"));
    private static final Set<String> POLICY_MEMBERS = Set.of("length", "lower", "upper", "digits", "symbols");

    /** Handler behaviours, by script byte (low three bits). */
    private static final int THROW_HOST = 2;
    private static final int THROW_RUNTIME = 3;
    private static final int UNENCODABLE = 4;
    private static final int PAD = 5;
    private static final int PAD_DELTAS = 8;
    private static final int PAD_CENTRE = 4;
    /** Non-secret strings a handler may put in a reply; unpaired surrogates must become U+FFFD. */
    private static final List<String> TITLES = List.of("Example", "", "\uD800", "a\uDC00b", "😀",
            "\uDE00\uD83D", "x\uD800𐀀", "\u0000\u001f\"\\/\u007f", "é ﻿", "\uDBFF");
    private static final HostException.Code[] CODES = HostException.Code.values();
    private static final String LEAK = "exception text must not reach the extension";
    private static final char REPLACEMENT = '�';

    /**
     * Allocation ceiling: a constant tied to the inbound limit, a per-byte term for the input, and one
     * allowance per padded reply. Eight times the 1 MiB frame limit is far below what a buffer sized
     * from an unchecked u32 length could take (up to 4 GiB); a bound loosened by less than that is
     * caught by the framing oracle (exact bytes read and {@code FRAME_SIZE}), not by this one.
     */
    private static final long ALLOC_BASE = 8L * ONE_MIB;
    private static final long ALLOC_PER_BYTE = 64;
    private static final long ALLOC_PER_PAD = 64L << 20;

    @FuzzTest
    void fuzz(byte[] in) throws IOException {
        assertTrue(Warm.RUNS > 0, "warm-up ran before the first measurement");
        assertEquals(List.of(), FIRST_CALL_ONLY, "warm-up inputs that threw on the first call only");
        byte[] data = Stretch.apply(in, STRETCH_CAP);
        Layout layout = Layout.of(data);
        List<String> args = layout.args();
        String expectedCaller = callerOf(args);
        Scripted handlers = new Scripted(layout.script());
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        int exit;
        long consumed;
        long allocated;
        try (Counting stdin = new Counting(layout.stdin())) {
            long before = Allocation.current();
            exit = NativeHost.runWithoutPasskeys(args, ALLOWLIST, stdin, stdout, handlers);
            allocated = Allocation.current() - before;
            consumed = stdin.consumed();
        }
        if (expectedCaller == null) {
            assertEquals(EXIT_REFUSED, exit, "refused caller");
            assertEquals(0, consumed, "stdin bytes read for a refused caller");
            assertEquals(0, stdout.size(), "bytes written for a refused caller");
            assertEquals(List.of(), handlers.callers, "handler created for a refused caller");
            return;
        }
        assertEquals(List.of(expectedCaller), handlers.callers, "verified caller");
        Model want = Model.of(layout.stdin(), layout.script());
        assertEquals(want.exit, exit, "exit status");
        assertEquals(want.consumed, consumed, "stdin bytes read");
        assertEquals(want.calls, handlers.snapshots, "requests delivered to the handler");
        assertEquals(want.replies, replies(stdout.toByteArray()), "replies");
        assertTrue(handlers.saved.stream().allMatch(SecretChars::isClosed), "save password wiped after the reply");
        long ceiling = ALLOC_BASE + ALLOC_PER_BYTE * data.length + ALLOC_PER_PAD * want.pads;
        long cost = allocated;
        assertTrue(cost <= ceiling, () -> "allocated " + cost + " > " + ceiling);
    }

    // ---- warm-up (m55-001) ----------------------------------------------------------------------

    /**
     * Every measured input's allocation is judged on its one run in this JVM, after the warm-up.
     * That is close to how a hostile header meets the host in production: Chrome starts a new host
     * process for each connection, so a buffer that is
     * grown once and then kept is paid for in full by the first frame that grows it. The first run
     * along a path also loads its classes on this thread (and, in fuzzing mode, instruments them),
     * and the allocation counter would charge that to the input (about 52 MB at M5.5's first plant
     * round). So {@link #warmUp} drives every path once before the first measurement. Its replies
     * are not judged, but an input that throws on its first run and not on its second is recorded
     * as a fault only a new process would show, and fails every test ({@link #FIRST_CALL_ONLY}).
     * Its largest header is 1 MiB + 1, so only a measured input can grow a header-sized buffer kept
     * between calls past the ceiling.
     */
    private static final class Warm {
        static final int RUNS = warmUp();

        private Warm() {
        }
    }

    /**
     * Runs the host over each request type with every handler behaviour, each schema limit and the
     * value past it, each decode and framing error, each caller form, and the committed seeds found
     * on the class path. The seed proofs withhold the seeds, so the frames built here stand alone.
     * Nothing is judged here, not even an unchecked exception out of the host: every input below is
     * also a seed, an edge or a caller form that a test judges, and a broken warm-up would fail the
     * whole class with one {@code ExceptionInInitializerError} instead of naming the input.
     *
     * @return the number of inputs the host returned from without throwing
     */
    private static int warmUp() {
        String origin = "\"https://a.example\"";
        byte[] hello = frame("{\"type\":\"hello\",\"id\":\"h\",\"version\":1}");
        byte[][] everyType = {hello,
            frame("{\"type\":\"lookup\",\"id\":\"l\",\"origin\":" + origin + "}"),
            frame("{\"type\":\"fill\",\"id\":\"f\",\"origin\":" + origin
                    + ",\"entry\":\"0000000a-0000-0000-0000-000000000000\"}"),
            frame("{\"type\":\"save\",\"id\":\"s\",\"origin\":" + origin + ",\"username\":\"u\",\"password\":\"p\"}"),
            frame("{\"type\":\"generate\",\"id\":\"g\",\"origin\":" + origin + ",\"username\":\"u\",\"policy\":"
                    + "{\"length\":16,\"lower\":true,\"upper\":true,\"digits\":true,\"symbols\":true}}"),
            frame("{\"type\":\"webauthn.get\",\"id\":\"w\"}"),
            frame("{\"type\":\"webauthn.create\",\"id\":\"c\"}")};
        List<byte[]> inputs = new ArrayList<>();
        for (int s = 0; s <= BYTE; s++) {
            inputs.add(input(MODE_A, new byte[] {(byte) s}, everyType));
        }
        for (Edge edge : edges()) {
            inputs.add(input(MODE_A, new byte[] {0}, frame(edge.json())));
        }
        String small = "{\"type\":\"hello\",\"id\":\"h\",\"version\":1}";
        inputs.add(input(MODE_A, new byte[0], frame(new byte[] {(byte) 0xC0, (byte) 0x80}), frame("{"), frame("[]"),
                frame("null"), frame("{\"type\":1}"), frame("{\"type\":\"nope\"}"),
                frame("{\"type\":\"hello\",\"type\":\"hello\"}"), frame("{\"type\":\"lookup\",\"id\":\"l\"}"),
                frame("{\"type\":\"hello\",\"id\":\"h\",\"version\":2}"),
                frame(small + " ".repeat(ONE_MIB - small.length()))));
        inputs.add(input(MODE_A, new byte[0], hello, lengthPrefix(0)));
        inputs.add(input(MODE_A, new byte[0], hello, lengthPrefix(ONE_MIB + 1L)));
        inputs.add(input(MODE_A, new byte[0], hello, new byte[] {1, 0}));
        inputs.add(input(MODE_A, new byte[0], hello, lengthPrefix(HEADER + HEADER), new byte[] {'{'}));
        byte[][] helloOnly = {hello};
        for (int mode = 0; mode < MODES; mode++) {
            inputs.add(input(mode, new byte[0], helloOnly));
        }
        for (int i = 0; i < NEAR_MISSES.size(); i++) {
            inputs.add(input(MODE_NEAR_MISS | (i << SELECTOR_SHIFT), new byte[0], helloOnly));
        }
        for (int digits = 0; digits <= MAX_WINDOW_DIGITS + 1; digits++) {
            inputs.add(input(MODE_WINDOW | (digits << SELECTOR_SHIFT), new byte[0], helloOnly));
        }
        byte[] raw = (originOf(EXT_A) + "\n" + PARENT_WINDOW + "7").getBytes(StandardCharsets.UTF_8);
        inputs.add(input(MODE_RAW, new byte[0], new byte[] {(byte) raw.length}, raw, hello));
        for (String name : SEED_OUTCOMES.keySet()) {
            try (InputStream seed = NativeHostFuzzTest.class.getResourceAsStream("NativeHostFuzzTestInputs/" + name)) {
                if (seed != null) {
                    inputs.add(seed.readAllBytes());
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        int returned = 0;
        List<byte[]> threw = new ArrayList<>();
        for (byte[] in : inputs) {
            if (runUnjudged(in) == null) {
                returned++;
            } else {
                threw.add(in); // left to the test that judges the same input (see the method comment)
            }
        }
        // m55b-002: production starts a new host process per connection, so a fault that only the
        // first call in a process shows (a lazy initialiser, a "first frame" flag) would hit every
        // connection. An input that threw here and no longer throws is exactly that fault.
        for (byte[] in : threw) {
            if (runUnjudged(in) == null) {
                FIRST_CALL_ONLY.add(Arrays.toString(Arrays.copyOf(in, Math.min(in.length, 64))));
            }
        }
        return returned;
    }

    /** Warm-up inputs that threw out of the host on their first run and not on their second. */
    private static final List<String> FIRST_CALL_ONLY = new ArrayList<>();

    /** Runs the host once over {@code in}, judging nothing; the unchecked exception it threw, or null. */
    private static RuntimeException runUnjudged(byte[] in) {
        Layout layout = Layout.of(Stretch.apply(in, STRETCH_CAP));
        try (Counting stdin = new Counting(layout.stdin())) {
            NativeHost.runWithoutPasskeys(layout.args(), ALLOWLIST, stdin, new ByteArrayOutputStream(),
                    new Scripted(layout.script()));
            return null;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (RuntimeException e) {
            return e;
        }
    }

    /** No host fault shows only on the first call in a process (m55b-002). */
    @Test
    void noFaultShowsOnlyOnTheFirstCallInAProcess() {
        assertTrue(Warm.RUNS > 0, "warm-up ran");
        assertEquals(List.of(), FIRST_CALL_ONLY, "inputs that threw on the first call only");
    }

    // ---- caller (ADR 0014 §4) -----------------------------------------------------------------

    /** The extension ID ADR 0014 §4 admits for {@code args}, or null. */
    static String callerOf(List<String> args) {
        if (args.isEmpty() || args.size() > 2) {
            return null;
        }
        if (args.size() == 2 && !isParentWindow(args.get(1))) {
            return null;
        }
        String origin = args.get(0);
        int idEnd = ORIGIN_PREFIX.length() + ID_LENGTH;
        if (origin.length() != idEnd + 1 || !origin.startsWith(ORIGIN_PREFIX) || origin.charAt(idEnd) != '/') {
            return null;
        }
        String id = origin.substring(ORIGIN_PREFIX.length(), idEnd);
        for (int i = 0; i < id.length(); i++) {
            if (!isIdLetter(id.charAt(i))) {
                return null;
            }
        }
        return ALLOWED.contains(id) ? id : null;
    }

    private static boolean isIdLetter(char c) {
        return c >= 'a' && c <= 'p';
    }

    private static boolean isParentWindow(String arg) {
        if (!arg.startsWith(PARENT_WINDOW)) {
            return false;
        }
        String digits = arg.substring(PARENT_WINDOW.length());
        if (digits.isEmpty() || digits.length() > MAX_WINDOW_DIGITS) {
            return false;
        }
        for (int i = 0; i < digits.length(); i++) {
            if (!isAsciiDigit(digits.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isAsciiDigit(char c) {
        return c >= '0' && c <= '9';
    }

    static String originOf(String id) {
        return ORIGIN_PREFIX + id + "/";
    }

    /** Argument lists that are close to, but not, an admitted caller. */
    static final List<List<String>> NEAR_MISSES = List.of(
            List.of(),
            List.of(""),
            List.of(ORIGIN_PREFIX + EXT_A),
            List.of(ORIGIN_PREFIX + EXT_A + "//"),
            List.of(ORIGIN_PREFIX + EXT_A + "/x"),
            List.of("Chrome-extension://" + EXT_A + "/"),
            List.of("chrome-extension:/" + EXT_A + "/"),
            List.of("moz-extension://" + EXT_A + "/"),
            List.of(originOf("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP")),
            List.of(originOf(EXT_A.substring(1))),
            List.of(originOf(EXT_A + "a")),
            List.of(originOf("q" + EXT_A.substring(1))),
            List.of(" " + originOf(EXT_A)),
            List.of(originOf(EXT_A) + " "),
            List.of(originOf(EXT_A) + "\n"),
            List.of(originOf(EXT_A), PARENT_WINDOW),
            List.of(originOf(EXT_A), PARENT_WINDOW + "-1"),
            List.of(originOf(EXT_A), PARENT_WINDOW + "1 "),
            List.of(originOf(EXT_A), PARENT_WINDOW + "１"),
            List.of(originOf(EXT_A), "--parent-window"),
            List.of(originOf(EXT_A), PARENT_WINDOW + "1", "x"),
            List.of(PARENT_WINDOW + "1", originOf(EXT_A)),
            List.of(originOf(EXT_A), originOf(EXT_B)),
            List.of(originOf(EXT_A), PARENT_WINDOW + DIGITS.substring(0, MAX_WINDOW_DIGITS + 1)),
            List.of(originOf(EXT_OTHER)),
            List.of(originOf(EXT_A) + "\u0000"));

    // ---- input layout -------------------------------------------------------------------------

    /** The decoded input: caller arguments, handler script and stdin. */
    static final class Layout {
        private final List<String> argList;
        private final byte[] scriptBytes;
        private final byte[] stdinBytes;

        private Layout(List<String> args, byte[] script, byte[] stdin) {
            this.argList = args;
            this.scriptBytes = script;
            this.stdinBytes = stdin;
        }

        List<String> args() {
            return argList;
        }

        byte[] script() {
            return scriptBytes.clone();
        }

        byte[] stdin() {
            return stdinBytes.clone();
        }

        static Layout of(byte[] data) {
            int mode = at(data, 0);
            int scriptLength = at(data, 1);
            int pos = Math.min(data.length, 2);
            byte[] script = Arrays.copyOfRange(data, pos, Math.min(data.length, pos + scriptLength));
            pos += script.length;
            List<String> args;
            int selector = mode >>> SELECTOR_SHIFT;
            switch (mode % MODES) {
                case MODE_A, MODE_A_AGAIN -> args = List.of(originOf(EXT_A));
                case MODE_B -> args = List.of(originOf(EXT_B));
                case MODE_WINDOW -> args = List.of(originOf(EXT_A),
                        PARENT_WINDOW + DIGITS.substring(0, selector & WINDOW_DIGIT_MASK));
                case MODE_OTHER -> args = List.of(originOf(EXT_OTHER));
                case MODE_NEAR_MISS -> args = NEAR_MISSES.get(selector % NEAR_MISSES.size());
                case MODE_RAW -> {
                    int length = at(data, pos);
                    pos = Math.min(data.length, pos + 1);
                    int end = Math.min(data.length, pos + length);
                    String text = new String(Arrays.copyOfRange(data, pos, end), StandardCharsets.UTF_8);
                    pos = end;
                    args = length == 0 ? List.of() : List.of(text.split("\n", -1));
                }
                default -> args = List.of(originOf(EXT_B), PARENT_WINDOW + "0");
            }
            return new Layout(args, script, Arrays.copyOfRange(data, pos, data.length));
        }

        private static int at(byte[] data, int i) {
            return i < data.length ? data[i] & BYTE : 0;
        }
    }

    // ---- scripted handler (the environment, not the oracle) -----------------------------------

    static int scriptByte(byte[] script, int call) {
        return script.length == 0 ? 0 : script[call % script.length] & BYTE;
    }

    /** Overhead of the compact pad reply around {@code n} pad characters. */
    static int padOverhead(String type, String id) {
        return ("{\"type\":\"" + type + "\",\"id\":\"" + id + "\",\"pad\":\"\"}").length();
    }

    static int padLength(int scriptByte, String type, String id) {
        int delta = (scriptByte >>> SELECTOR_SHIFT) % PAD_DELTAS - PAD_CENTRE;
        return ONE_MIB + delta - padOverhead(type, id);
    }

    private static final Map<Class<?>, String> TYPES = Map.of(Request.Hello.class, HELLO, Request.Lookup.class,
            "lookup", Request.Fill.class, "fill", Request.Save.class, "save", Request.Generate.class, "generate");

    static String typeOf(Request r) {
        return TYPES.get(r.getClass());
    }

    /** Creates itself as the handler, records what it is given and answers from the script. */
    static final class Scripted implements Handler.Factory, Handler {
        private final byte[] script;
        final List<String> callers = new ArrayList<>();
        final List<Map<String, Object>> snapshots = new ArrayList<>();
        final List<SecretChars> saved = new ArrayList<>();

        Scripted(byte[] script) {
            this.script = script.clone();
        }

        @Override
        public Handler forCaller(String extensionId) {
            callers.add(extensionId);
            return this;
        }

        @Override
        public Json.Obj handle(Request request) throws HostException {
            int s = scriptByte(script, snapshots.size());
            snapshots.add(snapshot(request));
            String type = typeOf(request);
            Map<String, Json> reply = new LinkedHashMap<>();
            reply.put("type", Json.Str.of(type));
            reply.put("id", Json.Str.of(request.id()));
            switch (s % MODES) {
                case THROW_HOST -> throw new HostException(CODES[(s >>> SELECTOR_SHIFT) % CODES.length]);
                case THROW_RUNTIME -> throw new IllegalStateException(LEAK);
                case UNENCODABLE -> {
                    try (SecretChars unpaired = SecretChars.takeOwnership(new char[] {'x', '\uD800'})) {
                        reply.put("password", Json.Str.of(unpaired));
                    }
                }
                case PAD -> reply.put("pad", Json.Str.of("a".repeat(padLength(s, type, request.id()))));
                default -> reply.put("title", Json.Str.of(TITLES.get((s >>> SELECTOR_SHIFT) % TITLES.size())));
            }
            return new Json.Obj(reply);
        }

        /** The request as the oracle's parsed tree would show it. */
        private Map<String, Object> snapshot(Request request) {
            Map<String, Object> m = new LinkedHashMap<>();
            String type = typeOf(request);
            m.put("type", type);
            m.put("id", request.id());
            switch (type) {
                case HELLO -> m.put("version", VERSION);
                case "lookup" -> m.put("origin", ((Request.Lookup) request).origin());
                case "fill" -> {
                    m.put("origin", ((Request.Fill) request).origin());
                    m.put("entry", ((Request.Fill) request).entry().toString());
                }
                case "save" -> saveFields(m, (Request.Save) request);
                default -> generateFields(m, (Request.Generate) request);
            }
            return m;
        }

        private void saveFields(Map<String, Object> m, Request.Save request) {
            saved.add(request.password());
            m.put("origin", request.origin());
            m.put("username", request.username());
            char[][] typed = new char[1][];
            request.password().withChars(c -> typed[0] = c.clone());
            m.put("password", String.valueOf(typed[0]));
            Arrays.fill(typed[0], '\0');
        }

        private static void generateFields(Map<String, Object> m, Request.Generate request) {
            m.put("origin", request.origin());
            m.put("username", request.username());
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("length", (long) request.policy().length());
            p.put("lower", request.policy().lower());
            p.put("upper", request.policy().upper());
            p.put("digits", request.policy().digits());
            p.put("symbols", request.policy().symbols());
            m.put("policy", p);
        }
    }

    // ---- the oracle's model of one connection (ADR 0014 §2, §3) --------------------------------

    /** What the host must do with {@code stdin}: replies, handler calls, exit status, bytes read. */
    static final class Model {
        final List<Map<String, Object>> replies = new ArrayList<>();
        final List<Map<String, Object>> calls = new ArrayList<>();
        int exit;
        long consumed;
        int pads;

        static Model of(byte[] stdin, byte[] script) {
            Model m = new Model();
            int pos = 0;
            while (true) {
                int left = stdin.length - pos;
                if (left == 0) {
                    return m.end(EXIT_CLOSED, pos);
                }
                if (left < HEADER) {
                    m.replies.add(error(null, "TRUNCATED"));
                    return m.end(EXIT_FRAMING, stdin.length);
                }
                long length = littleEndian(stdin, pos);
                if (length == 0 || length > ONE_MIB) {
                    m.replies.add(error(null, "FRAME_SIZE"));
                    return m.end(EXIT_FRAMING, pos + HEADER);
                }
                if (left - HEADER < length) {
                    m.replies.add(error(null, "TRUNCATED"));
                    return m.end(EXIT_FRAMING, stdin.length);
                }
                m.answer(Arrays.copyOfRange(stdin, pos + HEADER, pos + HEADER + (int) length), script);
                pos += HEADER + (int) length;
            }
        }

        private Model end(int status, long read) {
            exit = status;
            consumed = read;
            return this;
        }

        private void answer(byte[] body, byte[] script) {
            String text = JsonOracle.utf8(body);
            if (text == null) {
                replies.add(error(null, "BAD_UTF8"));
                return;
            }
            Object root;
            try {
                root = JsonOracle.parse(text, true);
            } catch (Refused e) {
                replies.add(error(null, "MALFORMED"));
                return;
            }
            String code = schemaError(root);
            if (code != null) {
                replies.add(error(null, code));
                return;
            }
            Map<?, ?> request = (Map<?, ?>) root;
            String type = (String) request.get("type");
            String id = (String) request.get("id");
            if (HELLO.equals(type)) {
                Map<String, Object> hello = reply(HELLO, id);
                hello.put("version", VERSION);
                replies.add(hello);
                return;
            }
            int s = scriptByte(script, calls.size());
            Map<String, Object> call = new LinkedHashMap<>();
            request.forEach((k, v) -> call.put((String) k, v));
            calls.add(call);
            replies.add(handlerReply(s, type, id));
        }

        private Map<String, Object> handlerReply(int s, String type, String id) {
            return switch (s % MODES) {
                case THROW_HOST -> error(id, CODES[(s >>> SELECTOR_SHIFT) % CODES.length].name());
                case THROW_RUNTIME, UNENCODABLE -> error(id, "INTERNAL");
                case PAD -> {
                    pads++;
                    int n = padLength(s, type, id);
                    if (padOverhead(type, id) + n > ONE_MIB) {
                        yield error(id, "FRAME_SIZE");
                    }
                    Map<String, Object> m = reply(type, id);
                    m.put("pad", "a".repeat(n));
                    yield m;
                }
                default -> {
                    Map<String, Object> m = reply(type, id);
                    m.put("title", replaceUnpaired(TITLES.get((s >>> SELECTOR_SHIFT) % TITLES.size())));
                    yield m;
                }
            };
        }
    }

    static long littleEndian(byte[] b, int at) {
        return (b[at] & BYTE) | ((b[at + 1] & BYTE) << 8) | ((b[at + 2] & BYTE) << 16) | ((long) (b[at + 3] & BYTE) << 24);
    }

    static Map<String, Object> reply(String type, String id) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", type);
        m.put("id", id == null ? Null.NULL : id);
        return m;
    }

    static Map<String, Object> error(String id, String code) {
        Map<String, Object> m = reply("error", id);
        m.put("code", code);
        return m;
    }

    /** ADR 0014 §2: each unpaired surrogate in a non-secret string becomes U+FFFD. */
    static String replaceUnpaired(String s) {
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            boolean pair = Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1));
            if (pair) {
                out.append(c).append(s.charAt(i + 1));
                i += 2;
            } else {
                out.append(Character.isSurrogate(c) ? REPLACEMENT : c);
                i++;
            }
        }
        return out.toString();
    }

    // ---- schema (ADR 0014 §3) -----------------------------------------------------------------

    /** The error code ADR 0014 §3 gives {@code root}, or null if it is a well-formed request. */
    static String schemaError(Object root) {
        if (!(root instanceof Map<?, ?> m)) {
            return "BAD_FIELD";
        }
        if (!(m.get("type") instanceof String type) || type.isEmpty() || type.length() > MAX_TYPE || hasControl(type)) {
            return "BAD_FIELD";
        }
        Set<String> members = MEMBERS.get(type);
        if (members == null) {
            return "UNKNOWN_TYPE";
        }
        if (!m.keySet().equals(members)) {
            return "BAD_FIELD";
        }
        if (HELLO.equals(type)) {
            if (!(m.get("version") instanceof Long version)) {
                return "BAD_FIELD";
            }
            return VERSION.equals(version) ? firstError(id(m)) : "VERSION";
        }
        return switch (type) {
            case "lookup" -> firstError(id(m), origin(m));
            case "fill" -> firstError(id(m), origin(m), entry(m.get("entry")));
            case "save" -> firstError(id(m), origin(m), username(m), secretField(m.get("password")));
            default -> firstError(id(m), origin(m), username(m), policy(m.get("policy")));
        };
    }

    private static String firstError(boolean... ok) {
        for (boolean b : ok) {
            if (!b) {
                return "BAD_FIELD";
            }
        }
        return null;
    }

    private static boolean id(Map<?, ?> m) {
        if (!(m.get("id") instanceof String s) || s.isEmpty() || s.length() > MAX_ID) {
            return false;
        }
        return s.chars().allMatch(c -> (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '_' || c == HYPHEN);
    }

    private static boolean origin(Map<?, ?> m) {
        if (!(m.get("origin") instanceof String s) || s.isEmpty() || s.length() > MAX_ORIGIN) {
            return false;
        }
        return s.chars().allMatch(c -> c >= FIRST_VISIBLE && c <= LAST_VISIBLE);
    }

    private static boolean username(Map<?, ?> m) {
        return m.get("username") instanceof String s && s.length() <= MAX_USERNAME && !hasControl(s);
    }

    private static boolean secretField(Object value) {
        return value instanceof String s && !s.isEmpty() && s.length() <= MAX_PASSWORD;
    }

    private static boolean entry(Object value) {
        if (!(value instanceof String s) || s.length() != UUID_LENGTH) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = UUID_HYPHENS.contains(i) ? c == HYPHEN : (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static boolean policy(Object value) {
        if (!(value instanceof Map<?, ?> p) || !p.keySet().equals(POLICY_MEMBERS)) {
            return false;
        }
        if (!(p.get("length") instanceof Long length) || length < MIN_POLICY || length > MAX_POLICY) {
            return false;
        }
        boolean any = false;
        for (String flag : List.of("lower", "upper", "digits", "symbols")) {
            if (!(p.get(flag) instanceof Boolean b)) {
                return false;
            }
            any |= b;
        }
        return any;
    }

    /** "No controls" as the host defines it: U+0000–U+001F and U+007F. */
    private static boolean hasControl(String s) {
        return s.chars().anyMatch(c -> c < FIRST_PRINTABLE || c == DELETE);
    }

    // ---- reading the host's replies --------------------------------------------------------------

    /** Every frame the host wrote, each checked for size and encoding and parsed by the oracle. */
    static List<Map<String, Object>> replies(byte[] out) {
        List<Map<String, Object>> found = new ArrayList<>();
        int pos = 0;
        while (pos < out.length) {
            assertTrue(out.length - pos >= HEADER, "partial reply header");
            long length = littleEndian(out, pos);
            assertTrue(length >= 1 && length <= ONE_MIB, () -> "reply length " + length);
            assertTrue(out.length - pos - HEADER >= length, "partial reply body");
            byte[] body = Arrays.copyOfRange(out, pos + HEADER, pos + HEADER + (int) length);
            pos += HEADER + (int) length;
            String text = JsonOracle.utf8(body);
            assertTrue(text != null, "reply is not UTF-8");
            try {
                Object value = JsonOracle.parse(text, false);
                if (!(value instanceof Map<?, ?> m)) {
                    return fail("reply is not an object");
                }
                Map<String, Object> reply = new LinkedHashMap<>();
                m.forEach((k, v) -> reply.put((String) k, v));
                found.add(reply);
            } catch (Refused e) {
                return fail("reply is not JSON");
            }
        }
        return found;
    }

    // ---- streams ------------------------------------------------------------------------------

    /** Stdin over a byte array that counts what the host consumed. */
    static final class Counting extends InputStream {
        private final byte[] data;
        private int pos;

        Counting(byte[] data) {
            this.data = data.clone();
        }

        long consumed() {
            return pos;
        }

        @Override
        public int read() {
            return pos < data.length ? data[pos++] & BYTE : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (len == 0) {
                return 0;
            }
            int n = Math.min(len, data.length - pos);
            if (n <= 0) {
                return -1;
            }
            System.arraycopy(data, pos, b, off, n);
            pos += n;
            return n;
        }
    }

    // ---- deterministic checks (run in the gate) ------------------------------------------------

    /** One frame: little-endian u32 length, then the UTF-8 of {@code json}. */
    static byte[] frame(String json) {
        return frame(json.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] frame(byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(lengthPrefix(body.length));
        out.writeBytes(body);
        return out.toByteArray();
    }

    static byte[] lengthPrefix(long length) {
        return new byte[] {(byte) length, (byte) (length >>> 8), (byte) (length >>> 16), (byte) (length >>> 24)};
    }

    /** A harness input: caller mode, handler script, then stdin. */
    static byte[] input(int mode, byte[] script, byte[]... stdin) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(mode);
        out.write(script.length);
        out.writeBytes(script);
        for (byte[] part : stdin) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    /** What the production host does with {@code in}: each reply's type or error code, then the exit. */
    static List<String> outcome(byte[] in) throws IOException {
        Layout layout = Layout.of(Stretch.apply(in, STRETCH_CAP));
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        int exit;
        try (Counting stdin = new Counting(layout.stdin())) {
            exit = NativeHost.runWithoutPasskeys(layout.args(), ALLOWLIST, stdin, stdout, new Scripted(layout.script()));
        }
        List<String> seen = new ArrayList<>();
        for (Map<String, Object> reply : replies(stdout.toByteArray())) {
            seen.add("error".equals(reply.get("type")) ? "error:" + reply.get("code") : (String) reply.get("type"));
        }
        seen.add("exit=" + exit);
        return seen;
    }

    /** Each committed seed, and what the host must do with it. */
    static final Map<String, List<String>> SEED_OUTCOMES = Map.ofEntries(
            Map.entry("hello.bin", List.of(HELLO, "exit=0")),
            Map.entry("every-type.bin", List.of(HELLO, "lookup", "fill", "save", "generate", "exit=0")),
            Map.entry("scripted-faults.bin", List.of("error:DENIED", "error:INTERNAL", "error:INTERNAL", "generate",
                    "error:FRAME_SIZE", "exit=0")),
            Map.entry("titles.bin", List.of("lookup", "lookup", "lookup", "lookup", "lookup", "lookup", "lookup",
                    "lookup", "lookup", "lookup", "exit=0")),
            Map.entry("decode-errors.bin", List.of("error:BAD_UTF8", "error:MALFORMED", "error:BAD_FIELD",
                    "error:UNKNOWN_TYPE", "error:VERSION", "error:BAD_FIELD", "error:MALFORMED", "error:MALFORMED",
                    "exit=0")),
            Map.entry("truncated-body.bin", List.of(HELLO, "error:TRUNCATED", "exit=3")),
            Map.entry("truncated-header.bin", List.of(HELLO, "error:TRUNCATED", "exit=3")),
            Map.entry("zero-length.bin", List.of("error:FRAME_SIZE", "exit=3")),
            Map.entry("one-mib-hello.bin", List.of(HELLO, "exit=0")),
            Map.entry("one-mib-plus-one.bin", List.of("error:FRAME_SIZE", "exit=3")),
            Map.entry("caller-other.bin", List.of("exit=2")),
            Map.entry("caller-near-miss.bin", List.of("exit=2")),
            Map.entry("caller-raw.bin", List.of(HELLO, "exit=0")),
            Map.entry("caller-window-20.bin", List.of(HELLO, "exit=0")),
            Map.entry("caller-window-21.bin", List.of("exit=2")),
            Map.entry("webauthn-get.bin", List.of("error:UNKNOWN_TYPE", "exit=0")),
            Map.entry("webauthn-create.bin", List.of("error:UNKNOWN_TYPE", "exit=0")));

    /** Every seed ends as its name says, and the full oracle accepts the host's behaviour on it. */
    @Test
    void everySeedEndsAsItsNameSays() throws IOException {
        // A fixed order (m55b-002): Map.ofEntries iterates in a per-JVM order.
        for (Map.Entry<String, List<String>> seed : new TreeMap<>(SEED_OUTCOMES).entrySet()) {
            byte[] file = Seeds.read(NativeHostFuzzTest.class, seed.getKey());
            assertEquals(seed.getValue(), outcome(file), seed.getKey());
            fuzz(file);
        }
    }

    /** A request at each ADR 0014 §3 limit and one just past it, with the hand-stated reply. */
    record Edge(String label, String json, String reply) {
    }

    static List<Edge> edges() {
        String lookup = "{\"type\":\"lookup\",\"id\":\"a\",\"origin\":";
        String save = "{\"type\":\"save\",\"id\":\"a\",\"origin\":\"https://a.example\",\"username\":";
        String gen = "{\"type\":\"generate\",\"id\":\"a\",\"origin\":\"o\",\"username\":\"\",\"policy\":{\"length\":";
        String flags = ",\"lower\":true,\"upper\":false,\"digits\":false,\"symbols\":false}}";
        String hello = "{\"type\":\"hello\",\"id\":\"a\",\"version\":";
        return List.of(
                new Edge("depth 8", lookup + "[".repeat(7) + "]".repeat(7) + "}", "error:BAD_FIELD"),
                new Edge("depth 9", lookup + "[".repeat(8) + "]".repeat(8) + "}", "error:MALFORMED"),
                new Edge("top depth 8", "[".repeat(8) + "]".repeat(8), "error:BAD_FIELD"),
                new Edge("top depth 9", "[".repeat(9) + "]".repeat(9), "error:MALFORMED"),
                new Edge("256 items", lookup + "[" + "0,".repeat(255) + "0]}", "error:BAD_FIELD"),
                new Edge("257 items", lookup + "[" + "0,".repeat(256) + "0]}", "error:MALFORMED"),
                new Edge("256 members", lookupWithMembers(256), "error:BAD_FIELD"),
                new Edge("257 members", lookupWithMembers(257), "error:MALFORMED"),
                new Edge("string 65536", lookup + quoted("a".repeat(JsonOracle.MAX_STRING)) + "}", "error:BAD_FIELD"),
                new Edge("string 65537", lookup + quoted("a".repeat(JsonOracle.MAX_STRING + 1)) + "}",
                        "error:MALFORMED"),
                new Edge("escaped 65536", lookup + quoted("\\u0061".repeat(JsonOracle.MAX_STRING)) + "}",
                        "error:BAD_FIELD"),
                new Edge("escaped 65537", lookup + quoted("\\u0061".repeat(JsonOracle.MAX_STRING + 1)) + "}",
                        "error:MALFORMED"),
                new Edge("pairs 65536 units", lookup + quoted("\\ud83d\\ude00".repeat(JsonOracle.MAX_STRING / 2))
                        + "}", "error:BAD_FIELD"),
                new Edge("pairs 65537 units", lookup + quoted("\\ud83d\\ude00".repeat(JsonOracle.MAX_STRING / 2)
                        + "a") + "}", "error:MALFORMED"),
                new Edge("15 digits", hello + "100000000000000}", "error:VERSION"),
                new Edge("16 digits", hello + "1000000000000000}", "error:MALFORMED"),
                new Edge("negative 15 digits", hello + "-100000000000000}", "error:VERSION"),
                new Edge("leading zero", hello + "01}", "error:MALFORMED"),
                new Edge("fraction", hello + "1.0}", "error:MALFORMED"),
                new Edge("exponent", hello + "1e0}", "error:MALFORMED"),
                new Edge("version string", hello + "\"1\"}", "error:BAD_FIELD"),
                new Edge("version 2, bad id", "{\"type\":\"hello\",\"id\":\"\",\"version\":2}", "error:VERSION"),
                new Edge("id 64", "{\"type\":\"hello\",\"id\":\"" + "a".repeat(MAX_ID) + "\",\"version\":1}", HELLO),
                new Edge("id 65", "{\"type\":\"hello\",\"id\":\"" + "a".repeat(MAX_ID + 1) + "\",\"version\":1}",
                        "error:BAD_FIELD"),
                new Edge("type 16", "{\"type\":\"" + "t".repeat(MAX_TYPE) + "\"}", "error:UNKNOWN_TYPE"),
                new Edge("type 17", "{\"type\":\"" + "t".repeat(MAX_TYPE + 1) + "\"}", "error:BAD_FIELD"),
                new Edge("type DEL", "{\"type\":\"hell\u007f\"}", "error:BAD_FIELD"),
                new Edge("origin 256", lookup + quoted("o".repeat(MAX_ORIGIN)) + "}", "lookup"),
                new Edge("origin 257", lookup + quoted("o".repeat(MAX_ORIGIN + 1)) + "}", "error:BAD_FIELD"),
                new Edge("origin space", lookup + "\"https://a .example\"}", "error:BAD_FIELD"),
                new Edge("username 1024", save + quoted("u".repeat(MAX_USERNAME)) + ",\"password\":\"p\"}", "save"),
                new Edge("username 1025", save + quoted("u".repeat(MAX_USERNAME + 1)) + ",\"password\":\"p\"}",
                        "error:BAD_FIELD"),
                new Edge("username DEL", save + "\"a\\u007f\",\"password\":\"p\"}", "error:BAD_FIELD"),
                new Edge("username C1", save + "\"a\\u0085\",\"password\":\"p\"}", "save"),
                new Edge("password 4096", save + "\"\",\"password\":" + quoted("p".repeat(MAX_PASSWORD)) + "}",
                        "save"),
                new Edge("password 4097", save + "\"\",\"password\":" + quoted("p".repeat(MAX_PASSWORD + 1)) + "}",
                        "error:BAD_FIELD"),
                new Edge("password empty", save + "\"\",\"password\":\"\"}", "error:BAD_FIELD"),
                new Edge("password control", save + "\"\",\"password\":\"\\u0000\"}", "save"),
                new Edge("policy 8", gen + MIN_POLICY + flags, "generate"),
                new Edge("policy 7", gen + (MIN_POLICY - 1) + flags, "error:BAD_FIELD"),
                new Edge("policy 128", gen + MAX_POLICY + flags, "generate"),
                new Edge("policy 129", gen + (MAX_POLICY + 1) + flags, "error:BAD_FIELD"),
                new Edge("policy no class", gen + "8,\"lower\":false,\"upper\":false,\"digits\":false,\"symbols\":false}}",
                        "error:BAD_FIELD"),
                new Edge("entry upper case", "{\"type\":\"fill\",\"id\":\"a\",\"origin\":\"o\",\"entry\":"
                        + "\"0000000A-0000-0000-0000-000000000000\"}", "error:BAD_FIELD"),
                new Edge("entry", "{\"type\":\"fill\",\"id\":\"a\",\"origin\":\"o\",\"entry\":"
                        + "\"0000000a-0000-0000-0000-000000000000\"}", "fill"));
    }

    private static String quoted(String s) {
        return "\"" + s + "\"";
    }

    /** A lookup with {@code n} members in all. */
    private static String lookupWithMembers(int n) {
        StringBuilder b = new StringBuilder("{\"type\":\"lookup\",\"id\":\"a\",\"origin\":\"o\"");
        for (int i = 3; i < n; i++) {
            b.append(",\"m").append(i).append("\":0");
        }
        return b.append('}').toString();
    }

    /**
     * Every limit holds at its value and refuses one past it, with the exact code stated here by
     * hand; the full oracle agrees with the host on each one.
     */
    @Test
    void limitsHoldAtAndJustPastTheirValues() throws IOException {
        for (Edge edge : edges()) {
            byte[] in = input(MODE_A, new byte[] {0}, frame(edge.json()));
            assertEquals(List.of(edge.reply(), "exit=0"), outcome(in), edge.label());
            fuzz(in);
        }
    }

    /** The caller forms of ADR 0014 §4: each near miss is refused with nothing read, each exact form served. */
    @Test
    void onlyTheExactCallerFormsAreServed() throws IOException {
        byte[] hello = frame("{\"type\":\"hello\",\"id\":\"h\",\"version\":1}");
        for (int i = 0; i < NEAR_MISSES.size(); i++) {
            byte[] in = input(MODE_NEAR_MISS | (i << SELECTOR_SHIFT), new byte[0], hello);
            assertEquals(List.of("exit=2"), outcome(in), NEAR_MISSES.get(i).toString());
            fuzz(in);
        }
        for (int digits = 1; digits <= MAX_WINDOW_DIGITS; digits++) {
            byte[] in = input(MODE_WINDOW | (digits << SELECTOR_SHIFT), new byte[0], hello);
            assertEquals(List.of(HELLO, "exit=0"), outcome(in), digits + " digits");
            fuzz(in);
        }
        for (int mode : new int[] {MODE_A, MODE_B, MODE_A_AGAIN, MODES - 1}) {
            assertEquals(List.of(HELLO, "exit=0"), outcome(input(mode, new byte[0], hello)), "mode " + mode);
        }
        assertEquals(List.of("exit=2"), outcome(input(MODE_OTHER, new byte[0], hello)), "not allowlisted");
    }

    /**
     * Headers past 1 MiB, up to the largest u32, give one {@code FRAME_SIZE} reply and exit 3 after
     * reading only the header. The body behind it never ends, so a loosened bound reads it. Each run
     * is also held to the allocation ceiling, so the first header that grows a kept buffer fails.
     */
    @Test
    void anOversizedHeaderIsRefusedBeforeAnyBodyByteIsRead() throws IOException {
        List<Long> lengths = new ArrayList<>(List.of(ONE_MIB + 1L, 2L * ONE_MIB, (long) Integer.MAX_VALUE, 1L << 31,
                0xFFFF_FFFFL));
        long step = (0xFFFF_FFFFL - ONE_MIB) / MAX_ID;
        for (long k = 1; k <= MAX_ID; k++) {
            lengths.add(ONE_MIB + k * step);
        }
        lengths.add(0L);
        for (long length : lengths) {
            long cost = refusedHeaderCost(length);
            assertTrue(cost <= ALLOC_BASE, () -> "allocated " + cost + " for header " + length);
        }
    }

    /**
     * m55-004: a hostile header (64 MiB, 1 GiB and the largest u32) costs no more than the ceiling
     * on its first read in this JVM, as it would in a new host process. The gate runs this without
     * fuzzing, so an allocation sized from the header fails CI and not only a local campaign.
     */
    @Test
    void aHostileHeaderAllocatesLessThanTheCeiling() throws IOException {
        for (long length : List.of(64L << 20, 1L << 30, 0xFFFF_FFFFL)) {
            long cost = refusedHeaderCost(length);
            assertTrue(cost <= ALLOC_BASE, () -> "allocated " + cost + " for header " + length);
        }
    }

    /** Runs one connection whose header is {@code length}, checks the refusal and returns its allocation. */
    private static long refusedHeaderCost(long length) throws IOException {
        assertTrue(Warm.RUNS > 0, "warm-up ran before the first measurement");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        long allocated;
        try (Endless in = new Endless(length)) {
            Scripted handlers = new Scripted(new byte[0]);
            List<String> args = List.of(originOf(EXT_A));
            long before = Allocation.current();
            int exit = NativeHost.runWithoutPasskeys(args, ALLOWLIST, in, out, handlers);
            allocated = Allocation.current() - before;
            assertEquals(EXIT_FRAMING, exit, "length " + length);
            assertEquals(0, in.bodyRead, "body bytes read for length " + length);
        }
        assertEquals(List.of(error(null, "FRAME_SIZE")), replies(out.toByteArray()), "length " + length);
        return allocated;
    }

    /** The endless stream is not vacuous: at and below 1 MiB the host reads exactly the body. */
    @Test
    void headersUpToTheBoundReadExactlyTheirBody() throws IOException {
        for (long length : List.of(1L, (long) MAX_PASSWORD, (long) ONE_MIB)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (Endless in = new Endless(length)) {
                NativeHost.runWithoutPasskeys(List.of(originOf(EXT_A)), ALLOWLIST, in, out, new Scripted(new byte[0]));
                assertEquals(length + HEADER, in.bodyRead, "bytes read past the first header");
            }
            // The zero body is U+0000 text (MALFORMED); the zero bytes after it are a zero header.
            assertEquals(List.of(error(null, "MALFORMED"), error(null, "FRAME_SIZE")), replies(out.toByteArray()));
        }
    }

    /** One header, then zero bytes for ever; counts what is read after the header. */
    private static final class Endless extends InputStream {
        private final byte[] head;
        private int headRead;
        long bodyRead;

        Endless(long length) {
            this.head = lengthPrefix(length);
        }

        @Override
        public int read() {
            if (headRead < head.length) {
                return head[headRead++] & BYTE;
            }
            bodyRead++;
            return 0;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            int n = 0;
            while (n < len && headRead < head.length) {
                b[off + n++] = head[headRead++];
            }
            Arrays.fill(b, off + n, off + len, (byte) 0);
            bodyRead += len - n;
            return len;
        }
    }

    /** The independent oracle is not vacuous: hand-picked RFC 3629 and RFC 8259 cases. */
    @Test
    void theOracleFollowsTheRfcs() throws Refused {
        for (int[] bad : new int[][] {{0xC0, 0x80}, {0xC1, 0xBF}, {0xE0, 0x80, 0x80}, {0xED, 0xA0, 0x80},
            {0xF4, 0x90, 0x80, 0x80}, {0xF5, 0x80, 0x80, 0x80}, {0x80}, {0xE2, 0x82}, {0xFF}}) {
            assertNull(JsonOracle.utf8(bytes(bad)), Arrays.toString(bad));
        }
        assertEquals("\uD83D\uDE00\u20AC\u00E9a", JsonOracle.utf8(bytes(new int[] {0xF0, 0x9F, 0x98, 0x80, 0xE2,
            0x82, 0xAC, 0xC3, 0xA9, 'a'})));
        for (String bad : List.of("", "01", "1.0", "1e2", "+1", "-", "\"\\ud800\"", "\"\\udc00\"", "\"\\ud800\\u0041\"",
                "{\"a\":1,\"a\":2}", "[1,]", "{,}", "1 2", "\"\t\"", "\"\\x\"", "\"\\u00G0\"", "nul", "\uFEFF{}",
                "\u00A0{}", "{\"a\" 1}")) {
            assertThrows(Refused.class, () -> JsonOracle.parse(bad, true), bad);
        }
        Map<String, Object> expected = new LinkedHashMap<>();
        expected.put("a", List.of(true, false, Null.NULL, 0L, "\uD83D\uDE00/\n", -12L));
        assertEquals(expected, JsonOracle.parse(" {\"a\" : [true,false,null,-0,\"\\ud83d\\uDE00\\/\\n\",-12]}\r\n",
                true));
    }

    private static byte[] bytes(int[] values) {
        byte[] b = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            b[i] = (byte) values[i];
        }
        return b;
    }
}
