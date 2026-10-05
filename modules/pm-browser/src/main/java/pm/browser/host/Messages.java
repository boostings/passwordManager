package pm.browser.host;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * The message schema (ADR 0014 §3): every request is one JSON object whose member names are
 * exactly the set listed for its {@code type}, each of the listed JSON type and range. Anything
 * else is refused before the request reaches the bridge (SR-303). Also builds the replies.
 */
public final class Messages {
    /** Longest origin accepted from the extension, in characters. */
    public static final int MAX_ORIGIN = 256;
    /** Longest username. */
    public static final int MAX_USERNAME = 1_024;
    /** Longest password the extension may save. */
    public static final int MAX_PASSWORD = 4_096;

    private static final Pattern ID_SHAPE = Pattern.compile("[A-Za-z0-9_-]{1,64}");
    private static final Pattern UUID_TEXT =
            Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    /** An origin is printable ASCII without spaces at this layer; the bridge canonicalises it. */
    private static final Pattern ORIGIN_TEXT = Pattern.compile("[\\x21-\\x7e]{1," + MAX_ORIGIN + "}");

    private static final String TYPE_HELLO = "hello";
    private static final String TYPE_LOOKUP = "lookup";
    private static final String TYPE_FILL = "fill";
    private static final String TYPE_SAVE = "save";
    private static final String TYPE_GENERATE = "generate";

    private static final Set<String> HELLO_FIELDS = Set.of("type", "id", "version");
    private static final Set<String> LOOKUP_FIELDS = Set.of("type", "id", "origin");
    private static final Set<String> FILL_FIELDS = Set.of("type", "id", "origin", "entry");
    private static final Set<String> SAVE_FIELDS = Set.of("type", "id", "origin", "username", "password");
    private static final Set<String> GENERATE_FIELDS = Set.of("type", "id", "origin", "username", "policy");
    private static final Set<String> POLICY_FIELDS = Set.of("length", "lower", "upper", "digits", "symbols");

    // ---- WebAuthn (M6.3, ADR 0016 M6.3 addendum) ----
    /** Longest {@code clientDataJSON}, in bytes. */
    public static final int MAX_CLIENT_DATA = 4_096;
    /** Longest user handle, in bytes (WebAuthn Level 3 §5.4.3). */
    public static final int MAX_USER_HANDLE = 64;
    /** Longest credential ID, in bytes (WebAuthn Level 3 §6.5.1). */
    public static final int MAX_CREDENTIAL_ID = 1_023;
    /** Most entries in {@code allowCredentials} or {@code excludeCredentials}. */
    public static final int MAX_CREDENTIALS = 64;
    /** Most algorithms in {@code algorithms}. */
    public static final int MAX_ALGORITHMS = 16;
    private static final Pattern RP_ID_TEXT = Pattern.compile("[\\x21-\\x7e]{1,253}");
    private static final String TYPE_WEBAUTHN_CREATE = "webauthn.create";
    private static final String TYPE_WEBAUTHN_GET = "webauthn.get";
    private static final Set<String> WEBAUTHN_CREATE_FIELDS = Set.of("type", "id", "origin", "rpId",
            "clientDataJSON", "user", "algorithms", "excludeCredentials", "userVerification");
    private static final Set<String> WEBAUTHN_GET_FIELDS = Set.of("type", "id", "origin", "rpId",
            "clientDataJSON", "allowCredentials", "credential", "userVerification");
    private static final Set<String> USER_FIELDS = Set.of("id", "name", "displayName");

    private Messages() {
    }

    /**
     * Decodes one frame body into a request. The body is zeroed, and so is every intermediate
     * copy; a {@link Request.Save} owns its password.
     *
     * @throws HostException {@code BAD_UTF8}, {@code MALFORMED}, {@code UNKNOWN_TYPE},
     *     {@code BAD_FIELD} or {@code VERSION}
     */
    public static Request decode(byte[] body) throws HostException {
        char[] text;
        try {
            text = NativeFrames.utf8(body);
        } finally {
            Arrays.fill(body, (byte) 0);
        }
        Json root;
        try {
            root = JsonText.parse(text);
        } finally {
            Arrays.fill(text, '\0');
        }
        try {
            return request(root);
        } finally {
            root.wipe();
        }
    }

    private static Request request(Json root) throws HostException {
        if (!(root instanceof Json.Obj o)) {
            throw badField();
        }
        String type = text(o.get("type"), 1, 16);
        if (TYPE_HELLO.equals(type)) {
            fields(o, HELLO_FIELDS);
            if (integer(o.get("version")) != Request.Hello.VERSION) {
                throw new HostException(HostException.Code.VERSION);
            }
            return new Request.Hello(id(o));
        }
        if (TYPE_LOOKUP.equals(type)) {
            fields(o, LOOKUP_FIELDS);
            return new Request.Lookup(id(o), origin(o));
        }
        if (TYPE_FILL.equals(type)) {
            fields(o, FILL_FIELDS);
            return new Request.Fill(id(o), origin(o), entry(o.get("entry")));
        }
        if (TYPE_SAVE.equals(type)) {
            fields(o, SAVE_FIELDS);
            String username = text(o.get("username"), 0, MAX_USERNAME);
            Json.Str secret = str(o.get("password"));
            if (secret.length() == 0 || secret.length() > MAX_PASSWORD) {
                throw badField();
            }
            return new Request.Save(id(o), origin(o), username, secret.secret());
        }
        if (TYPE_GENERATE.equals(type)) {
            fields(o, GENERATE_FIELDS);
            String username = text(o.get("username"), 0, MAX_USERNAME);
            return new Request.Generate(id(o), origin(o), username, policy(o.get("policy")));
        }
        if (TYPE_WEBAUTHN_CREATE.equals(type)) {
            fields(o, WEBAUTHN_CREATE_FIELDS);
            return new Request.WebauthnCreate(id(o), origin(o), matching(o.get("rpId"), RP_ID_TEXT),
                    binary(o.get("clientDataJSON"), 1, MAX_CLIENT_DATA), user(o.get("user")),
                    algorithms(o.get("algorithms")), credentials(o.get("excludeCredentials")),
                    userVerification(o.get("userVerification")));
        }
        if (TYPE_WEBAUTHN_GET.equals(type)) {
            fields(o, WEBAUTHN_GET_FIELDS);
            Json chosen = o.get("credential");
            Optional<String> credential = chosen instanceof Json.Null
                    ? Optional.empty()
                    : Optional.of(binary(chosen, 1, MAX_CREDENTIAL_ID));
            return new Request.WebauthnGet(id(o), origin(o), matching(o.get("rpId"), RP_ID_TEXT),
                    binary(o.get("clientDataJSON"), 1, MAX_CLIENT_DATA), credentials(o.get("allowCredentials")),
                    credential, userVerification(o.get("userVerification")));
        }
        throw new HostException(HostException.Code.UNKNOWN_TYPE);
    }

    private static Request.User user(Json value) throws HostException {
        if (!(value instanceof Json.Obj u)) {
            throw badField();
        }
        fields(u, USER_FIELDS);
        return new Request.User(binary(u.get("id"), 1, MAX_USER_HANDLE), text(u.get("name"), 1, MAX_USERNAME),
                text(u.get("displayName"), 0, MAX_USERNAME));
    }

    /** {@code pubKeyCredParams} algorithms: at most {@link #MAX_ALGORITHMS} integers. */
    private static List<Long> algorithms(Json value) throws HostException {
        List<Long> out = new ArrayList<>();
        for (Json item : array(value, MAX_ALGORITHMS)) {
            out.add(integer(item));
        }
        return out;
    }

    /** At most {@link #MAX_CREDENTIALS} credential IDs, each 1 to 1023 bytes. */
    private static List<String> credentials(Json value) throws HostException {
        List<String> out = new ArrayList<>();
        for (Json item : array(value, MAX_CREDENTIALS)) {
            out.add(binary(item, 1, MAX_CREDENTIAL_ID));
        }
        return out;
    }

    private static List<Json> array(Json value, int max) throws HostException {
        if (!(value instanceof Json.Arr a) || a.items().size() > max) {
            throw badField();
        }
        return a.items();
    }

    private static Request.UserVerification userVerification(Json value) throws HostException {
        return switch (str(value).text()) {
            case "required" -> Request.UserVerification.REQUIRED;
            case "preferred" -> Request.UserVerification.PREFERRED;
            case "discouraged" -> Request.UserVerification.DISCOURAGED;
            default -> throw badField();
        };
    }

    /** Canonical unpadded base64url of {@code min..max} bytes; returns the text. */
    private static String binary(Json value, int min, int max) throws HostException {
        String text = str(value).text();
        int length = Base64Url.decode(text).length;
        if (length < min || length > max) {
            throw badField();
        }
        return text;
    }

    private static Request.Policy policy(Json value) throws HostException {
        if (!(value instanceof Json.Obj p)) {
            throw badField();
        }
        fields(p, POLICY_FIELDS);
        long length = integer(p.get("length"));
        if (length < Request.Policy.MIN_LENGTH || length > Request.Policy.MAX_LENGTH) {
            throw badField();
        }
        boolean lower = bool(p.get("lower"));
        boolean upper = bool(p.get("upper"));
        boolean digits = bool(p.get("digits"));
        boolean symbols = bool(p.get("symbols"));
        if (!(lower || upper || digits || symbols)) {
            throw badField();
        }
        return new Request.Policy((int) length, lower, upper, digits, symbols);
    }

    /** Exactly these member names: a missing or an extra one is refused alike. */
    private static void fields(Json.Obj o, Set<String> expected) throws HostException {
        if (!o.names().equals(expected)) {
            throw badField();
        }
    }

    private static String id(Json.Obj o) throws HostException {
        return matching(o.get("id"), ID_SHAPE);
    }

    private static String origin(Json.Obj o) throws HostException {
        return matching(o.get("origin"), ORIGIN_TEXT);
    }

    private static UUID entry(Json value) throws HostException {
        return UUID.fromString(matching(value, UUID_TEXT));
    }

    private static String matching(Json value, Pattern shape) throws HostException {
        String s = str(value).text();
        if (!shape.matcher(s).matches()) {
            throw badField();
        }
        return s;
    }

    /** A string of {@code min..max} units without control characters. */
    private static String text(Json value, int min, int max) throws HostException {
        Json.Str s = str(value);
        if (s.length() < min || s.length() > max || s.hasControl()) {
            throw badField();
        }
        return s.text();
    }

    private static Json.Str str(Json value) throws HostException {
        if (value instanceof Json.Str s) {
            return s;
        }
        throw badField();
    }

    private static long integer(Json value) throws HostException {
        if (value instanceof Json.Num n) {
            return n.value();
        }
        throw badField();
    }

    private static boolean bool(Json value) throws HostException {
        if (value instanceof Json.Bool b) {
            return b.value();
        }
        throw badField();
    }

    private static HostException badField() {
        return new HostException(HostException.Code.BAD_FIELD);
    }

    // ---- replies ------------------------------------------------------------------------

    /** Starts a reply object of {@code type} answering request {@code id} (null if unknown). */
    public static Map<String, Json> reply(String type, String id) {
        Map<String, Json> m = new LinkedHashMap<>();
        m.put("type", Json.Str.of(type));
        m.put("id", id == null ? Json.Null.NULL : Json.Str.of(id));
        return m;
    }

    /** The answer to a {@code hello}. */
    public static Json.Obj hello(Request.Hello hello) {
        Map<String, Json> m = reply(TYPE_HELLO, hello.id());
        m.put("version", new Json.Num(Request.Hello.VERSION));
        return new Json.Obj(m);
    }

    /** An error reply carrying only a code. */
    public static Json.Obj error(String id, String code) {
        Map<String, Json> m = reply("error", id);
        m.put("code", Json.Str.of(code));
        return new Json.Obj(m);
    }
}
