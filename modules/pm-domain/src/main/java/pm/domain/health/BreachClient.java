package pm.domain.health;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;
import pm.crypto.ConstantTime;
import pm.crypto.CryptoException;
import pm.crypto.Hash;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;

/**
 * k-anonymity breach lookup against a Pwned Passwords style range API (ADR 0012 §8, SR-074).
 *
 * <p>For a password it computes SHA-1 locally, sends only the first {@value #PREFIX_CHARS} hex
 * characters as {@code GET <base>range/<PREFIX>} with {@code Add-Padding: true}, and matches the
 * remaining 35 characters against the returned suffix list locally, in constant time per line.
 * Padding lines (count 0) never count as a match. The full hash, the suffix and the password never
 * leave the process; the request has no body, no query and no cookies, and redirects are refused.
 *
 * <p>The network is off unless a caller constructs this client and calls {@link #occurrences}:
 * nothing else in pm-domain holds one, and {@link HealthCheck} never does. The base URI must be
 * {@code https}, except a loopback {@code http} URI for tests.
 */
public final class BreachClient implements AutoCloseable {
    /** The public Pwned Passwords range API. */
    public static final URI PWNED_PASSWORDS = URI.create("https://api.pwnedpasswords.com/");
    /** Default deadline for one whole lookup: connect, headers and body. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);
    /** Hex characters of the hash that are sent. */
    public static final int PREFIX_CHARS = 5;
    /** Largest accepted response body; padded real responses are about 40 KiB. */
    public static final int MAX_BODY_BYTES = 1 << 20;
    static final int HEX_CHARS = Hash.SHA1_BYTES * 2;
    static final int SUFFIX_CHARS = HEX_CHARS - PREFIX_CHARS;
    private static final int HTTP_OK = 200;
    private static final int MAX_COUNT_DIGITS = 18;
    private static final int MIN_COUNT_DIGITS = 1;
    private static final byte COLON = ':';
    private static final byte NEWLINE = '\n';
    private static final byte RETURN = '\r';
    private static final int NIBBLE = 4;
    private static final int LOW_NIBBLE = 0x0f;
    private static final byte[] HEX = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
    private static final Pattern LOOPBACK_V4 = Pattern.compile("127(\\.\\d{1,3}){3}");
    private static final String USER_AGENT = "pm-password-manager";

    private final URI baseUri;
    private final HttpClient http;
    private final Duration timeout;

    private BreachClient(URI base, HttpClient http, Duration timeout) {
        this.baseUri = base;
        this.http = http;
        this.timeout = timeout;
    }

    /** A client for {@link #PWNED_PASSWORDS} with {@link #DEFAULT_TIMEOUT}. Sends nothing until called. */
    public static BreachClient pwnedPasswords() {
        return create(PWNED_PASSWORDS, DEFAULT_TIMEOUT);
    }

    /**
     * A client for the range API at {@code base}. Sends nothing until {@link #occurrences} is called.
     *
     * @throws IllegalArgumentException if {@code base} is not an absolute {@code https} URI (or
     *     {@code http} on a loopback host), carries user info, a query or a fragment, or
     *     {@code timeout} is not positive
     */
    public static BreachClient create(URI base, Duration timeout) {
        URI checked = checkBase(Objects.requireNonNull(base, "base"));
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
        HttpClient http = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
        return new BreachClient(checked, http, timeout);
    }

    static URI checkBase(URI base) {
        // Exact, case-sensitive matches: an uppercase scheme or host is refused rather than folded.
        String scheme = Objects.requireNonNullElse(base.getScheme(), "");
        String host = Objects.requireNonNullElse(base.getHost(), "");
        boolean loopback = "localhost".equals(host) || "[::1]".equals(host) || LOOPBACK_V4.matcher(host).matches();
        if (!base.isAbsolute() || host.isEmpty() || base.getRawUserInfo() != null
                || base.getRawQuery() != null || base.getRawFragment() != null
                || !("https".equals(scheme) || ("http".equals(scheme) && loopback))) {
            throw new IllegalArgumentException("breach service URI must be https (or loopback http) without user info, query or fragment");
        }
        String path = base.getRawPath() == null || base.getRawPath().isEmpty() ? "/" : base.getRawPath();
        return path.endsWith("/") ? base.resolve(path) : base.resolve(path + "/");
    }

    /** The base URI requests go to. */
    public URI base() {
        return baseUri;
    }

    /** How often {@code password} (characters) appears in the corpus; 0 if never. */
    public long occurrences(SecretChars password) throws BreachCheckException {
        Objects.requireNonNull(password, "password");
        try (SecretBytes utf8 = password.toUtf8()) {
            return occurrences(utf8);
        }
    }

    /**
     * How often {@code password} (UTF-8, as the vault stores it) appears in the corpus; 0 if never.
     * Performs one HTTPS request carrying only a five-character hash prefix.
     */
    public long occurrences(SecretBytes password) throws BreachCheckException {
        Objects.requireNonNull(password, "password");
        byte[] hex = new byte[HEX_CHARS];
        try {
            try (SecretBytes digest = Hash.sha1ForBreachRange(password)) {
                digest.withBytes(d -> toHex(d, hex));
            } catch (CryptoException e) {
                throw new BreachCheckException(BreachCheckException.Code.INTERNAL);
            }
            String prefix = new String(hex, 0, PREFIX_CHARS, StandardCharsets.US_ASCII);
            byte[] body = fetch(prefix);
            return match(body, Arrays.copyOfRange(hex, PREFIX_CHARS, HEX_CHARS));
        } finally {
            Arrays.fill(hex, (byte) 0);
        }
    }

    /**
     * One GET under a single deadline of {@code timeout} covering connect, headers and the whole
     * body; on expiry the exchange is cancelled. The body is collected by {@link BoundedBody}, which
     * cancels as soon as it would exceed {@link #MAX_BODY_BYTES}.
     */
    @SuppressWarnings("PMD.DoNotUseThreads") // CE-016: only re-asserts the interrupt flag (TPS02-J)
    private byte[] fetch(String prefix) throws BreachCheckException {
        HttpRequest request = HttpRequest.newBuilder(baseUri.resolve("range/" + prefix))
                .GET()
                .timeout(timeout)
                .header("Add-Padding", "true")
                .header("User-Agent", USER_AGENT)
                .build();
        CompletableFuture<HttpResponse<byte[]>> pending = http.sendAsync(request, info ->
                info.statusCode() == HTTP_OK
                        ? boundedBody()
                        : HttpResponse.BodySubscribers.replacing(null));
        try {
            HttpResponse<byte[]> response = pending.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
            if (response.statusCode() != HTTP_OK) {
                throw new BreachCheckException(BreachCheckException.Code.HTTP_STATUS);
            }
            return response.body();
        } catch (TimeoutException e) {
            pending.cancel(true);
            throw new BreachCheckException(BreachCheckException.Code.TIMEOUT);
        } catch (ExecutionException e) {
            throw new BreachCheckException(e.getCause() instanceof BodyTooLarge
                    ? BreachCheckException.Code.TOO_LARGE
                    : BreachCheckException.Code.NETWORK);
        } catch (InterruptedException e) {
            pending.cancel(true);
            Thread.currentThread().interrupt();
            throw new BreachCheckException(BreachCheckException.Code.INTERRUPTED);
        }
    }

    /**
     * Parses a range response strictly and returns the count on the line whose suffix equals
     * {@code suffix} (35 uppercase hex ASCII bytes, zero-filled here); 0 if none or only padding.
     * A body with no lines is {@code MALFORMED}: a real (padded) response is never empty, so an
     * empty one must not read as "not breached".
     */
    static long match(byte[] body, byte[] suffix) throws BreachCheckException {
        long found = 0;
        boolean anyLine = false;
        try {
            int start = 0;
            while (start < body.length) {
                int end = start;
                while (end < body.length && body[end] != NEWLINE) {
                    end++;
                }
                int lineEnd = end > start && body[end - 1] == RETURN ? end - 1 : end;
                if (lineEnd > start) {
                    anyLine = true;
                    long count = parseLine(body, start, lineEnd, suffix);
                    found = Math.max(found, count);
                }
                start = end + 1;
            }
            if (!anyLine) {
                throw new BreachCheckException(BreachCheckException.Code.MALFORMED);
            }
            return found;
        } finally {
            Arrays.fill(suffix, (byte) 0);
        }
    }

    /** The count if the line's suffix matches, 0 otherwise; throws on a malformed line. */
    private static long parseLine(byte[] body, int from, int to, byte[] suffix) throws BreachCheckException {
        int colon = from + SUFFIX_CHARS;
        int digits = to - colon - 1;
        if (colon >= to || body[colon] != COLON || digits < MIN_COUNT_DIGITS || digits > MAX_COUNT_DIGITS) {
            throw new BreachCheckException(BreachCheckException.Code.MALFORMED);
        }
        for (int i = from; i < colon; i++) {
            if (!isUpperHex(body[i])) {
                throw new BreachCheckException(BreachCheckException.Code.MALFORMED);
            }
        }
        long count = 0;
        for (int i = colon + 1; i < to; i++) {
            if (!isDigit(body[i])) {
                throw new BreachCheckException(BreachCheckException.Code.MALFORMED);
            }
            count = count * 10 + (body[i] - '0');
        }
        boolean same = ConstantTime.equals(suffix, Arrays.copyOfRange(body, from, colon));
        return same ? count : 0;
    }

    private static boolean isUpperHex(byte b) {
        return isDigit(b) || (b >= 'A' && b <= 'F');
    }

    private static boolean isDigit(byte b) {
        return b >= '0' && b <= '9';
    }

    private static void toHex(byte[] digest, byte[] out) {
        for (int i = 0; i < digest.length; i++) {
            out[2 * i] = HEX[(digest[i] >> NIBBLE) & LOW_NIBBLE];
            out[2 * i + 1] = HEX[digest[i] & LOW_NIBBLE];
        }
    }

    /** Aborts any exchange still running and releases the HTTP client's connections and threads. */
    @Override
    public void close() {
        http.shutdownNow();
        http.close();
    }

    /**
     * The collector for a 200 response body, capped at {@link #MAX_BODY_BYTES}. Package-private so
     * the fuzz harness (T-FUZZ-BREACH) drives the production limit rather than its own.
     */
    static BoundedBody boundedBody() {
        return new BoundedBody(MAX_BODY_BYTES);
    }

    /** Signals that a response body passed {@link #MAX_BODY_BYTES}; carries no data. */
    static final class BodyTooLarge extends IOException {
        private static final long serialVersionUID = 1L;

        BodyTooLarge() {
            super("TOO_LARGE");
        }
    }

    /**
     * Collects a body of at most {@code limit} bytes; one byte more cancels the subscription and
     * fails with {@link BodyTooLarge}. Reactive-streams signals arrive serially, so plain fields suffice.
     */
    static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
        private static final int INITIAL = 1 << 12;
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final int limit;
        private byte[] buffer = new byte[INITIAL];
        private int size;
        private Flow.Subscription subscription;

        BoundedBody(int limit) {
            this.limit = limit;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription s) {
            subscription = s;
            s.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            for (ByteBuffer item : items) {
                if (result.isDone()) {
                    return;
                }
                int n = item.remaining();
                if (n > limit - size) {
                    Flow.Subscription s = subscription;
                    if (s != null) {
                        s.cancel();
                    }
                    result.completeExceptionally(new BodyTooLarge());
                    return;
                }
                if (size + n > buffer.length) {
                    buffer = Arrays.copyOf(buffer, Math.min(limit, Math.max(size + n, buffer.length * 2)));
                }
                item.get(buffer, size, n);
                size += n;
            }
        }

        @Override
        public void onError(Throwable error) {
            result.completeExceptionally(error);
        }

        @Override
        public void onComplete() {
            result.complete(Arrays.copyOf(buffer, size));
        }
    }
}
