package pm.sharing.web;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import pm.crypto.Aead;
import pm.crypto.CryptoException;
import pm.crypto.Csprng;
import pm.crypto.SecretBytes;
import pm.sharing.share.Shares;

/**
 * One browser share (lan-share.md §7 step 1): the payload sealed under a fresh 32-byte
 * {@code k_web} with AES-256-GCM, associated data the 16-byte share id. {@code k_web} encrypts
 * exactly this one message, so the nonce is zero (ADR 0005). The key leaves this object only inside
 * the URL fragment, which browsers never send to the server.
 */
public final class WebShare implements AutoCloseable {
    /** Largest payload: the LAN protocol's frame limit. */
    public static final int MAX_PAYLOAD = 1 << 20;
    static final int ID_BYTES = 16;
    static final int KEY_BYTES = 32;

    private final byte[] idBytes;
    private final SecretBytes key;
    private final byte[] sealed;
    private final Instant expiry;

    private WebShare(byte[] id, SecretBytes key, byte[] ciphertext, Instant expires) {
        this.idBytes = id;
        this.key = key;
        this.sealed = ciphertext;
        this.expiry = expires;
    }

    /**
     * Seals {@code payload} (UTF-8 text the page will show) for a window of {@code ttl} from
     * {@code now}. The caller keeps ownership of {@code payload}.
     *
     * @param ttl between 1 s and {@link Shares#MAX_TTL}
     * @throws CryptoException {@code BAD_INPUT} if the payload is empty or larger than
     *     {@link #MAX_PAYLOAD}, or the ttl is out of range
     */
    public static WebShare seal(SecretBytes payload, Duration ttl, Instant now) throws CryptoException {
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(now, "now");
        if (payload.length() == 0 || payload.length() > MAX_PAYLOAD
                || ttl.toSeconds() < 1 || ttl.compareTo(Shares.MAX_TTL) > 0) {
            throw new CryptoException(CryptoException.Code.BAD_INPUT);
        }
        byte[] id = Csprng.bytes(ID_BYTES);
        SecretBytes key = SecretBytes.takeOwnership(Csprng.bytes(KEY_BYTES));
        byte[] box = Aead.sealWithFreshKey(key.apply(SecretBytes::copyOf), payload, id.clone());
        return new WebShare(id, key, box, now.plus(ttl));
    }

    /** The share id as 32 lowercase hex characters, as it appears in the paths. */
    public String id() {
        return HexFormat.of().formatHex(idBytes);
    }

    /** When the window closes. */
    public Instant expires() {
        return expiry;
    }

    /** The bytes {@code /d/<id>} serves: ciphertext followed by the 16-byte tag. */
    byte[] ciphertext() {
        return sealed.clone();
    }

    /**
     * The link to give the recipient: {@code https://<host>:<port>/s/<id>#<base64url k_web>}. It
     * carries the key; show it only to the sender, and never log it.
     */
    public String url(InetAddress host, int port) {
        String literal = host.getHostAddress();
        String authority = host instanceof Inet6Address ? "[" + literal.replaceFirst("%.*$", "") + "]" : literal;
        String fragment = key.apply(k -> Base64.getUrlEncoder().withoutPadding().encodeToString(k));
        return "https://" + authority + ":" + port + WebServer.PAGE + id() + "#" + fragment;
    }

    /** Wipes {@code k_web}. */
    @Override
    public void close() {
        key.close();
    }
}
