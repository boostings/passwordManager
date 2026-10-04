package pm.tui.lan;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import pm.sharing.share.Shares;

/**
 * Addresses and windows as the user types them. Only IP literals are accepted, so nothing is ever
 * looked up in DNS (lan-share.md §3: no discovery, the user reads the address off the other screen).
 */
public final class LanAddress {
    private static final Pattern IPV4 = Pattern.compile("(\\d{1,3}(?:\\.\\d{1,3}){3}):(\\d{1,5})");
    private static final Pattern IPV6 = Pattern.compile("\\[([0-9A-Fa-f:.]{2,45})\\]:(\\d{1,5})");
    private static final Pattern BIND_V4 = Pattern.compile("\\d{1,3}(?:\\.\\d{1,3}){3}");
    private static final Pattern BIND_V6 = Pattern.compile("[0-9A-Fa-f:.]{2,45}");
    private static final Pattern WINDOW = Pattern.compile("([1-9]\\d{0,4})([smh])");
    private static final int MAX_OCTET = 255;
    private static final int MAX_PORT = 65_535;

    private LanAddress() {
    }

    /**
     * Parses {@code IPv4:port} or {@code [IPv6]:port}.
     *
     * @throws LanException {@code BAD_ADDRESS} for anything else, host names included
     */
    public static InetSocketAddress parse(String text) throws LanException {
        Objects.requireNonNull(text, "text");
        Matcher v4 = IPV4.matcher(text);
        Matcher v6 = IPV6.matcher(text);
        if (v4.matches()) {
            return new InetSocketAddress(literal(v4.group(1)), port(v4.group(2)));
        }
        if (v6.matches()) {
            return new InetSocketAddress(literal(v6.group(1)), port(v6.group(2)));
        }
        throw new LanException(LanException.Code.BAD_ADDRESS);
    }

    /**
     * Parses a bind address: an IP literal of this machine. A wildcard ({@code 0.0.0.0},
     * {@code ::}) is refused, so a window never listens on every interface (lan-share.md §3), and
     * so is any address no local interface has; loopback is allowed.
     *
     * @throws LanException {@code BAD_ADDRESS} if it is not an IP literal, is a wildcard, or is not
     *     an address of this machine
     */
    public static InetAddress bind(String text) throws LanException {
        Objects.requireNonNull(text, "text");
        if (!BIND_V4.matcher(text).matches() && !(BIND_V6.matcher(text).matches() && text.indexOf(':') >= 0)) {
            throw new LanException(LanException.Code.BAD_ADDRESS);
        }
        InetAddress address = literal(text);
        if (address.isAnyLocalAddress() || !(address.isLoopbackAddress() || isLocal(address))) {
            throw new LanException(LanException.Code.BAD_ADDRESS);
        }
        return address;
    }

    /** Whether an interface of this machine has {@code address}. */
    private static boolean isLocal(InetAddress address) {
        try {
            return NetworkInterface.getByInetAddress(address) != null;
        } catch (SocketException e) {
            return false;
        }
    }

    /**
     * Parses a window length such as {@code 90s}, {@code 10m} or {@code 2h}.
     *
     * @throws LanException {@code BAD_TTL} if malformed or not between 1 s and 24 h
     */
    public static Duration ttl(String text) throws LanException {
        Matcher m = WINDOW.matcher(Objects.requireNonNull(text, "text"));
        if (!m.matches()) {
            throw new LanException(LanException.Code.BAD_TTL);
        }
        long n = Long.parseLong(m.group(1));
        Duration ttl = switch (m.group(2)) {
            case "s" -> Duration.ofSeconds(n);
            case "m" -> Duration.ofMinutes(n);
            default -> Duration.ofHours(n);
        };
        if (ttl.compareTo(Shares.MAX_TTL) > 0) {
            throw new LanException(LanException.Code.BAD_TTL);
        }
        return ttl;
    }

    /**
     * Where to listen when the user names nothing: the first private (site-local) IPv4 address of
     * an interface that is up and not loopback, otherwise loopback. Never a wildcard address.
     */
    public static InetAddress defaultBind() {
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface nif : interfaces) {
                if (nif.isUp() && !nif.isLoopback()) {
                    for (InetAddress a : Collections.list(nif.getInetAddresses())) {
                        if (a instanceof Inet4Address && a.isSiteLocalAddress()) {
                            return a;
                        }
                    }
                }
            }
        } catch (SocketException e) {
            return InetAddress.getLoopbackAddress();
        }
        return InetAddress.getLoopbackAddress();
    }

    /** {@code address:port} as the other device types it. */
    public static String show(InetAddress address, int port) {
        String host = address.getHostAddress().replaceFirst("%.*$", "");
        return (address instanceof Inet4Address ? host : "[" + host + "]") + ":" + port;
    }

    private static InetAddress literal(String text) throws LanException {
        if (text.indexOf(':') < 0) {
            // Without a colon it must be dotted IPv4, or getByName would treat it as a host name.
            if (!BIND_V4.matcher(text).matches()) {
                throw new LanException(LanException.Code.BAD_ADDRESS);
            }
            for (String octet : text.split("\\.", -1)) {
                if (Integer.parseInt(octet) > MAX_OCTET) {
                    throw new LanException(LanException.Code.BAD_ADDRESS);
                }
            }
        }
        try {
            // An IP literal: getByName parses it and never consults DNS.
            return InetAddress.getByName(text);
        } catch (UnknownHostException e) {
            throw new LanException(LanException.Code.BAD_ADDRESS, e);
        }
    }

    private static int port(String text) throws LanException {
        int port = Integer.parseInt(text);
        if (port < 1 || port > MAX_PORT) {
            throw new LanException(LanException.Code.BAD_ADDRESS);
        }
        return port;
    }
}
