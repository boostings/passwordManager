package pm.browser.host;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The extension IDs allowed to talk to the host (SR-301). Chrome starts the host with the caller's
 * origin {@code chrome-extension://<id>/} as the first argument (and, on Windows, a
 * {@code --parent-window=<n>} handle as the second). The host checks it against this exact list
 * before it reads a single byte from the browser. The browser's own manifest check
 * ({@code allowed_origins}) is the first gate; this is the second, in case the manifest is edited
 * or another browser profile installs a different extension under the same host name.
 */
public final class ExtensionAllowlist {
    /** Largest allowlist file read. */
    public static final int MAX_FILE_BYTES = 4_096;

    /** A Chrome extension ID: 32 letters a–p (a base-16 hash spelled with a–p). */
    private static final Pattern ID = Pattern.compile("[a-p]{32}");
    private static final Pattern PARENT_WINDOW = Pattern.compile("--parent-window=[0-9]{1,20}");
    private static final Pattern ORIGIN = Pattern.compile("chrome-extension://([a-p]{32})/");

    private final Set<String> ids;

    private ExtensionAllowlist(Set<String> ids) {
        this.ids = ids;
    }

    /**
     * An allowlist of exactly {@code ids}; an empty list refuses every caller.
     *
     * @throws IllegalArgumentException {@code BAD_EXTENSION_ID} if any id is not 32 letters a–p
     */
    public static ExtensionAllowlist of(Collection<String> ids) {
        for (String id : ids) {
            if (!ID.matcher(id).matches()) {
                throw new IllegalArgumentException("BAD_EXTENSION_ID");
            }
        }
        return new ExtensionAllowlist(Set.copyOf(ids));
    }

    /**
     * Reads an allowlist file: one ID per line, blank lines and {@code #} comments ignored. The
     * file must be a regular file (not a link) of at most {@link #MAX_FILE_BYTES}.
     *
     * @throws IllegalArgumentException {@code UNSAFE_ALLOWLIST} or {@code BAD_EXTENSION_ID}
     */
    public static ExtensionAllowlist read(Path file) throws IOException {
        BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attrs.isRegularFile() || attrs.size() > MAX_FILE_BYTES) {
            throw new IllegalArgumentException("UNSAFE_ALLOWLIST");
        }
        List<String> found = new ArrayList<>();
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            String trimmed = line.strip();
            if (!trimmed.isEmpty() && trimmed.charAt(0) != '#') {
                found.add(trimmed);
            }
        }
        return of(found);
    }

    /**
     * The verified extension ID of the caller, or empty if the arguments are not exactly an
     * allowlisted origin (plus, optionally, Chrome's Windows parent-window handle).
     */
    public Optional<String> caller(List<String> args) {
        if (args.isEmpty() || args.size() > 2 || (args.size() == 2 && !PARENT_WINDOW.matcher(args.get(1)).matches())) {
            return Optional.empty();
        }
        Matcher origin = ORIGIN.matcher(args.get(0));
        return origin.matches() && ids.contains(origin.group(1)) ? Optional.of(origin.group(1)) : Optional.empty();
    }
}
