package pm.cli;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/** Reads {@code remote "origin"}'s url from {@code .git/config} without running git. */
final class GitRemote {
    private static final long MAX_CONFIG_BYTES = 256 * 1024;
    private static final int MAX_URL_CHARS = 8_192;

    private GitRemote() {
    }

    static Optional<String> origin(Path dir) {
        Path config = dir.resolve(".git").resolve("config");
        List<String> lines;
        try {
            if (!Files.isRegularFile(config, LinkOption.NOFOLLOW_LINKS) || Files.size(config) > MAX_CONFIG_BYTES) {
                return Optional.empty();
            }
            lines = Files.readAllLines(config, StandardCharsets.UTF_8);
        } catch (IOException | java.io.UncheckedIOException e) {
            return Optional.empty();
        }
        boolean inOrigin = false;
        for (String raw : lines) {
            String line = raw.strip();
            if (line.startsWith("[")) {
                inOrigin = "[remote \"origin\"]".equals(line);
            } else if (inOrigin && line.startsWith("url")) {
                int eq = line.indexOf('=');
                String url = eq < 0 ? "" : line.substring(eq + 1).strip();
                if (!url.isEmpty() && url.length() <= MAX_URL_CHARS && !Cli.hasUnsafeChars(url)) {
                    return Optional.of(url);
                }
            }
        }
        return Optional.empty();
    }
}
