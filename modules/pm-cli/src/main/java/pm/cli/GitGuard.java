package pm.cli;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Warns before a plaintext {@code .env} file can be committed (plan.md §13 M2). Git itself is not
 * run (IDS07-J: no process outside pm-approval); instead the {@code .gitignore} files from the
 * repository root down to the file's directory are read and their plain patterns matched. Rules it
 * does not understand (negations) make it assume the file is not ignored, so it errs toward warning.
 */
final class GitGuard {
    private static final String GITIGNORE = ".gitignore";
    private static final long MAX_IGNORE_BYTES = 256 * 1024;

    private GitGuard() {
    }

    /** True if {@code file} (absolute, normalized) is inside a git work tree and no rule ignores it. */
    static boolean atRisk(Path file) {
        Optional<Path> root = repositoryRoot(file.getParent());
        return root.isPresent() && !isIgnored(root.get(), file);
    }

    /** The nearest ancestor of {@code dir} holding {@code .git}. */
    static Optional<Path> repositoryRoot(Path dir) {
        for (Path p = dir; p != null; p = p.getParent()) {
            if (Files.exists(p.resolve(".git"), LinkOption.NOFOLLOW_LINKS)) {
                return Optional.of(p);
            }
        }
        return Optional.empty();
    }

    static boolean isIgnored(Path root, Path file) {
        Path rel = root.relativize(file);
        List<Path> dirs = new ArrayList<>();
        dirs.add(root);
        for (int i = 0; i < rel.getNameCount() - 1; i++) {
            dirs.add(root.resolve(rel.subpath(0, i + 1)));
        }
        boolean ignored = false;
        for (Path dir : dirs) {
            for (String line : readIgnore(dir.resolve(GITIGNORE))) {
                String rule = line.strip();
                if (rule.isEmpty() || rule.startsWith("#")) {
                    continue;
                }
                if (rule.startsWith("!")) {
                    return false; // negations are not modelled: assume the worst
                }
                if (matches(rule, dir.relativize(file))) {
                    ignored = true;
                }
            }
        }
        return ignored;
    }

    /** Matches one gitignore rule against {@code rel}, the path relative to the rule's directory. */
    static boolean matches(String rule, Path rel) {
        boolean dirOnly = rule.endsWith("/");
        String pattern = dirOnly ? rule.substring(0, rule.length() - 1) : rule;
        boolean anchored = pattern.startsWith("/") || pattern.contains("/");
        pattern = pattern.startsWith("/") ? pattern.substring(1) : pattern;
        if (pattern.isEmpty()) {
            return false;
        }
        PathMatcher m = FileSystems.getDefault().getPathMatcher("glob:" + pattern);
        int names = rel.getNameCount();
        if (anchored) {
            // An anchored rule matches the path itself or one of its leading directories.
            for (int i = 1; i <= names; i++) {
                boolean isDir = i < names;
                if ((isDir || !dirOnly) && m.matches(rel.subpath(0, i))) {
                    return true;
                }
            }
            return false;
        }
        for (int i = 0; i < names; i++) {
            boolean isDir = i < names - 1;
            if ((isDir || !dirOnly) && m.matches(rel.getName(i))) {
                return true;
            }
        }
        return false;
    }

    private static List<String> readIgnore(Path file) {
        try {
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.size(file) > MAX_IGNORE_BYTES) {
                return List.of();
            }
            return Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException | java.io.UncheckedIOException e) {
            return List.of(); // unreadable: treated as absent, which errs toward warning
        }
    }
}
