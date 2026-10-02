package pm.vault.record;

import java.util.Locale;

public final class RecordSearch {
    private RecordSearch() {}

    public static boolean matches(VaultRecord record, String query) {
        String value = query == null ? "" : query.toLowerCase(Locale.ROOT);
        if (value.isEmpty()) {
            return true;
        }
        if (record instanceof LoginRecord login) {
            return contains(login.title(), value)
                || contains(login.username(), value)
                || containsAny(login.urls(), value)
                || containsAny(login.tags(), value);
        }
        if (record instanceof WifiRecord wifi) {
            return contains(wifi.title(), value)
                || contains(wifi.ssid(), value)
                || contains(wifi.security(), value);
        }
        if (record instanceof SshKeyRecord ssh) {
            return contains(ssh.title(), value)
                || contains(ssh.publicKey(), value)
                || containsAny(ssh.hosts(), value);
        }
        if (record instanceof ProjectRecord project) {
            return contains(project.title(), value)
                || contains(project.canonicalPath(), value)
                || contains(project.gitRemote(), value);
        }
        return false;
    }

    private static boolean contains(String candidate, String query) {
        if (candidate == null) {
            return false;
        }
        return candidate.toLowerCase(Locale.ROOT).contains(query);
    }

    private static boolean containsAny(java.util.List<String> values, String query) {
        for (String value : values) {
            if (contains(value, query)) {
                return true;
            }
        }
        return false;
    }
}
