package pm.browser.host;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import pm.crypto.SecretBytes;
import pm.crypto.SecretChars;

/**
 * A JSON value of the native messaging protocol (ADR 0014 §3). Numbers are integers only: the
 * protocol has no other kind. Strings keep their characters in a {@code char[]} so a password
 * travels from the frame to a {@link SecretChars} (and back) without becoming a {@code String}
 * (MSC03-J, ADR 0008); {@link #wipe()} zeroes every string in the tree.
 */
public sealed interface Json permits Json.Obj, Json.Arr, Json.Str, Json.Num, Json.Bool, Json.Null {

    /** Zeroes the characters of every string in this value. */
    void wipe();

    /** An object; member order is kept for output, names are unique. */
    record Obj(Map<String, Json> members) implements Json {
        public Obj {
            members = Collections.unmodifiableMap(new LinkedHashMap<>(members));
        }

        /** The member names. */
        public Set<String> names() {
            return members.keySet();
        }

        /** The member called {@code name}, or null. */
        public Json get(String name) {
            return members.get(name);
        }

        @Override
        public void wipe() {
            members.values().forEach(Json::wipe);
        }
    }

    /** An array. */
    record Arr(List<Json> items) implements Json {
        public Arr {
            items = List.copyOf(items);
        }

        @Override
        public void wipe() {
            items.forEach(Json::wipe);
        }
    }

    /** An integer. */
    record Num(long value) implements Json {
        @Override
        public void wipe() {
            // nothing secret
        }
    }

    /** {@code true} or {@code false}. */
    record Bool(boolean value) implements Json {
        @Override
        public void wipe() {
            // nothing secret
        }
    }

    /** {@code null}. */
    enum Null implements Json {
        /** The only null. */
        NULL;

        @Override
        public void wipe() {
            // nothing secret
        }
    }

    /** A string, held as characters so it can be wiped. Not thread-safe. */
    final class Str implements Json {
        private static final char FIRST_PRINTABLE = 0x20;
        private static final char DELETE = 0x7f;
        private static final char REPLACEMENT = '\uFFFD';

        private final char[] units;

        private Str(char[] owned) {
            this.units = owned;
        }

        /**
         * A non-secret string, such as a login title from the vault. An unpaired surrogate is
         * replaced by U+FFFD, so one malformed title cannot make a whole reply unencodable.
         */
        public static Str of(String text) {
            char[] units = text.toCharArray();
            int i = 0;
            while (i < units.length) {
                boolean pair = Character.isHighSurrogate(units[i]) && i + 1 < units.length
                        && Character.isLowSurrogate(units[i + 1]);
                if (!pair && Character.isSurrogate(units[i])) {
                    units[i] = REPLACEMENT;
                }
                i += pair ? 2 : 1;
            }
            return new Str(units);
        }

        /** A copy of a secret; the caller keeps ownership of {@code secret}. */
        public static Str of(SecretChars secret) {
            char[][] copy = new char[1][];
            secret.withChars(c -> copy[0] = c.clone());
            return new Str(copy[0]);
        }

        /**
         * A copy of a UTF-8 secret, such as a stored password.
         *
         * @throws HostException {@code BAD_UTF8} if the bytes are not well-formed UTF-8
         */
        public static Str ofUtf8(SecretBytes secret) throws HostException {
            char[][] copy = new char[1][];
            HostException[] failed = new HostException[1];
            secret.withBytes(b -> {
                try {
                    copy[0] = NativeFrames.utf8(b);
                } catch (HostException e) {
                    failed[0] = e;
                }
            });
            if (failed[0] != null) {
                throw failed[0];
            }
            return new Str(copy[0]);
        }

        static Str take(char[] owned) {
            return new Str(owned);
        }

        /** Number of UTF-16 units. */
        public int length() {
            return units.length;
        }

        /** The text, for fields that are not secret. */
        public String text() {
            return String.valueOf(units);
        }

        /** A copy of the text as a secret the caller owns. */
        public SecretChars secret() {
            return SecretChars.takeOwnership(units.clone());
        }

        /** True if any unit is below U+0020 or is U+007F. */
        public boolean hasControl() {
            for (char c : units) {
                if (c < FIRST_PRINTABLE || c == DELETE) {
                    return true;
                }
            }
            return false;
        }

        char unitAt(int index) {
            return units[index];
        }

        @Override
        public void wipe() {
            Arrays.fill(units, '\0');
        }

        @Override
        public String toString() {
            return "Str[" + units.length + " chars]";
        }
    }
}
