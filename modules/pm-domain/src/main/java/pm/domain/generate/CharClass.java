package pm.domain.generate;

/** A character class a generated password may draw from. All alphabets are printable ASCII. */
public enum CharClass {
    /** {@code a-z}. */
    LOWER("abcdefghijklmnopqrstuvwxyz"),
    /** {@code A-Z}. */
    UPPER("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    /** {@code 0-9}. */
    DIGIT("0123456789"),
    /** The 32 ASCII punctuation characters. */
    SYMBOL("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");

    /**
     * Characters that are easy to confuse when read or retyped: {@code 0 O o 1 l I |} and the three
     * quote characters (which also break naive shell and CSV quoting).
     */
    public static final String AMBIGUOUS = "0Oo1lI|`'\"";

    private final String all;

    CharClass(String all) {
        this.all = all;
    }

    /** Returns this class's alphabet, without {@link #AMBIGUOUS} characters if asked. */
    public String alphabet(boolean excludeAmbiguous) {
        if (!excludeAmbiguous) {
            return all;
        }
        StringBuilder kept = new StringBuilder(all.length());
        for (int i = 0; i < all.length(); i++) {
            char c = all.charAt(i);
            if (AMBIGUOUS.indexOf(c) < 0) {
                kept.append(c);
            }
        }
        return kept.toString();
    }
}
