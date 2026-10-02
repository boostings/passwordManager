package pm.vault.record;

/**
 * Length bounds shared by the record constructors (ADR 0006, MSC05-J): every field that
 * comes from a decrypted payload is bounded before it is kept.
 */
final class RecordLimits {
    /** Longest title, in chars. */
    static final int MAX_TITLE = 256;
    /** Longest notes or comment, in chars (64 KiB). */
    static final int MAX_NOTES = 64 * 1024;
    /** Most urls, tags or hosts in one record. */
    static final int MAX_LIST = 64;

    private RecordLimits() {
    }

    /**
     * Rejects a title longer than {@link #MAX_TITLE}.
     *
     * @param title non-null title
     */
    static void checkTitle(String title) {
        if (title.length() > MAX_TITLE) {
            throw new IllegalArgumentException("TITLE_TOO_LONG");
        }
    }

    /**
     * Rejects notes longer than {@link #MAX_NOTES}.
     *
     * @param notes non-null notes or comment
     */
    static void checkNotes(String notes) {
        if (notes.length() > MAX_NOTES) {
            throw new IllegalArgumentException("NOTES_TOO_LONG");
        }
    }

    /**
     * Rejects a list with more than {@link #MAX_LIST} entries.
     *
     * @param size list size
     */
    static void checkListSize(int size) {
        if (size > MAX_LIST) {
            throw new IllegalArgumentException("TOO_MANY_ENTRIES");
        }
    }
}
