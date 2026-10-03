package pm.sharing.web;

/** What the browser share listener reports, for the TUI and the audit log. Never carries values. */
public interface WebEvents {
    /**
     * The page was fetched for the first time. This shows that something fetched the path, not
     * that the recipient has the key: a link preview can fetch the page too.
     */
    void opened();

    /** The ciphertext was fetched; the share is used up. */
    void delivered();

    /** The listener closed and its port is free. */
    void closed();
}
