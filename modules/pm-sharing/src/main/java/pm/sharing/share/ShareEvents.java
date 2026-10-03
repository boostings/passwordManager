package pm.sharing.share;

/** What the sender's listener reports, for the audit log (no values, lan-share.md §6 step 6). */
public interface ShareEvents {
    /** {@code share} was sent to its device and the receiver applied it. */
    void delivered(Share share);

    /**
     * A connection ended without a delivery.
     *
     * @param share the share offered on it, or null if none was
     */
    void failed(Share share, ShareException.Code code);

    /**
     * A connection was refused before any message: unpinned, revoked, or no open window for that
     * device (SR-205). Worth counting; repeated refusals may be a probe.
     */
    void refused();

    /** The listener closed: no share window remains open (SR-207). */
    void closed();
}
