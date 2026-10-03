package pm.browser.host;

/**
 * Answers the requests the host itself does not ({@code lookup}, {@code fill}, {@code save},
 * {@code generate}). The bridge implements it; the host owns framing, schema and the allowlist.
 */
@FunctionalInterface
public interface Handler {
    /**
     * The reply to {@code request}. The host serialises it, then {@link Json#wipe() wipes} it.
     *
     * @throws HostException to send an {@code error} reply carrying {@link HostException#getMessage()}
     */
    Json.Obj handle(Request request) throws HostException;

    /** Creates the handler for one verified caller. */
    @FunctionalInterface
    interface Factory {
        /** A handler serving the extension {@code extensionId}, which the allowlist accepted. */
        Handler forCaller(String extensionId);
    }
}
