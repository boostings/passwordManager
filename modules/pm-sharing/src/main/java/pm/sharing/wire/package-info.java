/**
 * The LAN protocol's wire format (lan-share.md §4): length-prefixed frames of deterministic CBOR,
 * decoded strictly into {@link pm.sharing.wire.Message} values before anything dispatches on them
 * (SR-202, SR-206).
 */
package pm.sharing.wire;
