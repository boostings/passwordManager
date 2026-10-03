package pm.sharing.share;

import pm.sharing.wire.Message;

/** Validates a received record set and applies it in one vault save, or applies nothing. */
@FunctionalInterface
public interface ShareApplier {
    /**
     * Applies {@code payload}, all of it or none.
     *
     * @param kind what the offer said it is
     * @param payload the CBOR record set; the caller wipes it afterwards
     * @return true only if every record validated and the save succeeded
     */
    boolean apply(Message.Kind kind, byte[] payload);
}
