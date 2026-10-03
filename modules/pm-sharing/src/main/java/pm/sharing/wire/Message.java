package pm.sharing.wire;

import java.util.List;
import java.util.Objects;

/**
 * One protocol message (lan-share.md §4). Every record validates its fields when constructed, so
 * a decoded message and a message about to be sent obey the same bounds.
 */
public sealed interface Message {
    /** Device ids are the first 16 bytes of SHA-256 of the identity key (lan-share.md §1). */
    int DEVICE_ID_BYTES = 16;
    /** Share ids are 16 random bytes. */
    int SHARE_ID_BYTES = 16;
    /** Commitments, nonces and MACs in the pairing ceremony are 32 bytes (ADR 0010 Amendment 1). */
    int PAIRING_VALUE_BYTES = 32;
    /** Room left in a frame for the rest of a SHARE_DATA message. */
    int FRAME_OVERHEAD = 256;
    /** Largest SHARE_DATA payload. */
    int MAX_PAYLOAD = Frames.MAX_BODY - FRAME_OVERHEAD;
    /** Largest error code. */
    long MAX_ERROR_CODE = 0xFFFF;

    /** The sender's sequence number; starts at 0 per direction (SR-202). */
    long seq();

    /**
     * HELLO, the first message each way.
     *
     * @param name the device name a user chose, shown on the peer's screen
     * @param caps capability tokens, at most {@link #MAX_CAPS}
     */
    record Hello(long seq, Octets deviceId, String name, List<String> caps) implements Message {
        /** The only protocol version. */
        public static final long VERSION = 1;
        /** Longest device name, in UTF-16 units (lan-share.md §2). */
        public static final int MAX_NAME = 32;
        /** Most capability tokens. */
        public static final int MAX_CAPS = 16;

        /** Validates the fields. */
        public Hello {
            Checks.length(deviceId, DEVICE_ID_BYTES, DEVICE_ID_BYTES);
            Checks.label(name, MAX_NAME);
            caps = List.copyOf(caps);
            Checks.range(caps.size(), 0, MAX_CAPS);
            caps.forEach(Checks::token);
        }
    }

    /** PAIR_REQ: the initiator asks to pair. */
    record PairReq(long seq) implements Message {}

    /** PAIR_COMMIT: the initiator's commitment to its nonce. */
    record PairCommit(long seq, Octets commit) implements Message {
        /** Validates the fields. */
        public PairCommit {
            Checks.length(commit, PAIRING_VALUE_BYTES, PAIRING_VALUE_BYTES);
        }
    }

    /** PAIR_NONCE: the responder's nonce. */
    record PairNonce(long seq, Octets nonce) implements Message {
        /** Validates the fields. */
        public PairNonce {
            Checks.length(nonce, PAIRING_VALUE_BYTES, PAIRING_VALUE_BYTES);
        }
    }

    /** PAIR_REVEAL: the initiator's nonce, opening its commitment. */
    record PairReveal(long seq, Octets nonce) implements Message {
        /** Validates the fields. */
        public PairReveal {
            Checks.length(nonce, PAIRING_VALUE_BYTES, PAIRING_VALUE_BYTES);
        }
    }

    /** PAIR_SAS_OK: the confirmation MAC, sent after the user matched the digits. */
    record PairSasOk(long seq, Octets mac) implements Message {
        /** Validates the fields. */
        public PairSasOk {
            Checks.length(mac, PAIRING_VALUE_BYTES, PAIRING_VALUE_BYTES);
        }
    }

    /** PAIR_DONE: the peer is pinned. */
    record PairDone(long seq) implements Message {}

    /** What a share carries. */
    enum Kind {
        /** One or more individual secrets. */
        SECRET("secret"),
        /** A project with its environment profiles. */
        PROJECT("project");

        private final String wireName;

        Kind(String wire) {
            this.wireName = wire;
        }

        /** The name on the wire. */
        public String wire() {
            return wireName;
        }

        /** The kind named {@code wire}. */
        public static Kind fromWire(String wire) {
            for (Kind k : values()) {
                if (k.wireName.equals(wire)) {
                    return k;
                }
            }
            throw new IllegalArgumentException("BAD_KIND");
        }
    }

    /**
     * SHARE_OFFER. The summary is names and counts, never values.
     *
     * @param expires end of the share window, epoch seconds
     */
    record ShareOffer(long seq, Octets shareId, Kind kind, String summary, long expires, boolean oneUse)
            implements Message {
        /** Longest summary, in UTF-16 units. */
        public static final int MAX_SUMMARY = 512;

        /** Validates the fields. */
        public ShareOffer {
            Checks.length(shareId, SHARE_ID_BYTES, SHARE_ID_BYTES);
            Objects.requireNonNull(kind, "kind");
            Checks.label(summary, MAX_SUMMARY);
            Checks.range(expires, 1, Long.MAX_VALUE);
        }
    }

    /** SHARE_ACCEPT. */
    record ShareAccept(long seq, Octets shareId) implements Message {
        /** Validates the fields. */
        public ShareAccept {
            Checks.length(shareId, SHARE_ID_BYTES, SHARE_ID_BYTES);
        }
    }

    /** SHARE_DATA: the record set, at most {@link #MAX_PAYLOAD} bytes. */
    record ShareData(long seq, Octets shareId, Octets payload) implements Message {
        /** Validates the fields. */
        public ShareData {
            Checks.length(shareId, SHARE_ID_BYTES, SHARE_ID_BYTES);
            Checks.length(payload, 1, MAX_PAYLOAD);
        }
    }

    /** SHARE_ACK: whether the receiver applied the share. */
    record ShareAck(long seq, Octets shareId, boolean applied) implements Message {
        /** Validates the fields. */
        public ShareAck {
            Checks.length(shareId, SHARE_ID_BYTES, SHARE_ID_BYTES);
        }
    }

    /** REVOKE: a courtesy notice that the sender no longer trusts {@code deviceId}. */
    record Revoke(long seq, Octets deviceId) implements Message {
        /** Validates the fields. */
        public Revoke {
            Checks.length(deviceId, DEVICE_ID_BYTES, DEVICE_ID_BYTES);
        }
    }

    /** ERROR with a numeric code. */
    record ErrorReport(long seq, long code) implements Message {
        /** Validates the fields. */
        public ErrorReport {
            Checks.range(code, 0, MAX_ERROR_CODE);
        }
    }

    /** BYE: orderly close. */
    record Bye(long seq) implements Message {}
}
