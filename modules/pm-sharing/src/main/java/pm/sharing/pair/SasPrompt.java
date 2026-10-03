package pm.sharing.pair;

/** Asks the local user whether the peer's screen shows the same digits. */
@FunctionalInterface
public interface SasPrompt {
    /**
     * Shows {@code sas} with the peer's name and fingerprint, and waits for the answer.
     *
     * @return true only if the user says the digits match
     */
    boolean sameDigits(String sas, String peerName, String peerFingerprint);
}
