package pm.vault.record;

/**
 * A record that belongs to LAN sharing rather than to the user's items (lan-share.md §1, §5): this
 * install's device identity and the trust list of paired devices. They live in the vault so they are
 * encrypted with everything else, never in a plain file. They are internal: the record list, search
 * and dashboard leave them out ({@link #isInternal}), and a share never carries one.
 */
public sealed interface DeviceRecord extends VaultRecord permits DeviceIdentityRecord, TrustedDeviceRecord {
    /** Longest device name, the HELLO name limit (lan-share.md §2, §4). */
    int MAX_NAME_CHARS = 32;

    /** Whether {@code record} is internal to sharing and must not be listed, searched or shared. */
    static boolean isInternal(VaultRecord record) {
        return record instanceof DeviceRecord;
    }

    /**
     * Returns {@code name} after checking it is 1..{@link #MAX_NAME_CHARS} UTF-16 units of
     * well-formed text with no control, format or separator characters (so no escapes or bidi
     * overrides can reach a screen).
     *
     * @throws IllegalArgumentException otherwise; the message names the field only
     */
    static String checkName(String name) {
        String checked = FieldRules.text(name, MAX_NAME_CHARS, "name");
        if (checked.isEmpty() || !checked.codePoints().allMatch(DeviceRecord::shown)) {
            throw new IllegalArgumentException("name is not a valid device name");
        }
        return checked;
    }

    private static boolean shown(int cp) {
        int type = Character.getType(cp);
        return !Character.isISOControl(cp) && type != Character.FORMAT && type != Character.LINE_SEPARATOR
                && type != Character.PARAGRAPH_SEPARATOR;
    }
}
