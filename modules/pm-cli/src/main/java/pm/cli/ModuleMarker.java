package pm.cli;

/** Marker for the pm-cli module so tooling has a class to analyze; removed when real code lands. */
public final class ModuleMarker {
    private ModuleMarker() {
    }

    /** Returns the module name. */
    public static String name() {
        return "pm-cli";
    }
}
