package pm.platform.windows;

/** Marker for the pm-platform-windows module so tooling has a class to analyze (empty in v1). */
public final class ModuleMarker {
    private ModuleMarker() {
    }

    /** Returns the module name. */
    public static String name() {
        return "pm-platform-windows";
    }
}
