package pm.cli;

import java.lang.module.ModuleDescriptor;
import java.util.Optional;

/**
 * The version {@code pm --version} prints, read at run time rather than written into the source:
 * the {@code pm.cli} module's version (javac {@code --module-version}, set by the build from the
 * project version and kept by jlink), else the jar manifest's {@code Implementation-Version} when
 * pm runs from the class path, else {@link #UNKNOWN}.
 */
final class Version {
    /** Printed when neither the module nor the jar carries a version (classes run from a directory). */
    static final String UNKNOWN = "unknown";

    private Version() {
    }

    /** This build's version. */
    static String current() {
        return of(Optional.ofNullable(Version.class.getModule().getDescriptor()),
                Optional.ofNullable(Version.class.getPackage().getImplementationVersion()));
    }

    /** The module descriptor's version if it has one, else {@code implementationVersion}, else {@link #UNKNOWN}. */
    static String of(Optional<ModuleDescriptor> descriptor, Optional<String> implementationVersion) {
        return descriptor.flatMap(ModuleDescriptor::rawVersion).or(() -> implementationVersion).orElse(UNKNOWN);
    }
}
