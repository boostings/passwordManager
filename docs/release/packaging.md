# Packaging and release artifacts (M7.3)

How pm is packaged for release, how to check the hashes, and which steps only a maintainer with
signing credentials can do. Requirements: SR-710 to SR-714 (with SR-502, SR-600, SR-601, SR-801)
in [requirements](../security/requirements.md); traceability rows under "M7 packaging" in
[traceability](../security/traceability.md).

All tasks live in `tools/packaging/release.gradle.kts`, applied by `modules/pm-cli`. No
third-party Gradle plugin is used: the SBOM and the manifest are written from Gradle's resolved
runtime classpath, so `gradle/verification-metadata.xml` did not change.

## Build

```sh
export JAVA_HOME=/opt/homebrew/opt/openjdk@21        # any JDK 21 with jmods/
./gradlew release -Dorg.gradle.java.installations.paths=$JAVA_HOME
```

`release` runs, for the current OS only:

| Task | Output (under `modules/pm-cli/build/release/`) |
| --- | --- |
| `jlinkImage` | `runtime/`: jlink image of the JDK modules pm needs |
| `distImage` | `image/pm-<version>-<os>-<arch>/` with `bin/pm` (`bin/pm.bat` on Windows), `runtime/`, `app/` |
| `releaseTar`, `releaseZip` | `dist/pm-<version>-<os>-<arch>.tar.gz` and `.zip` (reproducible) |
| `jpackageImage` | `jpackage/pm.app` (macOS) or `jpackage/pm/`: native launcher app-image |
| `jpackageInstallers` | `dist/pm-<version>-<os>-<arch>.dmg` and `.pkg` (macOS), `.deb`/`.rpm` (Linux, when `dpkg-deb`/`rpmbuild` exist), `.msi` (Windows, when WiX 3 `candle.exe`/`light.exe` exist). A missing tool is logged as `SKIPPED` |
| `cyclonedxSbom` | `dist/pm-<version>.cdx.json` |
| `sha256Manifest` | `dist/SHA256SUMS` over every file in `dist/` |
| `signManifest` | `dist/SHA256SUMS.asc` when `PM_GPG_KEY` is set |
| `verifyReleaseHashes` | re-hashes `dist/` against `SHA256SUMS` |
| `releaseSmoke` | runs `bin/pm --help` and the jpackage launcher under a pseudo-terminal, mounts the dmg and runs its launcher, and compares payload hashes (below) |

`-Ppm.installers=false` skips the native installers (the dmg step alone takes about two minutes
because jpackage lays out the Finder window). The installers carry the project version (1.0.0);
`-Ppm.packageVersion=1.2.3` overrides it for the installers only (jpackage on macOS refuses a
version whose first number is 0). Archive names always use the project version.

`check` (and so the gate) runs only `releaseMetadataCheck` and the `jlinkImage` it needs (a few
seconds; jlink and jmods ship with the pinned JDK 21 on every OS). No jpackage, installer or smoke
run is part of `check`. The check builds the SBOM twice and requires identical output, parses it
back, recomputes the SHA-256 of every runtime jar and of the runtime's `lib/modules`, checks purls,
the linked module list and dependency references, then writes a `SHA256SUMS` over a scratch copy
and checks the verifier catches a changed byte, a malformed line and a `../` name.

## What is in the image

- `runtime/`: `jlink --strip-debug --no-header-files --no-man-pages --compress=zip-6` over the JDK
  modules named by every `requires` (static ones included) of every module on the runtime module
  path, plus two modules no `requires` reaches but the app loads at run time: `jdk.crypto.ec`
  (SunEC, used by `pm.crypto` for EC and Ed25519 on JDK 21) and `jdk.unsupported` (Lanterna loads
  `sun.misc.Signal` reflectively for the terminal-resize handler). Lanterna's
  `requires static java.desktop` must be followed: its `TextColor` uses `java.awt.Color`, and
  without it the TUI died with "internal error" seconds after opening (found in the M7.3 review;
  `--help` never touched it). The full JDK hides such gaps because its boot layer binds services
  and so resolves far more modules than `requires` names; that is why the dev launcher
  `scripts/pm` worked. Today that is 14 modules, about 45 MB (`java.desktop` brings
  `java.datatransfer`, `java.prefs` and `java.xml`; Bouncy Castle requires `java.naming`,
  `java.sql` and `java.logging`). The build fails if a debug or monitoring module (`jdk.jdwp.agent`,
  `jdk.management.agent`, `java.management`, `java.management.rmi`, `jdk.attach`,
  `java.instrument`, `jdk.jdi`, `jdk.jshell`, `jdk.jcmd`, `jdk.jstatd`) is in the image (SR-710).
- The hardening flags `-XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError
  -XX:-CreateCoredumpOnCrash` are stored in the runtime itself with `jlink --add-options` and are
  also passed to jpackage as `--java-options`. The build reads them back with
  `-XX:+PrintFlagsFinal` (SR-711). They are defaults, not a lock: see "JVM options from the
  environment" below.
- `app/`: the pm module jars and their dependencies (Bouncy Castle, Lanterna) exactly as Gradle
  resolved and verified them, so each file's SHA-256 matches the SBOM. They are kept on the module
  path rather than linked into the runtime: `bcprov` is a signed modular jar, which jlink accepts
  only by dropping its signature (`--ignore-signing-information`).
- Third-party data inside a pm jar (M6.3): `pm-browser` carries an unmodified copy of the Public
  Suffix List, `pm/browser/webauthn/public_suffix_list.dat`, from
  https://publicsuffix.org/list/public_suffix_list.dat (`VERSION: 2026-10-01_23-02-52_UTC`,
  `COMMIT: 6cd82aff889e3d64e5e03bc5c1f43da1934a960a`, fetched 2026-10-04, SHA-256
  `e0fe072d26b0536525badea237953ff451c9f8e64c9d02c6daa81a4491d2fc66`), licensed MPL-2.0, with
  its notice `public_suffix_list.NOTICE` beside it. It is data, not a dependency, so the SBOM
  lists it only through the `pm-browser` jar's hash; the release notes must name it with its
  licence. `PublicSuffixList` refuses a file with another digest: WebAuthn requests then get
  `PSL_UNAVAILABLE` and everything else keeps working (ADR 0016 M6.3 addendum).
- `bin/pm`: a POSIX shell launcher (`exec runtime/bin/java -p app -m pm.cli/pm.cli.Main`). It clears
  `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS` and `CLASSPATH`, ignores `CDPATH`, and
  accepts only `PM_MAX_HEAP` from the environment: 1 to 5 digits with an `m` or `g` suffix,
  between 64m and 64g, for 1 GiB Argon2 vaults. `bin/pm.bat` clears the same variables on Windows
  (not exercised on a Windows host yet).

## JVM options from the environment (residual risk)

The JVM reads `JAVA_TOOL_OPTIONS` and `_JAVA_OPTIONS`, and the `java` launcher reads
`JDK_JAVA_OPTIONS`, before any pm code runs, and options from them are applied after the ones
baked into the runtime. The M7.3 review showed `JAVA_TOOL_OPTIONS=-XX:-DisableAttachMechanism`
re-enabling attach on the jpackage launcher (`jcmd` then worked). Three layers address it:

1. `bin/pm` (and `bin/pm.bat`) unset the three variables before starting Java.
2. `pm.cli.Main` refuses to run, with exit code 2 and the message "JAVA_TOOL_OPTIONS, _JAVA_OPTIONS
   or JDK_JAVA_OPTIONS is set; ...", when any of them is set to a non-empty value. This covers
   the jpackage launcher, which cannot clear its environment, and a direct `runtime/bin/java`
   start. `releaseSmoke` checks it on the app-image.
3. The flags are also in the jpackage launcher config.

The refusal in `Main` is detection, not prevention: by the time `main` runs the JVM has already
applied the options, so a malicious agent or debug option given through the environment has
already run. pm stops before opening any vault, so no secret is loaded into that JVM. Whoever can
set environment variables for the user's processes can also replace the launcher or the
user's shell, so this is accepted as residual risk (trust boundary: the local user account).

## Smoke checks

pm refuses to run without a terminal, even for `--help`, so `releaseSmoke` runs the launchers under
`script(1)`:

- `--help` on the archive launcher, the app-image launcher and the mounted dmg's launcher.
- The app-image launcher with `JAVA_TOOL_OPTIONS` set must exit 2 with the refusal message.
- The TUI, on the archive launcher and the app-image launcher. The smoke run creates a throwaway
  vault with a fixed test passphrase, presses Enter to open the app, and requires that the
  process is still running, with no "internal error", 30 seconds after the TUI took the screen.
  Then it kills only the process tree it started and deletes the vault.

On Windows these runs are skipped with a message; run `pm` by hand in a console there.

## Reproducibility

Archives use fixed entry timestamps (Gradle's constant: the epoch for tar, 1980-02-01 for zip),
sorted entries, owner and group 0 with no names, and permissions set to 0755 for executables and
directories and 0644 for everything else, so the builder's umask and checkout mode do not leak in.
The SBOM has no random serial number (a name-based UUID of its content) and takes its timestamp
from `SOURCE_DATE_EPOCH`, else the HEAD commit time.

```sh
tools/packaging/repro-check.sh                       # two clean builds here, compare
tools/packaging/repro-check.sh path/to/SHA256SUMS    # one clean build, compare with another builder
```

The script runs `clean release -Ppm.installers=false --no-build-cache --rerun-tasks` and compares
only the reproducible lines: the tar.gz, the zip and the SBOM. The hashes themselves are not
recorded here, because they change with every commit that touches a jar, the launcher or the
runtime. To get the reference hashes for a release, run the script on the tagged commit and keep
the `SHA256SUMS` it leaves in `modules/pm-cli/build/release/dist/`.

Limits:

- Builders must use the same JDK build: the jlink image contains that JDK's class image and
  native binaries, and the SBOM records the JDK version. A different patch release or vendor
  gives a different image by design.
- The archives are per OS and architecture; compare like with like.
- Installers (dmg, pkg, msi, deb) are not byte-reproducible: jpackage and the platform signing
  steps embed timestamps and signatures, and macOS code signing rewrites native binaries. Instead
  `releaseSmoke` checks that the app-image and the mounted dmg contain the same runtime class image
  (`lib/modules`), `release` file and application jars as the reproducible image (plan.md Phase 5).
  The pkg, deb, rpm and msi payloads are not yet checked this way.
- The SBOM timestamp follows the commit, so its hash changes with every commit even when nothing
  else does.
- The SBOM's runtime component carries the SHA-256 of `runtime/lib/modules` (the class image of
  every linked JDK module) plus, as a property, that of `runtime/release`. Native files
  (`bin/java`, `lib/*.dylib`) are left out of that hash because platform code signing rewrites
  them; the archive hashes in `SHA256SUMS` cover them for the unsigned image.

## Verifying a download

```sh
shasum -a 256 -c SHA256SUMS          # macOS; on Linux: sha256sum -c SHA256SUMS
gpg --verify SHA256SUMS.asc SHA256SUMS   # once releases are gpg-signed
```

`./gradlew verifyReleaseHashes` does the same check on a local `dist/`.

## Signing hooks

Every signing step reads its credential reference from an environment variable and is skipped
with a logged message when the variable is unset. Nothing secret is stored in the repository or
in the build (SR-714).

| Variable | Effect |
| --- | --- |
| `PM_MAC_SIGN_IDENTITY` | Passes `--mac-sign --mac-signing-key-user-name <value>` to jpackage for the app-image, dmg and pkg. The value is the certificate's name without the `Developer ID Application: ` prefix |
| `PM_MAC_KEYCHAIN` | Optional keychain path for the identity above |
| `PM_NOTARY_PROFILE` | After the dmg is built: `xcrun notarytool submit <dmg> --keychain-profile <value> --wait`, then `xcrun stapler staple <dmg>` |
| `PM_WIN_SIGN_CERT_SHA1` | `signtool sign /sha1 <value> /fd SHA256 /tr <url> /td SHA256` on `pm.exe` in the app-image and on the msi |
| `PM_WIN_TIMESTAMP_URL` | RFC 3161 timestamp server for signtool (default `http://timestamp.digicert.com`) |
| `PM_GPG_KEY` | `gpg --armor --detach-sign` of `SHA256SUMS` into `SHA256SUMS.asc` |

Signing happens before `SHA256SUMS` is written, so the manifest covers the signed and stapled
files.

## User-only items (not possible on the build machine)

| Item | Needed for | Status on the M7.3 machine |
| --- | --- | --- |
| Apple Developer ID Application (and Installer) certificate in the keychain | signed app-image, dmg, pkg (`PM_MAC_SIGN_IDENTITY`) | missing: app-image is ad-hoc signed only |
| `notarytool` keychain profile (`xcrun notarytool store-credentials`) | notarized, stapled dmg (`PM_NOTARY_PROFILE`) | missing |
| Authenticode code-signing certificate and `signtool` | signed `pm.exe` and msi | not available (no Windows host) |
| WiX 3 (`candle.exe`, `light.exe`) on a Windows host | msi | not available. JDK 21 jpackage needs WiX 3 |
| `dpkg-deb` / `rpmbuild` on a Linux host | deb / rpm | not available (macOS host) |
| Release gpg key on a hardware token | `SHA256SUMS.asc` (`PM_GPG_KEY`) | not set up |
| Second, independent builder with the same JDK build | SR-601 / SR-712 two-machine hash match: run `tools/packaging/repro-check.sh <published SHA256SUMS>` there | pending |
