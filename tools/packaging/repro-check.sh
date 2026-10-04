#!/usr/bin/env bash
# Reproducibility check for the release archives and SBOM (SR-601, docs/release/packaging.md).
#
#   tools/packaging/repro-check.sh                 build twice from clean on this machine and compare
#   tools/packaging/repro-check.sh <SHA256SUMS>    build once from clean and compare with another
#                                                  builder's published manifest (second-machine check)
#
# Each build runs `clean release` with the build cache off and every task re-run, installers
# skipped (-Ppm.installers=false): installers are signed and are not expected to be
# byte-identical (plan.md Phase 5). Only the reproducible lines are compared: *.tar.gz, *.zip and
# the *.cdx.json SBOM. Both builders need the same JDK build (the SBOM records it) and the same
# commit; SOURCE_DATE_EPOCH, if set, must match too.
#
# PM_JAVA_HOME  JDK 21 home (default /opt/homebrew/opt/openjdk@21, else $JAVA_HOME)
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." >/dev/null && pwd)
jdk=${PM_JAVA_HOME:-/opt/homebrew/opt/openjdk@21}
[ -x "$jdk/bin/java" ] || jdk=${JAVA_HOME:-}
[ -n "$jdk" ] && [ -x "$jdk/bin/java" ] || { echo "repro-check: no JDK 21; set PM_JAVA_HOME" >&2; exit 2; }
dist=$root/modules/pm-cli/build/release/dist
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

build() {
    JAVA_HOME="$jdk" "$root/gradlew" -q -p "$root" --no-build-cache --rerun-tasks \
        "-Dorg.gradle.java.installations.paths=$jdk" -Ppm.installers=false \
        clean :modules:pm-cli:release </dev/null >"$work/build-$1.log" 2>&1 \
        || { echo "repro-check: build $1 failed, see:"; tail -40 "$work/build-$1.log"; exit 1; }
    grep -E '  .*\.(tar\.gz|zip|cdx\.json)$' "$dist/SHA256SUMS" | sort -k2 >"$work/sums-$1"
}

build 1
if [ $# -ge 1 ]; then
    grep -E '  .*\.(tar\.gz|zip|cdx\.json)$' "$1" | sort -k2 >"$work/sums-2"
    other=$1
else
    build 2
    other="second clean build"
fi
echo "build 1 (this machine):"; cat "$work/sums-1"
echo "compared with $other:"; cat "$work/sums-2"
if diff -u "$work/sums-1" "$work/sums-2"; then
    echo "repro-check: IDENTICAL"
else
    echo "repro-check: DIFFERENT" >&2
    exit 1
fi
