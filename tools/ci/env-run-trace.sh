#!/usr/bin/env bash
# plan.md §13 M2 exit criterion: "env run never writes to disk: verified with filesystem tracing
# in CI". Linux only. Runs EnvRunNoDiskWriteTest under strace, one trace file per thread, then
# checks every file-creating or file-writing syscall made by the test JVM and its children between
# the test's start and end markers (tools/ci/env_run_trace_check.py).
#
#   tools/ci/env-run-trace.sh [trace-dir]     (default build/env-run-trace)
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${1:-build/env-run-trace}
rm -rf "$out"
mkdir -p "$out"
strace -ff -ttt -qq -o "$out/t" \
    -e trace=execve,clone,clone3,fork,vfork,open,openat,creat,rename,renameat,renameat2,link,linkat,symlink,symlinkat,mkdir,mkdirat,truncate \
    ./gradlew --no-daemon --console=plain :modules:pm-cli:test --tests pm.cli.EnvRunNoDiskWriteTest --rerun-tasks
python3 tools/ci/env_run_trace_check.py "$out"
