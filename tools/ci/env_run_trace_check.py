#!/usr/bin/env python3
"""Checks an `strace -ff -ttt` trace of EnvRunNoDiskWriteTest (tools/ci/env-run-trace.sh).

Between the test's start and end markers, the test JVM and every process it starts may create,
write, rename or link only the audit log, its head sidecar (replaced through `audit.log.head.new`
and a rename; it holds a hash, never content) and the vault's lock file. Exit 0 with a
summary, 1 listing each violation, 2 if the trace is unusable (no markers, no traced child).
"""
import os
import re
import sys

MARKER = "pm-env-run-trace-marker"
ALLOWED_NAMES = ("audit.log", "audit.log.head", "audit.log.head.new")
ALLOWED_SUFFIXES = (".pmv.lock",)
ALLOWED_PREFIXES = ("/dev/", "/proc/")
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
ALWAYS_WRITES = ("creat", "rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat",
                 "mkdir", "mkdirat", "truncate")

LINE = re.compile(r"^(\d+\.\d+) (\w+)\((.*)\) += (-?\d+|\?)")
STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')


def load(trace_dir):
    """Returns (events, parent) where events are (time, tid, call, args, result)."""
    events, parent = [], {}
    for name in os.listdir(trace_dir):
        if not name.startswith("t."):
            continue
        tid = int(name.split(".", 1)[1])
        with open(os.path.join(trace_dir, name), encoding="utf-8", errors="replace") as f:
            for raw in f:
                m = LINE.match(raw.rstrip("\n"))
                if not m:
                    continue
                ts, call, args, result = float(m.group(1)), m.group(2), m.group(3), m.group(4)
                events.append((ts, tid, call, args, result))
                if call in ("clone", "clone3", "fork", "vfork") and result not in ("?",) and int(result) > 0:
                    parent[int(result)] = tid
    events.sort()
    return events, parent


def is_write(call, args):
    if call in ALWAYS_WRITES:
        return True
    if call in ("open", "openat"):
        return any(flag in args for flag in WRITE_FLAGS)
    return False


def allowed(path):
    return (os.path.basename(path) in ALLOWED_NAMES or path.endswith(ALLOWED_SUFFIXES)
            or path.startswith(ALLOWED_PREFIXES) or MARKER in path)


def main(trace_dir):
    events, parent = load(trace_dir)
    marks = [(ts, tid, call, args) for ts, tid, call, args, result in events
             if call in ("open", "openat") and MARKER in args and "O_CREAT" in args and result != "-1"]
    starts = [m for m in marks if ".start" in m[3]]
    ends = [m for m in marks if ".end" in m[3]]
    if not starts or not ends:
        print(f"env-run-trace: markers not found (start={len(starts)}, end={len(ends)})")
        return 2
    t0, worker_thread = starts[0][0], starts[0][1]
    t1 = ends[0][0]

    # The test JVM is the ancestor of the marking thread that executed java.
    execs = {tid for ts, tid, call, args, result in events if call == "execve" and result == "0"}
    java = {tid for ts, tid, call, args, result in events
            if call == "execve" and result == "0" and STRING.search(args)
            and STRING.search(args).group(1).endswith("/java")}
    root = worker_thread
    while root not in java and root in parent:
        root = parent[root]
    if root not in java:
        print("env-run-trace: could not find the test JVM's execve")
        return 2
    children = {}
    for child, par in parent.items():
        children.setdefault(par, []).append(child)
    tree, todo = set(), [root]
    while todo:
        t = todo.pop()
        if t not in tree:
            tree.add(t)
            todo.extend(children.get(t, []))

    window = [e for e in events if t0 <= e[0] <= t1 and e[1] in tree]
    child_runs = [e for e in window if e[2] == "execve" and e[4] == "0" and e[1] in execs]
    if not child_runs:
        print("env-run-trace: no child process traced inside the window; the trace proves nothing")
        return 2
    violations = []
    checked = 0
    for ts, tid, call, args, result in window:
        if not is_write(call, args) or result == "-1":
            continue
        checked += 1
        paths = STRING.findall(args)
        bad = [p for p in paths if not allowed(p)]
        if bad:
            violations.append(f"{ts:.6f} tid {tid} {call}: {', '.join(bad)}")
    print(f"env-run-trace: {len(window)} syscalls from {len(tree)} threads/processes in "
          f"{t1 - t0:.3f} s; {checked} successful writes checked; {len(child_runs)} execve in window")
    if violations:
        print("env-run-trace: FAIL, writes outside the allowlist:")
        print("\n".join(violations))
        return 1
    print("env-run-trace: PASS, only the audit log, its head and the vault lock were written")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "build/env-run-trace"))
