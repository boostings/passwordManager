# Approval Model Specification

The approval broker (`pm-approval`) is the single point through which any
secret leaves the vault to a process, extension, or device (SR-100). This
document is normative; ADR 0009 records the decision.

## 1. Request

```cddl
approval-request = {
  schema_version: 1,
  request_id:     bytes .size 16,          ; random, single-use (SR-104)
  requester:      requester,
  operation:      "env-inject" / "reveal" / "export" / "autofill" / "share" / "ssh-sign" / "passkey",
  scope:          scope,
  duration_s:     uint .le 86400,          ; requested validity if policy asked
  display:        display,
  created:        uint                     ; epoch seconds
}
requester = {
  kind: "cli" / "agent" / "extension" / "device",
  os_user:  tstr,                          ; verified by broker, not caller-supplied
  session:  bytes .size 32,                ; per-session token (SR-101)
  label:    tstr .size (1..64),            ; caller-supplied, shown in quotes as untrusted
  ? extension_id: tstr,
  ? device_id:    bytes .size 16
}
scope = {
  project:   tstr,                         ; exactly one project per request (SR-103)
  ? profile: tstr,
  ? vars:    [+ tstr],                     ; subset; absent = whole profile (shown as such)
  ? records: [+ bytes .size 16]            ; for reveal/autofill/share
}
display = {
  ? argv: [+ tstr],                        ; exact argv broker will exec (SR-102)
  ? origin: tstr,                          ; for autofill
  effect: "inject" / "show" / "write-file" / "send"
}
```

Rules: the broker fills `requester.os_user` and validates `session` itself;
caller-supplied text is rendered in the TUI inside a visibly distinct
"untrusted label" style and truncated. `argv` in `display` is the only argv
the broker will execute; `env run` constructs the request from the command
line, so display and execution cannot diverge.

## 2. Decision options

| Option | Semantics | Persisted |
| --- | --- | --- |
| Approve once | This `request_id` only | Audit log only |
| Approve for session | Same requester session + same scope until vault locks | In-memory policy, dies on lock |
| Approve temporary policy | Same scope (never wider) for `duration_s` ≤ 24 h | In vault, expires |
| Deny | Nothing released; requester gets `DENIED` | Audit log |
| (timeout 60 s) | Treated as Deny (SR-111) | Audit log `DENIED_TIMEOUT` |

A policy can never cover more than one project, and never "all profiles".
A policy created from a request with `vars` covers only those vars.

## 3. Decision table

Evaluation order for an incoming request `q`:

| # | Condition | Result |
| --- | --- | --- |
| 1 | vault locked | DENIED_LOCKED (no prompt) |
| 2 | session token invalid or os_user mismatch | DENIED_AUTH (no prompt, audit) |
| 3 | `request_id` seen before | DENIED_REPLAY |
| 4 | schema invalid / size > 64 KiB | DENIED_MALFORMED |
| 5 | operation = export, share or passkey | always PROMPT (no policy may cover these; a session or policy answer counts once and stores nothing, so the TUI prompt offers only once and deny; passkey since M6.3, ADR 0016) |
| 6 | active session policy matches (requester.session, project, profile, vars ⊆) | ALLOWED_SESSION |
| 7 | stored temporary policy matches and not expired | ALLOWED_POLICY |
| 8 | pending prompt queue ≥ 5 | DENIED_BUSY |
| 9 | otherwise | PROMPT → user decision |

"Matches" is exact on project and profile and subset on vars; a request
without `vars` (whole profile) does **not** match a policy that lists vars.

## 4. Prompt UX (SR-109)

- Dialog shows: requester kind + quoted label, verified os_user, operation,
  project/profile/vars (count and names), effect, and exact argv on its own
  lines.
- Inputs are ignored for 500 ms after the dialog appears.
- Approve requires `y` then `Enter`; session/policy approvals require `s`/`p`
  then `Enter` and a confirmation line. `Esc` or `n` denies.
- Multiple pending requests are shown one at a time in arrival order.

## 5. IPC transport and authentication (SR-101, SR-108)

As built at M2.4 (ADR 0009 Amendment 1, which supersedes the per-platform table drafted here in
M0): one transport on every OS.

| Platform | Transport | Peer authentication |
| --- | --- | --- |
| macOS | Unix domain socket `broker.sock` in the run directory, dir 0700 | `SO_PEERCRED` via `jdk.net.ExtendedSocketOptions` (uid must equal the broker's) + session token |
| Linux | Same, run directory `$XDG_RUNTIME_DIR/pm` | Same |
| Windows 10 1803+ | Same (`UnixDomainSocketAddress`), run directory with an owner-only ACL | No peer credentials in the JDK: session token + directory ACL |

- Run directory: `$XDG_RUNTIME_DIR/pm` when set, else `run/` beside the vault (`RunDir.locate`).
  The broker creates it owner-only; the broker and the client both refuse it if it is a link,
  not a directory, or open to anyone else (`UNSAFE_PATH`).
- Session token: 32 random bytes, written to `token` in the run directory 0600 through
  create-new and an atomic rename, deleted on lock and replaced on every unlock. The token is the
  primary control on all platforms; peer credentials are defense in depth.
- Frames: one request and one reply per connection, 4-byte length, at most 64 KiB, deterministic
  CBOR. Oversized, truncated or undecodable frames are answered `DENIED_MALFORMED` and audited
  without reading the body; a wrong token is denied and audited. At most 8 connections at once.
- plan.md §13 M2 named a Windows named pipe with a user-SID DACL. That was replaced by the socket
  above (ADR 0009 Amendment 1): the JDK has no named-pipe server API, and the directory ACL gives
  the same "current user only" property. Recorded as a deviation in the M2 sign-off.

## 6. Injection (operation = env-inject)

The child is spawned by `pm.approval.run.EnvRunner`, the only class that builds processes:
`new ProcessBuilder(argv)` where `argv` is `display.argv` of the approved request, with
`environment()` = parent env minus the scrubbed names, plus the approved variables.
`inheritIO()` for terminal passthrough. No shell. No temp file. Exit code is passed through
(127 if the program cannot be started). Variable values are `SecretBytes` until the moment of
`environment().put`, which requires a `String`: this is a documented `@SecretBoundary` (R-009),
and the `ProcessBuilder` object is discarded immediately after `start()`.

**Where it runs (M2.6).** The runner executes in the `pm env run` process, which owns the
user's terminal; the broker lives in the TUI, which owns the screen. After the user approves, the
broker sends the approved values over the authenticated socket (§5) in the reply, and the CLI
runs exactly the argv it put in the request, so what was shown is what runs (SR-102). In that
path the scrubbed names are the released ones.

**Without a broker.** If no TUI is running (no token file), or `--project` was not given, `pm env
run` unlocks the vault itself: the passphrase plus a typed `y` after the same summary (project,
profile, variable names, argv one element per line) are the approval. The values are copied out
and the vault is locked before the command starts; the profile's names are scrubbed from the
inherited environment; an `approval` entry is appended to the audit log first, and no entry means
no run.

## 7. Audit log

Append-only file `audit.log` in the vault directory, 0600, one CBOR entry per
line (base64), hash-chained. The TUI's broker and CLI commands write the same file through
`AuditLog.append`, often from separate processes (and vaults in one folder share one log). Each
writer holds an exclusive lock on `audit.log` from reading the chain to replacing
`audit.log.head`, and reads and writes the log only through the locked descriptor: on POSIX
systems the lock belongs to the process and is dropped as soon as the process closes *any*
descriptor of the file. `AuditLog.check` reads under a shared lock, and the threads of one
process take turns on top of the file lock. So concurrent writers cannot fork the chain (SR-150).
Both the file lock and the per-process turn are polled, never awaited without end: a caller that
has not got them after 10 s (`AuditLog.LOCK_WAIT`, for example because another pm process was
stopped with Ctrl-Z in the middle of an append) writes nothing and reports
"the audit log is in use by another pm process; try again" (`BUSY`, SR-158):

```cddl
audit-entry = {
  seq: uint, ts: uint, prev: bytes .size 32,           ; SHA-256 of previous entry
  kind: "unlock"/"lock"/"approval"/"prompt"/"policy"/"share"/"pair"/"revoke"/"export"/"slot",
  ? request_id: bytes, ? requester_kind: tstr, ? os_user: tstr,
  ? project: tstr, ? profile: tstr, ? var_count: uint, ? record_ids: [+bytes],
  ? decision: tstr, ? argv0: tstr,                     ; program name only, never full argv
  ? device_id: bytes, ? share_id: bytes
}
```
Entry `seq`/`prev` chain is verified on open; a break is reported to the user
as "audit log tampered or truncated after entry N". A chain cannot notice entries
cut from the end, so a 0600 sidecar `audit.log.head` holds the last `seq` and
its SHA-256 after each append (it may lag the log by one entry, never lead it).
A same-user process can rewrite both files; the log detects
accidents and naive edits, not a same-user attacker (threat model T-12). No Secret-class field is
ever written (`data-classification.md`); full argv is excluded because
arguments may embed secrets.

An append is all or nothing (SR-159). If writing the entry, flushing it or
replacing the head fails (a full disk can refuse the head's new file while the
short log line still fits), the writer cuts the log back to its length before
the append and flushes it, still under the lock, and the operation is refused
with the I/O message: a refused operation leaves no entry. Only if that cut fails
too, or the process dies between the entry and the head, does the entry stay
with the head one behind; the next append first brings such a head up to date
(and writes nothing if it cannot), so the head never falls two behind and a
retry after the disk has room again succeeds.

**What the user sees.** The CLI prints the reason on standard error and exits 2:
"audit log tampered or truncated after entry N, so nothing was done; ..." for a
break, the `BUSY` text above, "audit log is a link or is readable by other users,
so nothing was done", "audit log is too large, so nothing was done; archive it
with its .head file", and the command's own generic text (such as "the audit log
could not be written, so nothing was exported") only for a plain I/O failure
(`env run` without a broker, `env export`, `ssh add`, `ssh export`, `share`,
`devices remove`; SR-160). Where the change is already made when its entry is
written (`pair`, a delivered or closed share, `receive`, `revoke`, `passphrase`,
`recover`), the command instead says what did happen ("the item was received and
saved, but its audit log entry could not be written") and exits 11 (SR-134). The
TUI's share and Devices screens show the log's own message in their notice line
in the same cases. Two TUI paths still show only a generic text: sending an SSH
key to the agent ("The audit log could not be written, so the key was not sent.")
and broker start-up, which on a broken or busy log silently runs without a
broker, so `pm env run` falls back to the CLI path and prints the CLI message.

**When the log reports a break.** pm never repairs the log, because it
cannot tell an accident from an edit. While the chain is broken, every
append fails, so the broker denies requests (the TUI does not start its
broker on a broken log), and CLI commands that must be audited stop (`env export`, for example, exports
nothing and exits 2). Pre-release builds before M7.12 released
the lock early (they re-read the log through a second descriptor), so two
writers at the same moment could append two entries with the same `seq` and
`prev`. Such a fork is reported like any other break, as "audit log tampered
or truncated after entry N", N being the last entry before the duplicate.
pm does not decide whether that was a fork or tampering: the user does, by
reading the file (the two lines after entry N decode to the same `seq` and
`prev`). To start a new log, in this order:

1. Quit every pm process that uses vaults in that folder (TUI and CLI).
2. Move `audit.log` **and** `audit.log.head` out of the folder together into a
   new, dated archive folder, without overwriting anything there (for example
   `mkdir audit-2026-10-06 && mv -n audit.log audit.log.head audit-2026-10-06/`).
   Keep them as evidence; do not edit them. Moving only `audit.log` is reported
   as truncation after entry 0, because the head still names the old last entry;
   pm then creates no new `audit.log` (SR-150), so moving the head afterwards
   loses nothing.
3. The next audited operation starts a new chain at entry 1.

A log over 64 MiB (`TOO_LARGE`) is archived the same way.

## 8. Failure modes

All errors return a coded `DENIED_*`; the requester never learns whether a
project or variable exists unless approved. Broker crash → child not started;
no partial injection.
