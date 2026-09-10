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
  operation:      "env-inject" / "reveal" / "export" / "autofill" / "share" / "ssh-sign",
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
| 5 | operation = export or share | always PROMPT (no policy may cover these) |
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

| Platform | Transport | Peer authentication |
| --- | --- | --- |
| macOS | Unix domain socket at `$HOME/Library/Application Support/passwordManager/run/<random32>.sock`, dir mode 0700 | `LOCAL_PEERCRED` (uid must equal broker uid) + session token |
| Linux | Unix domain socket at `$XDG_RUNTIME_DIR/passwordManager/<random32>.sock` (fallback `$HOME/.local/state/...`, 0700) | `SO_PEERCRED` uid + session token |
| Windows | Named pipe `\\.\pipe\passwordManager-<random32>` with DACL = current user SID only, `PIPE_REJECT_REMOTE_CLIENTS` | DACL + session token |

- The socket path is written to a 0600 file the CLI reads; symlinks in the
  path are refused (`Files.isSymbolicLink` after canonicalization).
- Session token: 32 random bytes generated when the broker starts; handed to
  `env run` and agents via the same 0600 file; rotated on every vault lock.
- Java 21 `UnixDomainSocketAddress` is used on macOS/Linux; peer credentials
  are obtained via a small JNI-free approach: on Linux read `SO_PEERCRED`
  through `jdk.net.ExtendedSocketOptions` if exposed, otherwise the broker
  additionally verifies the client by requiring it to prove it can read the
  0600 token file (which only the same uid can). The token is therefore the
  primary control on all platforms and peer creds are defense in depth.
- Windows named pipes are accessed through the JDK `RandomAccessFile` on the
  pipe path; the DACL is set at creation via a PowerShell-free approach using
  `java.nio.file.attribute.AclFileAttributeView` where supported, else the
  launcher creates the pipe with the DACL (documented in platform adapter).

## 6. Injection (operation = env-inject)

The broker itself spawns the child: `new ProcessBuilder(argv)` with
`environment()` = parent env minus any variable named in the profile, plus the
approved variables. `inheritIO()` for terminal passthrough. No shell. No temp
file. Exit code is passed through. Variable values are `SecretBytes` until the
moment of `environment().put`, which requires a `String`: this is a documented
`@SecretBoundary` (R-009), and the `ProcessBuilder` object is discarded
immediately after `start()`.

## 7. Audit log

Append-only file `audit.log` in the vault directory, 0600, one CBOR entry per
line (base64), hash-chained:

```cddl
audit-entry = {
  seq: uint, ts: uint, prev: bytes .size 32,           ; SHA-256 of previous entry
  kind: "unlock"/"lock"/"approval"/"policy"/"share"/"pair"/"revoke"/"export"/"slot",
  ? request_id: bytes, ? requester_kind: tstr, ? os_user: tstr,
  ? project: tstr, ? profile: tstr, ? var_count: uint, ? record_ids: [+bytes],
  ? decision: tstr, ? argv0: tstr,                     ; program name only, never full argv
  ? device_id: bytes, ? share_id: bytes
}
```
Entry `seq`/`prev` chain is verified on open; a break is reported to the user
as "audit log tampered or truncated after entry N". No Secret-class field is
ever written (`data-classification.md`); full argv is excluded because
arguments may embed secrets.

## 8. Failure modes

All errors return a coded `DENIED_*`; the requester never learns whether a
project or variable exists unless approved. Broker crash → child not started;
no partial injection.
