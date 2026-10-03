# ADR 0009: Approval broker as sole secret-release path

- Status: Proposed
- Date: 2026-09-10

## Decision
Adopt `docs/security/approval-model.md` as normative. `pm-approval` exposes
one `final` class `ApprovalBroker` with `private` decision methods (MET03-J);
ArchUnit asserts no other module calls `Vault.reveal*`/`SecretBytes`-returning
record accessors except through the broker.

Session token is the primary IPC authentication on all platforms; OS peer
credentials are defense in depth. Reason: uniform semantics and no JNI.

## Alternatives considered
- TCP loopback with token: any local process can connect; the 0700-directory
  Unix socket adds an OS-enforced layer for free.
- Per-request password prompt: unusable and trains bad habits.

## Consequences
`env run` always goes through the broker even in the same process; slight
latency, full auditability.

## CERT rules referenced
MET03-J, SEC02-J, IDS07-J, FIO00-J, FIO01-J, FIO16-J, ENV02-J, FIO13-J, LCK00-J
(broker lock is private final), THI04-J (prompt wait is interruptible).

## Amendment 1 (2026-10-03, M2.4): one transport on every OS

The broker listens on a Unix domain socket (`java.net.UnixDomainSocketAddress`,
JDK 16+) on Linux, macOS **and Windows 10 1803+**, so there is no named-pipe
code path. The socket lives in the run directory (`$XDG_RUNTIME_DIR/pm`, else
`run/` beside the vault), created 0700 (owner-only ACL on Windows), refused if
it is a link or open to others. The token file is written 0600 via
create-new + atomic rename, deleted on lock, and replaced on every unlock.

Peer credentials come from `jdk.net.ExtendedSocketOptions.SO_PEERCRED` where
the JDK offers it (Linux, macOS); a peer running as another user is denied
even with a valid token. Windows has no peer credentials; there the token and
the directory ACL are the controls, as the decision above already accepted.

Each connection carries one request frame (4-byte length, at most 64 KiB,
deterministic CBOR) and one reply frame. Oversized, truncated or undecodable
frames are answered `DENIED_MALFORMED` and audited without reading the body.
At most 8 connections are served at once; more are answered `DENIED_BUSY`.
