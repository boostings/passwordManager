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
