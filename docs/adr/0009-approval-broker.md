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

## Amendment 2 (2026-10-06, M7.12): the audit log keeps its lock across verify and append

A scratch run forked the audit chain: two `pm pair` processes on vaults in one
folder (one shared `audit.log`) appended entries with the same `seq` and `prev`,
and every audited operation failed after that. `AuditLog.append` took an
exclusive `FileChannel.lock()` but then re-read the log with
`Files.readAllBytes`, a second descriptor. On POSIX systems a record lock belongs
to the process and closing *any* descriptor of the file releases it, so the lock
was gone before the append. A standalone probe confirmed it (another process's
`tryLock` succeeded after the holder read the file that way, and was refused
when it did not). In-process tests did not catch it, because a JVM-wide lock
already serialized appends between threads.

Decision (SR-150): the log is opened once, read and written, without `APPEND`,
only through the locked channel; the entry is written right after the verified
bytes, and the head is replaced while the lock is still held. `check` reads
under a shared lock, so another process's half-written line is never reported
as truncation. One lock per JVM covers every open of a log, reads included, so
no thread closes a descriptor while another holds the file lock. An `AuditLog`
instance re-reads the tail on every `record` instead of appending from the
state it saw at `open`. The head file is a different file, so its descriptors
do not affect the log's lock. The format is unchanged and there is no rotation.

A log that is already forked is reported like any other break ("audit log
tampered or truncated after entry N") and is not repaired; approval-model §7
says how the user archives it and starts a new chain. Only pre-release builds
had the defect.

The adversarial review of this change found four more gaps, fixed in the same
commit:

- Locks are polled with `tryLock` (1 ms pauses doubling to 50 ms), and so is the
  per-JVM lock, up to `AuditLog.LOCK_WAIT` (10 s); then the caller gets `BUSY`,
  "the audit log is in use by another pm process; try again", and nothing is
  written (SR-158). Before, a pm process stopped inside the lock hung every other
  one without a word, and the TUI's broker start-up waited on its GUI thread. The
  TUI can still freeze for up to 10 s there; moving that check off the GUI thread
  is left for later. Readers are not made to give way to a waiting writer: no
  production path calls `check` in a loop, so a writer cannot be starved in
  practice, and a starved one now fails with `BUSY` instead of waiting forever.
- An append is all or nothing (SR-159): if the entry, its flush or the head
  replacement fails, the log is truncated back to its verified length and
  flushed before the lock goes. Before, an entry whose head could not be written
  (a full disk refuses the head's new file while the short line still fits)
  stayed in the log, recording an operation that was refused, and two such
  failures left the head two behind: `TAMPERED` for good, even after space was
  freed. If the truncation fails too, its failure is kept as a suppressed
  exception and the head lags by one; the next append updates such a head before
  writing anything.
- The reason reaches the user (SR-160). `AuditException.userMessage()` had no
  production caller: every CLI command and TUI screen printed one generic text, so
  the "after entry N" that §7 tells the user to look for never appeared. The CLI
  now prints a catalogue entry per code with N filled in, and the TUI's share and
  Devices notices show the log's own message; only a plain I/O failure keeps the
  generic text.
- A head without its log is `TRUNCATED` for writers too, and no empty log is
  created in its place (SR-150). Before, `append` created a 0-byte `audit.log`
  first, which a user following §7 could then `mv` over the archived original.

The directory is not fsynced after the head's rename (Java has no portable way);
after a power loss the head can therefore lag, which the one-entry tolerance
covers for a single lost rename.

Test: `AuditLogProcessTest` starts four JVMs that append to one log at the same
moment. It failed before the fix (5 lines, 2 distinct `seq` values). The children
are started through `EnvRunner.start`: the SR-100 ArchUnit rule leaves test
classes out, but the semgrep rule IDS07-J bans `new ProcessBuilder` in every
source file, tests included, and the env runner is the class allowed to spawn.
The same child, in `hold` mode, keeps the log's lock from another JVM while the
test checks that `append` and `check` give up with `BUSY` after the wait and
write nothing.
