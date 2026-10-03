# ADR 0013: ssh-agent client and SSH key export

- Status: Accepted
- Date: 2026-10-03

## Decision
SSH keys stored in the vault reach SSH through the user's own `ssh-agent`, not through files on
disk. All of it lives in `pm.crypto.ssh` and is driven only by `pm.cli` (SR-060, TM-61). The
compiler enforces this: `pm.crypto` has `exports pm.crypto.ssh to pm.cli`, so no other module can
name the package, not even its inlined constants (javac lint `module` suppressed, CE-021). Two
ArchUnit rules back it up: `onlyTheCliReachesSshKeys` (no class outside `pm.crypto` and `pm.cli`
depends on the package) and `noCryptoFacadeOverSshKeys` (no other `pm.crypto` package wraps it).

- **Key format.** `SshKey.parse(SecretBytes)` reads `openssh-key-v1` files (OpenSSH
  `PROTOCOL.key`), unencrypted only: Ed25519 (required) and ECDSA P-256 (`ecdsa-sha2-nistp256`).
  The private section's key fields (`string type` + key contents) are byte for byte what an
  agent's add-identity message carries, so the key keeps exactly those bytes in a `SecretBytes`
  and never returns them. Parsing is strict (SR-062): the BEGIN line must open the file and the END line must be
  followed only by line breaks; body line breaks (LF or CRLF) are removed and the rest must be
  strict base64 (any line length, as OpenSSH accepts); then magic,
  `nkeys = 1`, equal check integers, every `uint32` length bounded before use (64 KiB file,
  16 KiB public blob, 4 KiB comment), exact field sizes, minimal positive mpint below the curve
  order, padding `1, 2, 3, ...` shorter than one block, no trailing bytes, comment strict UTF-8
  with no control, format (bidi overrides and isolates such as U+202E, zero-width characters) or
  line/paragraph separator characters. The private key must match the public key: the parser signs a
  probe with the private half and verifies it with the public half, and compares the outer
  public blob in constant time.
- **Encrypted keys are refused** with `ENCRYPTED_KEY` (SR-064). Supporting them needs
  `bcrypt_pbkdf` and the OpenSSH cipher suite, which are new code or a new dependency for a case
  the user can resolve with `ssh-keygen -p -N ''` on import. The vault's own encryption protects
  the stored key.
- **Agent protocol.** `SshAgentClient` speaks draft-miller-ssh-agent over a Unix domain socket
  (`UnixDomainSocketAddress`, JDK 16+): request-identities (11), add-identity (17),
  add-identity-constrained (25, lifetime and confirm constraints; the lifetime is capped at
  2^31 - 1 s although the field is a `uint32`, because OpenSSH 10.3 `ssh-agent` fails `poll` with
  EINVAL and exits, dropping every identity, at 2^31 s or more; `ssh-add -t` also stops at
  2^31 - 1), remove-identity (18) and
  remove-all (19); replies success (6), failure (5) and identities-answer (12). Every reply is
  length-checked: 1 byte to 256 KiB, at most 1,024 identities, no trailing bytes, an exact
  1-byte success or failure. A malformed, oversized or truncated reply raises `BAD_REPLY` and
  closes the connection. Agent-supplied comments are printed with the same unsafe characters
  replaced by `?`. Requests that carry key bytes are written from a pm-owned direct buffer that
  is zero-filled afterwards; writing a heap buffer would make the JDK copy it into its per-thread
  cached direct buffer (`sun.nio.ch.Util`), which is reused but never cleared.
- **Socket checks** (SR-061; FIO00-J, FIO15-J, FIO16-J). The path from `$SSH_AUTH_SOCK` must be
  absolute. Its parent directory is canonicalised and must not be group- or world-writable. The
  socket itself is read with `NOFOLLOW_LINKS` and must be a socket (not a link or regular file)
  owned by the current user. After connecting, the listening process is checked with
  `SO_PEERCRED` (as the approval broker does on its side): it must run as the current user, which
  closes the window in which the checked socket could be swapped before the connect. Anything else
  is `UNSAFE_SOCKET`; a missing or dead socket is `NO_AGENT`.
- **Export fallback** (SR-063). `SshKeyExport.write` is the one way private bytes leave: an
  explicit export writes the OpenSSH file with `CREATE_NEW`, `NOFOLLOW_LINKS` and mode `0600` set
  at creation, so it never overwrites, never follows a link and is never briefly readable by
  others. It refuses an existing target with `TARGET_EXISTS`. The file is written through the same
  zero-filled direct buffer, and if writing or syncing fails after creation, the partial file is
  deleted (best effort) before `IO` is reported.

## Alternatives considered
- Write keys to `~/.ssh` and let `ssh` read them: leaves private keys on disk outside the vault.
- Implement an agent inside pm: would put the key in a long-lived process and duplicate what
  `ssh-agent` (and its confirm and lifetime constraints) already do.
- Parse with a third-party SSH library: a new dependency for a small, fully tested parser.
- Support RSA: not required for M4; `UNSUPPORTED_KEY` is reported cleanly.

## Consequences
- Residual risk: copies pm cannot wipe remain (as in ADR 0008): the JCA key objects built for
  the consistency probe, the `BigInteger` P-256 scalar (both unreachable once parsing returns),
  and the kernel's socket buffers until the agent reads the request (and the page cache for an
  export). The JDK's cached direct I/O buffers no longer receive key bytes (see above).
- A hung agent blocks the calling command (no read timeout on Unix domain sockets in the JDK)
  until the user interrupts it.
- Windows named-pipe agents (OpenSSH for Windows, Pageant) are out of scope for M4.
- No private key file is committed as a test fixture: an `ssh-keygen` fixture is flagged by
  gitleaks (checked 2026-10-03, "leaks found: 1"). Tests build `openssh-key-v1` files from keys
  the JDK generates, laid out as `ssh-keygen` writes them, and talk to a test agent on a socket
  in a `0700` temporary directory.
- Checked by hand against OpenSSH 10.3p1 `ssh-agent` on macOS (2026-10-03, socket in a `0700`
  temporary directory; not part of the gate): Ed25519 and ECDSA P-256 keys from `ssh-keygen`
  added by pm (ECDSA with a 600 s lifetime) are listed by `ssh-add -l` with the same fingerprints
  as `ssh-keygen -lf`; pm remove and remove-all work; exported files are `0600`,
  `ssh-keygen -y` reproduces the `.pub` exactly and `ssh-add` accepts them; exporting over an
  existing file gives `TARGET_EXISTS`; a passphrase-protected key gives `ENCRYPTED_KEY`; an RSA
  key gives `UNSUPPORTED_KEY`. After the lifetime cap: a pm add with a lifetime of 2^31 - 1 s
  is accepted and the agent stays up and keeps listing the key; `ssh-add -t 2147483648` reports
  "Invalid lifetime".

## CERT rules referenced
FIO00-J, FIO01-J, FIO15-J, FIO16-J (socket and export paths), IDS00-J, NUM00-J, MSC05-J (bounded
parsing), MSC03-J, FIO13-J (no key bytes in logs or exceptions), ERR01-J (exceptions carry codes
only), TPS00-J (test agent thread, CE-020).
