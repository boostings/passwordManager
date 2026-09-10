# Threat Model

Method: STRIDE per trust boundary (`trust-boundaries.md`), attacker profiles,
and attack trees for the three crown-jewel goals (`attack-trees.md`). Every
threat has an ID `TM-nn`, a mitigation, and a link to requirements (`SR-`) and
tests (`T-`) in `traceability.md`. Re-reviewed at the start of every milestone.

## Assets

| Asset | Class | Where |
| --- | --- | --- |
| A1 Vault key | Secret | Memory while unlocked; wrapped in slots on disk |
| A2 Record secrets (passwords, keys, env values, passkey keys) | Secret | Encrypted vault; memory transiently |
| A3 Master passphrase / recovery key | Secret | User's head/paper; memory transiently |
| A4 Device identity private key | Secret | Encrypted vault |
| A5 Trust list (paired devices) | Sensitive | Encrypted vault |
| A6 Audit log integrity | Sensitive | Hash-chained file |
| A7 Approval decisions and policies | Sensitive | Encrypted vault |
| A8 Availability of the user's own secrets | — | Local |

## Attacker profiles

| ID | Attacker | Capabilities | In scope |
| --- | --- | --- | --- |
| AT-1 | Local unprivileged process (same user) | Read/write user files, connect to local sockets, spawn processes, read env of own children, screen-scrape terminal in some configs | Yes |
| AT-2 | Local privileged process (root/admin) or physical attacker with unlocked session | Read process memory, keychain, everything | **No** (R-001); documented |
| AT-3 | Local attacker with the locked vault file only (stolen disk/backup) | Offline brute force, tamper, downgrade | Yes |
| AT-4 | LAN attacker | Sniff, spoof discovery, MITM, replay, DoS the listener | Yes |
| AT-5 | Malicious web page | Craft DOM, control origin it owns, script timing | Yes |
| AT-6 | Malicious or compromised browser extension | Send native messages, read page DOM | Yes |
| AT-7 | Malicious or over-eager AI agent / CLI caller | Send approval requests, choose scopes, retry | Yes |
| AT-8 | Malicious file (vault, backup, `.env`, update package) | Trigger parser and path bugs | Yes |
| AT-9 | Compromised upstream dependency or CI | Inject code into builds | Yes (supply chain) |
| AT-10 | Rogue paired device (revoked, lost, or its user turns hostile) | Holds old secrets, may reconnect | Yes |

## STRIDE per boundary

Legend: S spoofing, T tampering, R repudiation, I information disclosure, D denial of service, E elevation.

### TB-1 User ↔ TUI
| ID | Cat | Threat | Mitigation |
| --- | --- | --- | --- |
| TM-01 | S | Attacker at unattended unlocked terminal | Auto-lock (SR-504), lock on sleep, masked values |
| TM-02 | I | Shoulder-surf / screen capture of revealed secret or recovery key | Mask by default, reveal timer, one-time recovery display (SR-030) |
| TM-03 | I | Terminal scrollback retains revealed secret | Full-screen alternate buffer; overwrite on screen change; documented limitation for terminals that log |
| TM-04 | E | Keystroke lands on Approve | Grace period + deliberate key (SR-109) |

### TB-3/TB-4 Crypto and storage
| ID | Cat | Threat | Mitigation |
| --- | --- | --- | --- |
| TM-10 | I | Offline brute force of passphrase (AT-3) | Argon2id floors, strength gate (SR-010, SR-011) |
| TM-11 | T | Byte-level tamper of vault to corrupt or downgrade | AEAD over payload, AAD over header (SR-015, SR-020), downgrade refusal (SR-701) |
| TM-12 | I | Nonce reuse leaks XOR of plaintexts / forges tags | Per-save HKDF data key, no counters (SR-014) |
| TM-13 | I | Vault readable by other users | Owner-only perms before write (SR-040) |
| TM-14 | D/T | Crash mid-write corrupts vault | Atomic write + fsync + rename (SR-041) |
| TM-15 | I | Secrets left in memory after lock; heap dump | SecretBytes zeroing, dumps disabled (SR-505, SR-502) |
| TM-16 | I | Timing reveals correct-prefix or vault contents | Structural constant time (SR-051) |
| TM-17 | E | Malformed vault triggers parser RCE/DoS (AT-8) | Size-bounded, schema, fuzzed, no native serialization (SR-021, SR-507) |
| TM-18 | I | Keychain slot read by same-user malware (AT-1) | Off by default, warning, code-sign binding (SR-050); accepted R-002 |

### TB-5 Approval broker
| ID | Cat | Threat | Mitigation |
| --- | --- | --- | --- |
| TM-20 | S | Unauthorized process requests secrets (AT-1, AT-7) | Peer creds + session token (SR-101), broker is sole path (SR-100) |
| TM-21 | T | Displayed command differs from executed | Broker launches argv itself (SR-102) |
| TM-22 | E | Scope creep: approve-once becomes policy, or one project becomes all | Explicit scope, per-project policy cap, single-use nonce (SR-103, SR-104) |
| TM-23 | R | User disputes what was approved | Audit log before release (SR-112) |
| TM-24 | I | Secrets written to temp file for injection | In-memory env only, fs tracing test (SR-106) |
| TM-25 | S | Symlink / predictable socket path hijack | Random name, owner-only dir, refuse symlinks (SR-108) |
| TM-26 | D | Flood of requests locks the user out of the TUI | Queue cap, rate limit, timeout denies (SR-111) |
| TM-27 | I | Child leaks env to grandchildren/logs | Documented limitation + warning (SR-107); accepted |

### TB-8 LAN peer
| ID | Cat | Threat | Mitigation |
| --- | --- | --- | --- |
| TM-30 | S | Spoofed discovery / impostor device (AT-4) | Discovery advisory; SAS ceremony (SR-200, SR-201) |
| TM-31 | S/I | MITM during pairing | SAS from TLS exporter + both pubkeys; both users confirm (SR-201) |
| TM-32 | S | Brute-force SAS or pairing | Rate limit + lockout; SAS never on the wire (SR-203) |
| TM-33 | T/S | Replay of share session or message | Fresh session keys, sequence numbers (SR-202) |
| TM-34 | E | Expired/used share reopened; revoked device reconnects (AT-10) | Server-side single-use + expiry; pinned identity deleted (SR-204, SR-205) |
| TM-35 | D | Oversized/malformed messages, slowloris | Length cap, schema, timeouts, fuzz (SR-206) |
| TM-36 | I | Port left open after share | Listener lifetime bound; closed-port test (SR-207) |
| TM-37 | T | Partial apply on interruption | Verify-then-apply atomically (SR-208) |
| TM-38 | I | Rogue device already has the secret | Accepted (R-005); rotate checklist |

### TB-9 Browser share page
| ID | Cat | Threat | Mitigation |
| --- | --- | --- | --- |
| TM-40 | I | MITM serves/reads page over untrusted TLS | Key only in fragment; server sees ciphertext (SR-209) |
| TM-41 | I | QR/URL observed by bystander | Short expiry, one-use, sender confirms recipient (SR-204, SR-209) |
| TM-42 | I | Browser caches page or persists data | no-store, strict CSP, no storage, self-destruct (SR-210) |

### TB-10/TB-11 Extension
| ID | Cat | Threat | Mitigation |
| --- | --- | --- | --- |
| TM-50 | S | Wrong-origin autofill (AT-5) | Exact origin match (SR-300), explicit user action (SR-304) |
| TM-51 | S | Foreign extension talks to host (AT-6) | Manifest allowlist (SR-301) |
| TM-52 | I | Compromised extension bulk-exports | Per-release approval, one-origin policies (SR-302) |
| TM-53 | E | Malformed native message | Size + schema + fuzz (SR-303) |
| TM-54 | I | Page script reads filled value | Accepted limitation, fill on action only (SR-304) |

### TB-7/TB-12 Hardware key and ssh-agent
| ID | Cat | Threat | Mitigation |
| --- | --- | --- | --- |
| TM-60 | D | Lost security key locks user out | Multiple slots, recovery key required at setup (SR-013) |
| TM-61 | I | SSH private key bytes exposed to TUI | Keys stay in pm-crypto; ArchUnit (SR-017) |

### TB-13/TB-14 Network services
| ID | Cat | Threat | Mitigation |
| --- | --- | --- | --- |
| TM-70 | I | Breach check leaks full password hash | k-anonymity 5-char prefix only; capture test (M4) |
| TM-71 | T | Tampered update package | Pinned signing key verification (SR-602) |
| TM-72 | I | Update check reveals usage | Opt-in, no identifiers |

### TB-15 Imports and restore
| ID | Cat | Threat | Mitigation |
| --- | --- | --- | --- |
| TM-80 | E | Path traversal in backup archive | Canonicalize, reject escapes (SR-700) |
| TM-81 | D | Huge `.env` / archive exhausts memory | Size bounds, fuzz (SR-105) |
| TM-82 | I | Exported `.env` committed to git | Refuse git-tracked paths, warn (SR-110) |

### Supply chain and build (AT-9)
| ID | Cat | Threat | Mitigation |
| --- | --- | --- | --- |
| TM-90 | T | Malicious dependency version | Pinning + checksum/signature verification, allowlist (SR-600) |
| TM-91 | T | Compromised CI injects code | Reproducible JARs/image across builders, SHA-pinned actions, read-only tokens (SR-601) |
| TM-92 | I | Secret committed to repo | gitleaks on PR and history (SR-800) |
| TM-93 | E | Debug/JMX left in release | Launcher flags audit (SR-801) |

## Accepted risks

TM-18 (R-002), TM-27, TM-38 (R-005), TM-54, and all AT-2 scenarios (R-001) are
accepted and recorded in `risk-register.md`. Every other threat has a
mitigation with a test or CI check in `traceability.md`.
