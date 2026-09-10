# Data Classification

| Class | Definition | Handling rules |
| --- | --- | --- |
| **Secret** | Value whose disclosure alone compromises an account, device, or the vault | `SecretBytes` only; never `String` outside `@SecretBoundary`; never logged, never in exceptions or `toString()`; zeroed on close; encrypted at rest always; never in the envelope header; never in the audit log |
| **Sensitive** | Reveals who/what/where but not a credential | Encrypted at rest inside the vault; redacted from logs by default; may appear in the TUI unmasked; may appear in audit log only as a reference ID |
| **Metadata** | Needed to open or validate the vault; reveals nothing about contents | May be in the authenticated envelope header (AAD); may be logged |

## Field classification

| Record | Field | Class |
| --- | --- | --- |
| Vault | vault key, slot wrapping keys, per-save data key, recovery key | Secret |
| Vault | master passphrase (transient) | Secret |
| Vault | format version, KDF algorithm + parameters, salts, nonces, slot IDs, slot types | Metadata |
| Vault | record count, last-modified time | Metadata |
| Login | password | Secret |
| Login | TOTP seed (future) | Secret |
| Login | title, username, URLs, notes, tags, timestamps, health flags | Sensitive |
| Passkey | credential private key | Secret |
| Passkey | user handle, credential ID | Sensitive (user handle is opaque but linkable) |
| Passkey | display name, RP ID, RP name, user name, counter, transports, algorithm, timestamps | Sensitive |
| Wi-Fi | password / PSK | Secret |
| Wi-Fi | SSID, security type, hidden flag, notes | Sensitive |
| SSH key | private key, key passphrase | Secret |
| SSH key | public key, fingerprint, comment, hosts, agent settings | Sensitive |
| Project | environment variable values | Secret |
| Project | variable names, profile names, project name, path, git remote/identity, non-secret config values | Sensitive |
| Project | sharing and approval policies | Sensitive |
| Device | peer identity private key (this device) | Secret |
| Device | peer public keys, fingerprints, names, platform, pairing time, revocation status | Sensitive |
| Share | one-time share key, share payload | Secret |
| Share | share ID, expiry, use count, recipient device ID | Sensitive |
| Audit log | entry type, timestamp, record/project/device IDs, decision, requesting UID, command name | Sensitive |
| Audit log | chain hash, sequence number | Metadata |
| Approval request | injected env values | Secret |
| Approval request | command argv, project, profile, scope, duration, requester identity | Sensitive (argv may embed secrets: treated as Secret in logs) |
| Config | auto-lock timeout, UI preferences, backup directory | Metadata |
| Breach check | full password hash | Secret (never leaves machine) |
| Breach check | 5-char hash prefix | Sensitive (leaves machine, k-anonymous) |

## Rule mapping

Secret handling enforces `IDS15-J`, `FIO13-J`, `IDS03-J`, `ERR01-J`, `SER03-J`,
`MSC03-J`, `OBJ07-J`, `OBJ14-J`, `STR03-J`. Metadata-in-header is bounded by
`SER03-J` (no unencrypted sensitive data).
