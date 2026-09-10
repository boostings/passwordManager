# Abuse Cases

One or more abuse cases per user journey in `plan.md` §3. Each maps to a
threat ID (Phase 3) and a security requirement (`SR-nnn`).

## Journey: First vault

| ID | Abuse case | SR |
| --- | --- | --- |
| AC-01 | Attacker with a copy of the vault file brute-forces a weak passphrase offline | SR-010, SR-011 |
| AC-02 | Malware swaps the vault file for a crafted one to trigger a parser bug on open | SR-020, SR-021 |
| AC-03 | Shoulder-surfer or screen recorder captures the recovery key during setup | SR-030 |
| AC-04 | Vault created in a shared or world-readable directory | SR-040 |
| AC-05 | User enables keychain unlock; same-user malware unlocks silently | SR-050 |

## Journey: Environment workflow

| ID | Abuse case | SR |
| --- | --- | --- |
| AC-10 | Malicious local process connects to the broker and requests `production` secrets | SR-100, SR-101 |
| AC-11 | Process spoofs the approval dialog text (shows `npm start`, runs something else) | SR-102 |
| AC-12 | Agent requests a broad scope ("all profiles") and hopes the user clicks approve | SR-103 |
| AC-13 | Approve-once decision is replayed to inject secrets again | SR-104 |
| AC-14 | A crafted `.env` file with huge or malformed content crashes the importer | SR-105 |
| AC-15 | `env run` writes a temp file with secrets that survives a crash | SR-106 |
| AC-16 | Child process inherits secrets, then a grandchild is spawned with the environment intact and logged elsewhere | SR-107 (documented limitation + warning) |
| AC-17 | Broker socket path is predictable and a symlink is planted | SR-108 |
| AC-18 | Approval request arrives while the user is typing; keystroke lands on "approve" | SR-109 |
| AC-19 | User's `.env` export lands in a git-tracked directory | SR-110 |

## Journey: LAN sharing

| ID | Abuse case | SR |
| --- | --- | --- |
| AC-20 | LAN attacker answers discovery pretending to be the user's laptop | SR-200 |
| AC-21 | Active man-in-the-middle during pairing | SR-201 |
| AC-22 | Captured share session is replayed later | SR-202 |
| AC-23 | Pairing code brute-forced by repeated attempts | SR-203 |
| AC-24 | Expired or already-used share is re-opened | SR-204 |
| AC-25 | Revoked device reconnects with old credentials | SR-205 |
| AC-26 | Oversized or malformed protocol message exhausts memory or hangs the listener | SR-206 |
| AC-27 | Listener keeps running after the share ends, exposing a port | SR-207 |
| AC-28 | Transfer interrupted; recipient ends up with a half-applied project | SR-208 |
| AC-29 | Browser share page served to the wrong person who scanned the QR over a shoulder | SR-209 |
| AC-30 | Browser page cached or persisted by the browser after expiry | SR-210 |

## Journey: Browser workflow

| ID | Abuse case | SR |
| --- | --- | --- |
| AC-40 | Malicious page mimics a login form and triggers autofill for another origin | SR-300 |
| AC-41 | Subdomain/port/scheme confusion (`evil.example.com`, `http://` vs `https://`) | SR-300 |
| AC-42 | A different extension talks to the native messaging host | SR-301 |
| AC-43 | Extension is compromised and bulk-exports credentials | SR-302 |
| AC-44 | Native messaging host receives malformed JSON and crashes or misparses | SR-303 |
| AC-45 | Page reads autofilled value via script before the user submits | SR-304 (documented limitation; fill on explicit user action only) |

## Journey: Passkeys

| ID | Abuse case | SR |
| --- | --- | --- |
| AC-50 | Relying-party ID mismatch lets a phishing site assert a passkey | SR-400 |
| AC-51 | Signature counter regresses after restore from backup, RP flags clone | SR-401 |
| AC-52 | Passkey private key exposed to the TUI or extension layer | SR-402 |

## Cross-cutting

| ID | Abuse case | SR |
| --- | --- | --- |
| AC-60 | Secrets appear in logs, crash reports, or diagnostics bundles | SR-500 |
| AC-61 | Exception message includes a secret or a vault path | SR-501 |
| AC-62 | Heap dump or core dump captures the unlocked vault | SR-502 |
| AC-63 | Clipboard retains a copied secret indefinitely | SR-503 |
| AC-64 | App left unlocked on an unattended terminal | SR-504 |
| AC-65 | Vulnerable dependency ships in a release | SR-600 |
| AC-66 | Tampered installer or update | SR-601, SR-602 |
| AC-67 | Backup restore with path traversal entries overwrites files | SR-700 |
| AC-68 | Vault downgrade to an older format with weaker parameters | SR-701 |
| AC-69 | Developer commits a test vault with real data | SR-800 |
| AC-70 | Remote JMX/debug port enabled in a release build | SR-801 |
