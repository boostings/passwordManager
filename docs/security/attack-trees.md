# Attack Trees

Three crown-jewel goals. Leaves are annotated with the threat ID that mitigates
them or `ACCEPTED` with the risk ID. OR unless marked AND.

## Goal 1: Read the vault key (A1)

```
Read vault key
├── From disk
│   ├── Brute-force passphrase slot ........................ TM-10
│   ├── Read keychain slot as same user ..................... TM-18 (ACCEPTED R-002 when enabled)
│   ├── Downgrade header to weak KDF then brute-force ....... TM-11
│   └── Exploit vault parser to leak memory ................. TM-17
├── From memory
│   ├── Root/admin reads process memory ..................... ACCEPTED R-001
│   ├── Heap dump / core dump ............................... TM-15
│   └── Secret lingers after lock, later disclosed .......... TM-15
├── From the user
│   ├── Observe recovery key at setup ....................... TM-02
│   └── Phish passphrase via fake TUI ....................... TM-01 (partial: no remote surface; documented)
└── From backups
    ├── Same as "From disk" on a backup copy ................ TM-10, TM-11
    └── Restore tampered backup to weaken slot .............. TM-11, SR-701
```

## Goal 2: Obtain a record secret without approval (A2)

```
Secret without approval
├── Bypass the broker
│   ├── Find a second release code path ..................... TM-20 (ArchUnit: sole path)
│   ├── Connect to broker as unauthenticated peer ........... TM-20
│   ├── Hijack socket path (symlink) ........................ TM-25
│   └── Replay an approve-once decision ..................... TM-22
├── Deceive the user
│   ├── Display one command, run another .................... TM-21
│   ├── Request broad scope, hope for approval .............. TM-22 (UI shows scope; policy cap)
│   ├── Race a keystroke onto Approve ....................... TM-04
│   └── Flood requests until user approves to stop it ....... TM-26
├── Read it after release
│   ├── Grandchild inherits env ............................. ACCEPTED (TM-27)
│   ├── Temp file with injected env ......................... TM-24
│   ├── Log / crash report contains secret .................. SR-500, SR-501
│   └── Clipboard ........................................... SR-503
├── Via browser
│   ├── Wrong-origin autofill ............................... TM-50
│   ├── Foreign extension uses host ......................... TM-51
│   ├── Compromised extension bulk export ................... TM-52
│   └── Page script reads filled field ...................... ACCEPTED (TM-54)
└── Via sharing
    ├── Impersonate a paired device ......................... Goal 3
    ├── Reopen expired/used share ........................... TM-34
    ├── Read browser share in transit ....................... TM-40
    └── Rogue device already holds it ....................... ACCEPTED R-005
```

## Goal 3: Impersonate a paired device (A4/A5)

```
Impersonate paired device
├── During pairing
│   ├── Spoof discovery and get user to pair with attacker .. TM-30 (SAS must match on both screens)
│   ├── MITM the pairing TLS session ........................ TM-31
│   └── Brute-force SAS .................................... TM-32
├── After pairing
│   ├── Steal device identity key from the other vault ...... Goal 1 on that device
│   ├── Replay captured session ............................. TM-33
│   ├── Reconnect after revocation .......................... TM-34
│   └── Tamper trust list on disk ........................... TM-11 (trust list is inside AEAD payload)
└── Availability
    ├── Crash listener with malformed input ................. TM-35
    └── Keep port open to attack later ...................... TM-36
```
