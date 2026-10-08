# Risk Register

Severity scale and fix SLAs are defined in `SECURITY.md`.
Likelihood: Rare / Possible / Likely. Impact: Low / Medium / High / Critical.

| ID | Risk | Likelihood | Impact | Mitigation | Owner | Status | Opened |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R-001 | Fully compromised OS (root/admin malware) reads process memory or the unlocked vault | Possible | Critical | Out of scope by design; minimize plaintext lifetime; document limitation | security owner | Accepted | 2026-09-10 |
| R-002 | Same-user local malware unlocks the vault when OS-keychain unlock is enabled | Possible | Critical | Keychain unlock off by default; wizard warning; shorter auto-lock; code-signing binding on macOS | security owner | Accepted (user-chosen) | 2026-09-10 |
| R-003 | Java cannot guarantee zeroing of secret memory (GC copies, JIT) | Likely | Medium | `SecretBytes` with best-effort zeroing; heap dump disabled; documented | crypto reviewer | Mitigated | 2026-09-10 |
| R-004 | Browser extensions cannot act as WebAuthn authenticators; vault-backed passkeys infeasible | Likely | Medium | Q3 feasibility spike with go/no-go; storage-only fallback is a complete release | security owner | Open | 2026-09-10 |
| R-005 | Recipient copies a shared secret; revocation cannot recall it | Likely | Medium | UI warning; rotate-affected-secrets checklist from audit log | product | Accepted | 2026-09-10 |
| R-006 | No audited Java PAKE; hand-rolled protocol risk | Likely | High | Do not use a PAKE; TLS mutual auth + short authentication string (HKDF over exporter secret) using JDK-only crypto | crypto reviewer | Mitigated by design | 2026-09-10 |
| R-007 | Third-party Argon2id or TLS library vulnerability | Possible | High | Dependency verification, vuln scanning, pinned versions, Critical/High SLA | security owner | Open | 2026-09-10 |
| R-008 | Installers not byte-reproducible; supply-chain tampering harder to detect | Likely | Medium | JARs and runtime image reproducible; installer contents verified against those hashes; signatures | release | Mitigated | 2026-09-10 |
| R-009 | TUI library returns secrets as `String` | Likely | Low | Custom masked input widget; documented `@SecretBoundary`; immediate conversion | TUI | Mitigated | 2026-09-10 |
| R-010 | Team reviewers unavailable for Tier 1 two-review rule, blocking merges | Possible | Low | Named backups in CODEOWNERS | team lead | Open | 2026-09-10 |
| R-011 | A same-user process connects to the browser relay socket and poses as the native host (ADR 0014 §8, TM-20): it can claim any host-instance ID, so a new one per request escapes the per-host limits (one waiting prompt, 10 lookups a minute), and the prompt cannot name the program that asks | Possible | Medium | The global lookup limit (20 a minute) and the lookup audit hold; every connection needs its own approval, which shows the exact origin and the claimed host instance marked unverified; one approval releases one password; the extension ID must be allowlisted at the request, when the prompt is shown and when the answer arrives (SR-113) | security owner | Accepted | 2026-10-06 |
