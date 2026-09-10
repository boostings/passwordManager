# Design Review Checklist

Run before implementing any Tier 1 module or changing a trust boundary.
Reviewer records Y/N/NA per item and links the ADR.

| # | Item |
| --- | --- |
| 1 | Is there an ADR, and is it Accepted (not Proposed)? |
| 2 | Which trust boundaries (TB-n) does this touch? Are they in `trust-boundaries.md`? |
| 3 | Which threats (TM-nn) does it mitigate or introduce? Threat model updated? |
| 4 | Which security requirements (SR-nnn) apply? Each has a named test? |
| 5 | Least privilege: what is the minimum data and capability this component needs? |
| 6 | Fail closed: enumerate every error path; does each deny/lock/refuse? |
| 7 | Complete mediation: does any secret leave the vault without the approval broker? |
| 8 | Secrets: every Secret-class field is `SecretBytes`; boundaries annotated `@SecretBoundary`? |
| 9 | Inputs: every external input has a size bound, schema, and fuzz harness planned? |
| 10 | Crypto: JDK-only (plus the one audited Argon2id dependency)? No new constructions? |
| 11 | Concurrency: what is shared, what lock protects it, is it private final, is blocking I/O outside the lock? |
| 12 | Lifecycle: resources closed deterministically; no finalizers; shutdown path defined? |
| 13 | Logging: what is logged; is it all Metadata/Sensitive-by-ID only? |
| 14 | Platform: which OS-specific behavior differs; is it in the platform matrix? |
| 15 | Which `RULES.md` rules are most relevant; are they Enforced or Review-only for this code? |
| 16 | Rollback: can this be disabled or reverted without data loss? |
