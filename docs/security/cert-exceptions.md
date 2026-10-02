# CERT exceptions ledger

Every scanner suppression (SpotBugs exclude, `@SuppressWarnings("PMD.…")`, Semgrep `nosemgrep`)
must have a row here. Each one is as narrow as the tool allows (one class, one method, one rule)
and needs security-owner sign-off before the milestone closes.

| ID | Rule | Location | Justification | Status |
| --- | --- | --- | --- | --- |
| CE-001 | FindSecBugs `CIPHER_INTEGRITY` (CWE-353) | `pm.crypto.KeyWrap#initCipher` (`tools/cert-rules/spotbugs-exclude.xml`) | False positive. The transformation is `AES/KWP/NoPadding` (RFC 5649 AES Key Wrap with Padding, ADR 0004). KWP is a deterministic authenticated-encryption mode: unwrap verifies the alternative initial value and the padding length, and any wrong KEK or modified byte fails with a `GeneralSecurityException`, mapped to `AUTH_FAILED`. The detector only treats GCM as integrity-protecting. Covered by `KeyWrapTest` (RFC 5649 vectors, wrong-KEK and bit-flip properties). | Pending security-owner sign-off |
