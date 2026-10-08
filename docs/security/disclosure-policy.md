# Coordinated disclosure policy

How the project handles a security report, from receipt to public advisory. How to report, the
severity scale and the fix targets are in [SECURITY.md](../../SECURITY.md); this document does not
restate them.

## Roles

- **Security owner** (`@boostings`, `CODEOWNERS`): receives reports, assigns severity, decides the
  disclosure date, and signs the advisory.
- **Module owner**: the second `CODEOWNERS` entry for the affected module. They write or review
  the fix.
- **Reporter**: the person who found the problem. They are kept informed at every step below.

## Steps

1. **Receipt.** The report arrives through GitHub private vulnerability reporting, or through a
   private channel arranged after a "Security contact request" issue. The security owner
   acknowledges it within 48 hours and opens a draft GitHub Security Advisory. All discussion
   stays in that advisory, never in a public issue, PR, commit message or CI log.
2. **Triage** (within 7 days). The security owner reproduces the problem on the latest release and
   on `main`. They assign a severity using SECURITY.md's scale and record the affected versions.
   If the report describes a limitation that is already accepted (the out-of-scope list in
   SECURITY.md), the reporter is told which entry covers it and why. The report is closed only if
   it adds nothing to that entry.
3. **Fix.** The fix is made in the advisory's temporary private fork, so the commits stay private
   until release. It needs:
   - a regression test that fails before the fix;
   - the full gate (`./gradlew check certReport gitleaksScan`) green;
   - a new or updated row in `docs/security/requirements.md` and `traceability.md`;
   - the module owner's review.

   A Critical or High fix also needs an adversarial re-check of the fix itself.
4. **Release.** A patch release `1.0.x` is built with `./gradlew release` and published with its
   `SHA256SUMS`, and with its signature once signing is set up (`docs/release/packaging.md`). pm
   has no auto-update, so the advisory and the release notes say exactly what users must do: for
   example, install the patch, run `pm backup create`, or change secrets that may have been
   exposed.
5. **Disclosure.** The advisory is published, with a CVE requested through GitHub where the issue
   qualifies, on the day the fixed release is available. The risk register gets a row (or an
   updated row) that cites the advisory. The reporter is credited by name, or not at all if they
   prefer.

## Timing

- The default embargo is **90 days** from acknowledgement, or until the fix ships, whichever comes
  first.
- If the problem is being exploited, or is already public, the advisory and the advice to users
  are published at once, before a fix if necessary.
- If a fix cannot meet the SECURITY.md target, the security owner tells the reporter why and gives
  a new date. The 90 days are extended only with the reporter's agreement.
- A reporter who intends to publish first is asked to give 7 days' notice so the advisory can go
  out with their write-up.

## What the project never does

- Ask a reporter for vault files, passphrases or real credentials, or accept them.
- Fix a security problem silently. Every fix of Medium or higher severity ships with an advisory,
  and every Low fix with a release-notes line.
- Pursue good-faith research that follows SECURITY.md's safe harbor.
