# ADR 0001: Record architecture decisions

- Status: Accepted
- Date: 2026-09-10
- Deciders: project team

## Context

`plan.md` requires that every decision touching cryptography, storage format,
protocols, approvals, or trust boundaries is recorded before code is written,
and that security decisions are auditable later.

## Decision

Use Architecture Decision Records in `docs/adr/`, numbered sequentially,
one decision per file, using this template:

```markdown
# ADR NNNN: Title
- Status: Proposed | Accepted | Superseded by NNNN | Deprecated
- Date: YYYY-MM-DD
- Deciders:
## Context
## Decision
## Alternatives considered
## Consequences
## Security considerations
## CERT rules referenced
```

An ADR is "Proposed" until the security owner and one other reviewer accept it.
Code that depends on a Proposed ADR may be written on a branch but not merged.
Superseding an ADR requires a new ADR; the old one is never edited except to
change its status line.

## Alternatives considered

- Decisions in PR descriptions only: not discoverable, lost on squash.
- A single design document: becomes stale and has no history per decision.

## Consequences

Slightly more ceremony per decision; in exchange, every security-relevant
choice has a dated, reviewed rationale that the threat model and external
reviewers can reference.

## Security considerations

ADRs are the audit trail for the security review at M7.

## CERT rules referenced

None directly; the ADR process is how rule applicability decisions are recorded.
