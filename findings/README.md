# Findings index

Global index of all findings. Domain indexes live in each domain README; per-target indexes in each target README.

| ID | Date | Domain | Target | Finding | Severity | Status |
|----|------|--------|--------|---------|----------|--------|
| [FND-etsi-ts-101-671-001](telecom/etsi-ts-101-671/2026-10-02-hi-handover-interface-attacks.md) | 2026-10-02 | telecom | ETSI TS 101 671 V3.14.1 | Six protocol-conformant attacks on the LI handover interface (Checkmate, Ghost Warrant, Bounce-back, Rebind, Stash, Blackout) | high | published |
| [FND-etsi-ts-101-671-002](telecom/etsi-ts-101-671/2026-10-02-second-wave-flaws.md) | 2026-10-02 | telecom | ETSI TS 101 671 V3.14.1 | Second-wave findings: direction inversion, ingest-key rollback, interception-of-interception intelligence, coverage gaps, implementation-seeded flaw classes (findings 7–18) | high | published |

## Adding a finding

1. Copy `templates/finding.md` into `findings/<domain>/<target-slug>/` (create the target dir if new) as `YYYY-MM-DD-<short-slug>.md`.
2. Assign the next ID in the target's `README.md` and fill in the frontmatter.
3. Link the finding from the target README, the domain README, and this index.
