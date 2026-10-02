# infosec — security findings repository

Vulnerability and protocol-security research findings across many protocols, standards, systems, and applications. Each finding is a self-contained, clause/version-cited write-up with a threat model, attack procedure, impact, novelty boundary, and countermeasures.

## Repository layout

```text
infosec/
├── README.md            # this file — orientation and global index
├── taxonomy.md          # domains, actor model, severity, status, ID scheme
├── templates/
│   └── finding.md       # required skeleton for every finding
├── findings/            # all findings, organized domain → target → dated file
│   ├── README.md        # global findings index
│   ├── telecom/         # mobile core, IMS/SIP, PSTN/ISDN, LI, TETRA, SMS
│   ├── network/         # routing, DNS/DHCP/NTP, L3/L4, VPN/tunneling
│   ├── wireless/        # 802.11, BLE, 802.15.4, NFC, cellular access layer
│   ├── web/             # HTTP semantics, browsers, frameworks, identity federation
│   ├── crypto/          # applied protocol crypto: downgrade, misuse, oracles, ASN.1
│   ├── systems/         # kernels, hypervisors, firmware/boot, containers, sandboxes
│   └── applications/    # named vendor products, SaaS, desktop/mobile apps
├── poc/                 # proof-of-concept code, mirroring findings/ paths
└── notes/               # research scratchpads pending promotion to findings/
```

## Conventions

- **Finding paths:** `findings/<domain>/<target-slug>/YYYY-MM-DD-<short-slug>.md`
  - `target-slug`: lowercase, hyphenated, version-less — versions live in frontmatter
- **Finding IDs:** `FND-<target-slug>-NNN`, assigned once in the target's `README.md`, never reused
- **Frontmatter:** required on every finding, per `templates/finding.md`
- **PoC code:** `poc/<domain>/<target-slug>/<finding-id>/`, mirroring the finding's path
- **Citations:** findings against specs cite clause/section; findings against code cite `file:line` and commit

## Lifecycle

`notes/` (free-form scratch) → `findings/<domain>/<target>/` (frontmatter + ID, indexed in the target README, domain README, and global index) → optionally `poc/` (code). Status moves `draft → review → published`; published findings are superseded by new findings, not silently edited.

## Global findings index

| ID | Date | Domain | Target | Finding | Severity | Status |
|----|------|--------|--------|---------|----------|--------|
| [FND-etsi-ts-101-671-001](findings/telecom/etsi-ts-101-671/2026-10-02-hi-handover-interface-attacks.md) | 2026-10-02 | telecom | ETSI TS 101 671 V3.14.1 | Six protocol-conformant attacks on the LI handover interface (Checkmate, Ghost Warrant, Bounce-back, Rebind, Stash, Blackout) | high | published |

## Ground rules

Defensive research only: public specs and products, reproducible reasoning, countermeasures included. No live-target data, no credentials, no operational tooling.
