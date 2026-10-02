# ETSI TS 101 671 — Lawful Interception handover interface (HI1/HI2/HI3)

Generic handover interface delivering the intercept product (Intercept Related Information on HI2, Content of Communication on HI3) from operator mediation functions to law-enforcement monitoring facilities. ROSE and FTP delivery, circuit- and packet-switched annexes, ASN.1/BER modules in annex D.

**Versions analyzed:** V3.14.1 (2016-03).

**Status context:** legacy — ETSI recommends migration to the TS 102 232 series; TS 103 172 specifies transport security for the successor interfaces.

**Attack surface (root causes):** R1 static cleartext passwords; R2 no FTP server authentication; R3 no per-record integrity; R4 correlation identifiers exposed in filenames/records/HI3 signalling; R5 mandated receiver leniency (annex G); R6 fixed LEMF addresses + silent loss semantics; R7 target-controlled octet strings copied verbatim into LEMF-parsed records; R8 non-canonical identifiers; R9 filename-keyed ingest with replace semantics; R10 unprotected direction field; R11 frozen/optional version signalling; R12 immediacy vs. batching contradiction; R13 fragmented gap-tolerant sequences; R14 scope filters parse attacker PDUs; R15 best-effort coverage.

## Findings

| ID | Date | Title | Severity | Status |
|----|------|-------|----------|--------|
| [FND-etsi-ts-101-671-001](2026-10-02-hi-handover-interface-attacks.md) | 2026-10-02 | Six protocol-conformant attacks on the LI handover interface (Checkmate, Ghost Warrant, Bounce-back, Rebind, Stash, Blackout) | high | published |
| [FND-etsi-ts-101-671-002](2026-10-02-second-wave-flaws.md) | 2026-10-02 | Second-wave findings: Echo-Flip direction inversion, Rollback filename-keyed replacement, Panopticon interception-of-interception intelligence, Alibi-Gap, Fossilize downgrade, plus implementation-seeded flaw classes (7–18) | high | published |
