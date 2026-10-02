# ETSI TS 101 671 — Lawful Interception handover interface (HI1/HI2/HI3)

Generic handover interface delivering the intercept product (Intercept Related Information on HI2, Content of Communication on HI3) from operator mediation functions to law-enforcement monitoring facilities. ROSE and FTP delivery, circuit- and packet-switched annexes, ASN.1/BER modules in annex D.

**Versions analyzed:** V3.14.1 (2016-03).

**Status context:** legacy — ETSI recommends migration to the TS 102 232 series; TS 103 172 specifies transport security for the successor interfaces.

**Attack surface (root causes):** R1 static cleartext passwords; R2 no FTP server authentication; R3 no per-record integrity; R4 correlation identifiers exposed in filenames/records/HI3 signalling; R5 mandated receiver leniency (annex G); R6 fixed LEMF addresses + silent loss semantics; R7 target-controlled octet strings copied verbatim into LEMF-parsed records.

## Findings

| ID | Date | Title | Severity | Status |
|----|------|-------|----------|--------|
| [FND-etsi-ts-101-671-001](2026-10-02-hi-handover-interface-attacks.md) | 2026-10-02 | Six protocol-conformant attacks on the LI handover interface (Checkmate, Ghost Warrant, Bounce-back, Rebind, Stash, Blackout) | high | published |
