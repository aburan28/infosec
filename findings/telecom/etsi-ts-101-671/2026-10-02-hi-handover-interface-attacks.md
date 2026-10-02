---
id: FND-etsi-ts-101-671-001
title: "Six protocol-conformant attacks on the LI handover interface (Checkmate, Ghost Warrant, Bounce-back, Rebind, Stash, Blackout)"
date: 2026-10-02
domain: telecom
target: "ETSI TS 101 671 — Lawful Interception handover interface (HI1/HI2/HI3)"
target_versions: ["V3.14.1 (2016-03)"]
classification: protocol-spec
severity: high
status: published
actors: [A1-on-path, A2-end-party, A3-insider, A4-agency]
novelty: novel
references:
  - "ETSI TS 102 232 series (successor HI for IP delivery)"
  - "ETSI TS 103 172 (securing the handover interface)"
  - "3GPP TS 33.108 (handover interface, TLS-based profiles)"
---

# Security analysis of the ETSI TS 101 671 V3.14.1 (2016-03) lawful-interception handover interface

**Target:** ETSI TS 101 671 V3.14.1 (2016-03) — "Lawful Interception (LI); Handover interface for the lawful interception of telecommunications traffic" (HI1/HI2/HI3, ROSE and FTP delivery, annexes A–L, ASN.1 modules per annex D).
**Type:** Protocol-level vulnerability research against a published public ETSI deliverable. All manipulations are protocol-conformant — no implementation bug is required; a fully conformant deployment is exploitable.
**Purpose:** Defensive / standards-hardening. ETSI's own deliverable invites error comments. Countermeasures included. No operational tooling.
**Scope note:** Clause references are to TS 101 671 V3.14.1 unless stated. ETSI's successors (TS 102 232 series, TS 103 172, 3GPP TS 33.108 TLS profiles) already concede the headline transport-security gap; the novel findings here go beyond it.

---

## 0. Root finding: the interface is cryptographically empty *by specification*

Clause 11 ("Security aspects") is an **informative overview** — clause 11.0 says so explicitly, and 11.2 defers all mechanism choices to implementation. No mandatory confidentiality, integrity, or authentication exists anywhere in the normative body; no MAC, signature, nonce, or key appears in any ASN.1 module of annex D. Every attack below is protocol-conformant manipulation.

### Root causes (clause-cited)

- **R1 — Static cleartext symmetric password, both directions, no challenge.** Clauses C.1.2.3.1 / D.3 (`Password-Name`): MF and LEMF exchange `origin`/`destination` passwords in the clear over TCP/X.25. No nonce ⇒ **byte-level replay of a recorded handshake is valid forever**.
- **R2 — FTP mode has no server authentication at all.** Clauses C.2.2/C.2.3: MF is FTP client, LEMF is server; the only "authentication" is the MF typing `user <leauser> <leapasswd>` *into* whatever answers at `<destaddr>`. A redirected destination captures credentials; a sniffered password captures the MF.
- **R3 — No per-record integrity on any port.** IRI (D.5), CS CC via UUS1/subaddress (A.4.3, D.8, annex E), PS CC via GLIC (F.3.1) or the TLV CC-header (F.3.2.5). Nothing is MACed or signed.
- **R4 — Correlation identifiers are exposed plaintext in four channels.** HI2 records (CID, `gPRSCorrelationNumber`), HI3 (GLIC correlation number, UUS1, subaddress), **FTP filenames** (C.2.2 method A embeds the LIID), HI1 notifications (D.4). Metadata in one channel *is* the authorization for content in another.
- **R5 — Mandated receiver leniency.** Annex G: unrecognized parameter/value ⇒ *ignore and proceed*. The LEMF is specified to be permissive by design.
- **R6 — Fixed LEMF addresses, finite DSS1 capacity, silent loss semantics.** A.4.1.0 (fixed LEMF address per LI activation), A.4.4.1 (≈3 retries / 10 s, then "CC information gets lost"), A.4.4.2 (alarms go to the *operator*, LEMF only optionally).
- **R7 — Target-controlled octet strings copied verbatim into LEMF-parsed records.** A.3.3 ("copied transparently"): UUS, keypad facility, facility components, SMS bodies (1..270 octets, D.5 `sMS-Contents`, plus `enhancedContent`), SMPP/UCP `alphanumeric` UTF8String identities, unbounded `sIPMessage` (annex H).

### Threat model

| ID | Actor | Position required |
|----|-------|-------------------|
| T1 | Transit / on-path vantage | Transit provider, BGP/DNS hijack of `<destaddr>`, shared segment, SS7 interconnect |
| T2 | The interception subject | Own signaling/SMS content only — no network vantage |
| T3 | Operator / LEA insider | MF configuration or channel access |
| T4 | Rival-agency-grade actor | T1 capabilities at scale |

---

## Attack 1 — "CHECKMATE": warrant-scoped, source-destructive, alarm-suppressed CC erasure (T1, FTP delivery)

The single strongest novel attack. It weaponizes three spec features *together*:

1. The **filename encodes the target and the warrant scope** (C.2.2; tables C.2.1 / F.3.4: ext `1`=IRI, `2/4/6`=CC MO/MT/MO&MT, `7`=IRI+CC).
2. The MF's **own success oracle is a directory listing** — `nlist <lastfile> <checkfile>` (C.2.3: "if it exists then the transfer is considered successful").
3. Success triggers **source deletion** (C.2.3: "upon successful file transfer the sent files are deleted from the DF").

### Procedure

1. Obtain on-path vantage over MF→LEMF FTP control+data (both plaintext).
2. Filter **by filename only**: `<LIID>_<seq>.1` (IRI) passes untouched; `<LIID>_<seq>.2|4|6|7` (CC-bearing) is diverted/truncated. The LEMF receives a perfectly self-consistent metadata world — every IRI-BEGIN/END proving the calls happened, timestamps, locations, party numbers.
3. Optionally archive the diverted CC yourself — this variant is a full **wiretap of the wiretappers**.
4. When the MF runs `nlist <lastfile> <checkfile>`, alter the listing so the checkfile contains `<lastfile>`. The MF's success oracle now returns true.
5. MF deletes its source files. No "file transfer failure" alarm is raised (C.2.3), so the retry/buffer/drop path of C.2.5 never triggers, and no fault report (A.4.4.2) is generated.
6. If the temp-rename scheme is used (C.2.3), simply never deliver the `ren` — the LEMF "starts processing data only after data transfer is complete", so orphaned temp files are never ingested.

### Impact

Post-hoc *irrecoverable*: a full forensic audit of both ends shows successful transfers. IRI proves the intercept was live and the calls occurred; the content is gone.

### Variants (all filename-layer, one edit each)

- **Evidence swap:** rewrite the LIID inside `put`/`ren` names ⇒ subject A's traffic is ingested under subject B's LIID. Defeats the strict-separation *shall* of 4.3 and the per-LEA LIID uniqueness of 6.1.
- **Time-shift:** method B names `ABXYyymmddhhmmss…` — edit the date/time digits to move evidence across warrant windows.
- **Type reclass:** rewrite ext `7→1` (strip CC classification) or `→8` ("national use", an undefined bucket).
- **Zero-credential LEMF impersonation:** hijack `<destaddr>` (DNS/route) and stand up a fake FTP server. In FTP mode *only the client authenticates*, so the MF hands you its credentials and every target's IRI+CC with no stolen secret. (ROSE mode needs the LEMF password — one passive capture of the C.1.2.3.1 exchange yields it; it is static and replayable per R1.)

---

## Attack 2 — "GHOST WARRANT": end-to-end synthetic evidence fabrication (T1/T4)

Builds a complete fake interception from harvested identifiers — the complement of Attack 1 (plant instead of erase).

1. **Harvest:** LIIDs and per-target `seq` counters from FTP filenames; CID (CIN ASCII digits + NID), `gPRSCorrelationNumber`, party identities from the plaintext HI2 stream (D.5).
2. **Forge IRI:** BER-encode IRI-BEGIN/CONTINUE/END/REPORT (D.5 `IRI-Parameters`) with fabricated `PartyInformation` (ISUP-format calling/called numbers), timestamps (`localTime` with `notProvided` winter/summer indication, 1 s resolution, D.5 `TimeStamp` — adds evidentiary ambiguity), chosen `nature-Of-The-intercepted-call`. Inject via the ROSE session after replaying the recorded password handshake (R1), or as correctly named FTP files; optionally aggregated via `IRISequence`.
3. **Forge CC, PS variant:** GLIC over **UDP** (F.3.1) needs only a valid 8-byte correlation number — which step 1 provided. The LEMF's sole check is that number; it reorders and stores "in line with the sequence numbers" and is *trained to tolerate* sequence gaps after SGSN handoff (F.3.1.2 NOTE) — injected, deleted, or reordered packets are all accepted as normal.
4. **Forge CC, CS variant:** place an SS7 call to the LEMF's fixed delivery access with network-provided CLIP of the MF — the LEMF's mandatory check is *only* CLIP screening (A.4.5.1); CUG is optional (A.4.5.2), COLP may be deactivated and accepts two numbers as correct anyway, ISO 9798 authentication is optional (A.4.5.3). Carry the matching LIID/CID/direction in UUS1 (table A.4.1 rows 2–5) or annex-E subaddresses; the 64 kbit/s "unrestricted" bearer delivers fabricated audio into the target's stereo channels. Forge the connected number to pass the optional COLP check.
5. **Forge HI1 ops traffic:** `liActivated`/`liModified`/`liDeactivated`/`alarms-indicator` — free-format alarm text up to 256 octets (D.4) — ride the same unauthenticated channel (5.1.0 explicitly permits HI1 information via the HI2 mechanism).

### Impact

Fabricated call records + fabricated content under a *real* warrant ID ⇒ framing or discrediting. The symmetric damage is worse: because forgery is undetectable *by specification*, any defense can plausibly assert fabrication — **the chain-of-custody value of every legitimate record collapses** (clause 11.1 itself names integrity-as-evidence as a requirement it then fails to specify).

---

## Attack 3 — "BOUNCE-BACK": the interception subject attacks the monitor (T2 — no network vantage needed)

The target's own signaling *is* the LEMF's parser input. Per A.3.3, target-controlled IEs are copied verbatim: UUS1 (up to 131 octets in their call setup, A.4.3), keypad facility, DSS1 facility components, SMS bodies (`content` 1..270 + `enhancedContent` with arbitrary octets and an attacker-chosen `character-encoding`, D.5), SMPP/UCP `alphanumeric` UTF8String identities, IMS `sIPMessage` (unbounded, annex H). Annex G then **mandates** continue-on-unknown parsing.

- **Parser attack surface:** BER nested-length abuse inside SETs of up to 256 × 256-octet octet strings (D.5 `Supplementary-Services`, `ISUP-parameters`), recursive TLV nesting (F.3.2.5 CC-header: nested MainElement/Header/Payload IEs), extension markers (`...`), and the undefined `PrivateExtension` (1..N) and `National-Parameters` containers. Crafted SMS/UUS bodies can crash or corrupt the LEMF's decoder — the most sensitive LEA system — *from the target's own phone line*.
- **Fingerprinting oracle:** the LEMF's RO-Error choice (`unknown-parameter` vs `unknown-parameter-value` vs record-reject, D.5 `OperationErrors`) reveals its implementation vintage, enabling targeted exploits while annex G suppresses alarms ("no special error or alarm procedures… because the reason may be the introduction of a new version").
- **Self-amplification DoS on the LI infrastructure:** interception is an amplifier — an n-party CONF spawns n+1 CC links (A.6.11.1); hold/retrieve toggling and CFU churn generate IRI/CC-link storms against the LEMF's **finite** DSS1 capacity (A.4.1.0). A scripted target saturates the shared LEMF access ⇒ CC links for *other* agencies' targets fail with "lack of system resources" (table A.4.2) and are silently lost (A.4.4.1), while alarms go to the operator, not the victims' LEAs. One target neutralizes other targets' collection using only the mechanics of their own interception.

---

## Attack 4 — "REBIND": audio-to-transaction misattribution (one-record edit)

Option B CC-link reuse requires an IRI-CONTINUE carrying "the correct CID and CCLID" (A.5.4.2) — but A.1.1 says the CCLID "may use the same format as CIN; it need not be transmitted explicitly… the CIN may implicitly represent the CCLID." **Implicit identifier binding = engineered ambiguity.** Drop or forge the rebind CONTINUE so the LEMF attaches call 2's audio to call 1's transaction; with diversion chains (one call interceptable up to 7× from different LEAs, A.6.16.1) you can permute which recording belongs to which warrant. Minimal-footprint, court-grade attribution poisoning — no bulk traffic manipulation needed.

---

## Attack 5 — "STASH": the LI pipeline as an insider covert channel (T3)

Undefined containers designed to be ignored: `National-Parameters` [16] (up to 40 × 256 octets, "content defined by national law"), national ASN.1 extension markers (D.4/D.5), `Other-Services` ("reference manufacturer manuals"), CC-header `PrivateExtension` (1..N, "vendor or LEA or operator specific", F.3.2.5), free-format `alarm-information` (D.4), `target-Information`. An insider routes arbitrary bulk data (subscriber DB dumps, C2 beacons) to any reachable endpoint — including a colluding "LEMF" — inside *valid* warrant traffic, which every legitimate receiver is specified to ignore-unrecognized (annex G). Nothing in the spec permits content auditing of these fields. Converse use: a compromised MF exfiltrates through the one pipeline operators are culturally reluctant to inspect.

---

## Attack 6 — "BLACKOUT": hidden-downtime shims and timed starvation

Answer `data-Link-Test` keepalives (C.1.2.3.1) while withholding IRI ⇒ the link looks alive, evidence quietly stops, then C.2.5's "very long period" discard path erases the backlog. CS variant: the plaintext IRI-BEGIN reveals a chosen target's call start; in that window, induce "no answer from LEA / LEA busy" (table A.4.2) on the delivery call — three retries in ~10 s, then CC lost (A.4.4.1), alarm routed to the operator while the LEA's case file shows a live warrant. Selective, timed, deniable — the ISDN-mode version of Attack 1.

---

## Novelty assessment

**Not novel:** "no transport security / plaintext passwords" — ETSI's own successors concede this (TS 102 232 with TLS, TS 103 172 securing HI2/HI3; the scope's NOTE 3 admits the document is going historical). SS7 CLIP-spoofing and BER-parser abuse are established literatures that the *feasibility* of Attacks 2/3 leans on.

**Novel contributions of this report:**

1. The filename-scoped `nlist`/checkfile oracle combined with source-deletion semantics — a protocol-conformant, alarm-suppressing, source-destructive erasure (Attack 1).
2. The HI2-metadata → HI3-content authorization chain: a correlation number read from IRI is the *sole credential* for UDP CC injection (Attack 2, step 3).
3. The target→LEMF offensive channel and interception self-amplification DoS (Attack 3).
4. The implicit-CCLID rebinding misattribution attack (Attack 4).
5. The LI pipeline as an uninspectable insider covert channel (Attack 5).

**Caveats:** T1/T3/T4 attacks assume the attacker already holds a network or insider position; Attack 3 (T2) needs only an intercepted phone line. That asymmetry — the monitored party being able to reach the monitoring facility — is the finding to lead with.

---

## Countermeasures

1. **Retire FTP profiles;** require TLS 1.3 with *mutual certificate* authentication (client and server), or IPsec with certificate pinning. Password-only schemes are useless (R1/R2).
2. **Per-record or per-batch signatures** (or channel MACs) covering LIID/CID/sequence/timestamp/payload — this converts Ghost-Warrant/Rebind from "undetectable" to "detectable" and restores evidentiary value.
3. **Remove LIIDs and correlation data from filenames;** use opaque batch handles.
4. **Replace the `nlist`/checkfile oracle** with signed hash manifests plus explicit application-level ACK from the LEMF; never delete-at-source on filesystem inference.
5. **Strict decoding for security-relevant containers:** DER-only, depth/size caps, reject (not ignore) on structural anomalies; keep annex-G leniency only for genuinely extensible, type-safe fields.
6. **CC-link failure and sequence-gap alarms must be authenticated and must reach the LEA** (not only the operator); gap detection must be handoff-aware rather than gap-tolerant.
7. **Process:** file an ETSI comment via the deliverable's own invitation (portal.etsi.org); procurement should refuse TS 101 671 profiles in new deployments per the scope's own migration recommendation (TS 102 232 series).

---

## References

- ETSI TS 101 671 V3.14.1 (2016-03), all clause citations above.
- ETSI TS 102 232 series (HI for IP delivery) and ETSI TS 103 172 (securing the handover interface) — successor mitigation context.
- 3GPP TS 33.108 (handover interface, TLS-based profiles).
- Public SS7 interconnect spoofing literature and ASN.1/BER parser abuse literature — feasibility context for Attacks 2/3.
