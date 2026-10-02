---
id: FND-etsi-ts-101-671-002
title: "Second-wave findings: direction inversion, ingest-key rollback, interception-of-interception intelligence, coverage gaps, and implementation-seeded flaw classes"
date: 2026-10-02
domain: telecom
target: "ETSI TS 101 671 — Lawful Interception handover interface (HI1/HI2/HI3)"
target_versions: ["V3.14.1 (2016-03)"]
classification: protocol-spec
severity: high
status: published
actors: [A1-on-path, A2-end-party, A3-insider]
novelty: novel
references:
  - "FND-etsi-ts-101-671-001 — first-wave attacks (Checkmate, Ghost Warrant, Bounce-back, Rebind, Stash, Blackout)"
  - "ETSI TS 102 232 series / ETSI TS 103 172 (successor mitigation context)"
superseded_by:
---

# Second-wave findings on ETSI TS 101 671 V3.14.1

## Summary

Companion to FND-etsi-ts-101-671-001. Twelve further protocol-conformant flaws, distinct from the first-wave six attacks. The strongest: **Echo-Flip** — a single unprotected direction field decides whether archived audio is attributed to what the target *said* or what the target *heard*; **Rollback** — LEMF ingest is keyed on attacker-reachable filenames and FTP store/rename semantics replace by name; **Panopticon** — duplicate transactions, plaintext directory listings, and en-clair correlation data on transit ISUP leak *who is under interception and by whom*, which clause 11.1 explicitly names as a harm to prevent. The remainder are implementation-seeded flaw classes and no-attacker design defects (batch/discard contradiction, module version skew inside the spec itself, DST-fold timestamp ambiguity, a mandated evidentiary fiction in A.5.5).

## Target & versions

ETSI TS 101 671 V3.14.1 (2016-03), all annexes. Clause citations inline. Findings are numbered 7–18 to continue FND-001's 1–6.

## Root causes (R8–R15, extending R1–R7 of FND-001)

- **R8 — Correlation identity is unauthenticated *and* non-canonical.** NID "should be internationally unique" (6.2.1 — soft verb, for the cornerstone identifier); `operator-Identifier` is 1..5 ASCII octets with no registry or canonical form (D.5); `Network-Element-Identifier` textual `iP-Format`/`dNS-Format` OCTET STRINGs (1..25) admit multiple string forms of the same node (D.5).
- **R9 — Ingest is keyed on attacker-influencable filenames with replace-by-name semantics.** Method A `<LIID>_<seq>.<ext>` / method B `ABXYyymmddhhmmsseeeet` are the LEMF's sort/correlation keys (C.2.2, F.3.2.2); FTP `STOR` and the temp→ordinary `ren` (C.2.3, F.3.2.2) replace by name; method B's `eeee` clash-avoidance is "chosen at the discretion of the Operator... within the MF" — best-effort, single-node, no collision protocol.
- **R10 — Direction of a CC stream is a single unprotected field.** UUS1 `direction-Indication` ENUMERATED (D.8: mono(0)/from-target(1)/from-other-party(2)/unknown(3)); annex E encodes it as one BCD digit in octet 17 of the Calling Party Subaddress (tables E.3.5/E.3.8, E.4.1).
- **R11 — Version signaling is frozen, optional, and legacy-defaulting.** `iRIversion` is "recommended to always send... lastVersion(8)" (frozen by design, D.5); `domainID` is OPTIONAL; absent version "means version 1 is handled"; `version11(11)` of HI2Operations is documented as containing a syntax error (D.5 header comment).
- **R12 — Normative immediacy is contradicted by the delivery design.** 5.2: IRI "shall be sent immediately and shall not be held in the MF/DF" — but FTP delivery gathers "records... to bigger packages" with send-timeout/volume triggers (C.2.2), and "if the [T2] timer is set to 0 the only trigger to send the file is the file size parameter" (table C.2.2), followed by discard-on-buffer-exhaustion (C.2.5).
- **R13 — Sequence integrity is fragmented and gap-tolerant.** HI2 records carry no sequence field; the GLIC header sequence is 16-bit (table F.3.1, octets 5–6) while the CC-header `CCSeqNumber` TLV is 32-bit (F.3.2.5); non-contiguity after SGSN handoff is *tolerated by design* (F.3.1.2 NOTE).
- **R14 — Warrant-scope filtering requires parsing attacker-crafted PDUs.** IRI-only authorizations must strip content while keeping party data that lives *inside* the content structure: SMS receiving MSISDN is "included as header information in the SMS message body" and must still reach IRI (A.8.2 + NOTE); SIP filtering deletes known content but "unknown headers are not deleted" and SDP is retained for correlation (H.1.4 NOTE 2, H.1.5).
- **R15 — Coverage is best-effort by design.** IMEI-based activation "could lead to a delay in start of interception" and cannot see non-call events (A.8.1); MSN coverage is per-number manual with administrative catch-up (A.6.15); name display, abbreviated-address, and FDC user input are excluded from IRI by design (A.6.32, A.6.23, A.6.24); non-call REPORT records may omit the CID entirely (A.3.2.1).

## Threat model

A1 (on-path/transit, incl. SS7 interconnect) — findings 7–11, 14; A2 (interception subject, own signaling/SMS/SIP only) — findings 10, 15; A3 (operator/LEA insider) — findings 12, 13, 18; findings 12, 16, 17 require no attacker at all.

## Findings

### 7. Echo-Flip — evidentiary direction inversion (one nibble)

The stereo attribution of all CS content rests on one field: `direction-Indication` in the UUS1 content (D.8) or, in annex E deployments, a single BCD digit plus field separator in octet 17 of the Calling Party Subaddress (E.3.5/E.3.8, coding per E.4.1). An A1 attacker with SS7 write access flips 1↔2 on the delivery call setup:

- **Inversion:** audio the target *received* (e.g., statements by the other party, an undercover officer's suggestions) is archived as the target's *transmitted* channel — speech attributed to the wrong party, at trial quality.
- **Sum-merge:** set value 0 (mono, "historic" but accepted, E.4.1 NOTE) — channels merge into a sum signal; who-said-what becomes forensically unresolvable for the whole call.
- **Poisoning:** set value 3 ("direction unknown") — every affected record is self-flagged ambiguous, tainting admissibility.

Cost: one nibble on the setup message of the MF→LEMF ISDN call (or the equivalent ENUMERATED in an injected UUS1). Distinct from FND-001's Rebind (call-to-call binding): Echo-Flip attacks *within-call* attribution. Severity: high.

### 8. Rollback — filename-keyed evidence replacement

LEMF ingest is keyed on the filename: method A sorts "per observed target" by `<LIID>_<seq>`; method B batches by `ABXYyymmddhhmmss...`; the temp-rename flow (put temp name, then `ren` to the ordinary name, C.2.3/F.3.2.2) *replaces by name* — no append/merge/anti-overwrite semantics are specified anywhere. An A1 attacker (or a checkfile-lie posture per FND-001 Attack 1) re-`put`s a chosen filename with older, edited, or partial content after the genuine file landed: the LEMF's record for `<LIID>_0042.1` silently becomes the attacker's version, with no alarm — the transfer "succeeded" by the spec's own oracle. Method B adds a benign-collision variant: `eeee` is operator-discretionary clash avoidance *within one MF*, nothing coordinates across MF nodes or batches; a colliding name is a legitimate-looking overwrite. Impact: history replacement rather than FND-001's history erasure — the audit trail shows a consistent, complete, wrong record set. Severity: high.

### 9. Panopticon — interception-of-interception intelligence

Three independent leaks of *who is under surveillance and by whom* — the exact harm clause 11.1 names ("Irregularities can be a sign of... detection of interception"):

1. **Duplicate-transaction clustering (A1).** When both parties are targets, each is "dealt with separately" (4.3; B.5.2.1 NOTE: both CC and IRI delivered per party as separate activities); the same underlying call may be intercepted up to 7 times from the same or different LEAs (A.6.16.1), and 6.2.2 NOTE 2 permits the *same CIN* across the identities in one communication. A transit observer of unencrypted HI2 sees two-to-seven transactions with identical party numbers, timestamps, and durations under different LIIDs, destined for different LEMF addresses (the per-LEA HI2/HI3 destinations of 7.1 items 5–6) — yielding the target cluster *and* which agencies run parallel warrants on it. IMS doubles the signal: "If P-CSCF and S-CSCF are in the same network the events are sent twice" (H.0 NOTE).
2. **`nlist` inventory leak (A1).** The MF's own success-check command lists the LEMF directory across the plaintext control channel (C.2.3) — an on-path observer reads the LEMF's *entire LIID inventory* (all targets, all agencies sharing that LEMF) with zero credentials.
3. **Transit ISUP exposure (A1/state).** CC delivery calls are standard ISUP with "ISDN user part required all the way" (A.4.3 row 9), carrying the LIID/CID en clair in UUS1 (rows 2–4) or annex-E subaddresses through arbitrary international SS7 carriers — every transit provider sees foreign warrants' identifiers and the fixed LEMF reception numbers (A.4.1.0).

Severity: medium-high; no integrity mechanism anywhere in the spec can detect the metadata leak.

### 10. Alibi-Gap — coverage-timeline manipulation and designed coverage holes

Non-call REPORT records (DMO, MobileOn/Off, LocationUpdate, GroupIndication, SCI, ServingSystem) may omit the CommunicationIdentifier entirely (A.3.2.1) and ride the same integrity-free channel. An A1/A3 actor deletes or forges them to move the apparent coverage window: fabricate DMO reports (A.9.2.1.4.7 defines DMO as radio comms "which cannot be observed") to create documented unobservable windows; forge MobileOff/LocationUpdate to shift the location timeline. Pairs with R15's designed holes — IMEI start-of-call delay (A.8.1), per-MSN manual coverage (A.6.15), and excluded-by-design signalling: name display strings are *never* included in IRI (A.6.32), abbreviated-address and FDC user input are not (A.6.23/A.6.24) — so a target can move meaningful metadata through CNAM display names and speed-dial prefixes that the interface is specified not to carry. Severity: medium.

### 11. Fossilize — evidence-format downgrade and the spec's own version skew

Two related defects. (a) *Downgrade:* `iRIversion` is frozen at `lastVersion(8)` by recommendation, `domainID` is OPTIONAL, and an absent version "means version 1 is handled" (all D.5) — a forger emits records without `domainID`/version and the LEMF applies version-1 semantics, including the sanctioned malformed encoding ("the value 'zero' may be included in the first octet string of the SET", D.5 ISUP-parameters comment), or sends `version11(11)`-era syntax that the spec itself calls erroneous. Cross-version records parse differently for mandatory/optional fields — confusion usable to launder forged parameters past strict v18 parsers. (b) *Spec-internal skew:* the D.5 module header declares `HI2Operations ... version18(18)` while annex J says "Current version is 17"; D.4 and D.8 import HI2Operations `version10(10)`, D.6 imports `version13(13)`, and TETRA-HI2 (D.10.3) imports `UmtsHI2Operations r10 version-1` while the main module imports `r11 version-0`. A conformant system assembles co-resident modules of different vintages with drifting parameter tables — the confusion is shipped in the specification. Severity: medium.

### 12. Quiet-Target Black Hole — self-inflicted IRI loss (no attacker required)

5.2 (normative) forbids holding records for aggregation; the FTP delivery mechanism is built on holding: "Several records may be gathered to bigger packages prior to sending" under volume/timeout triggers (C.2.2), and table C.2.2's T2 allows "the only trigger to send the file is the file size parameter." For a low-activity target under volume-triggered transfer, records sit in the DF/MF until buffer exhaustion triggers the C.2.5 discard path ("the local buffering at the MF may have to be terminated... intercepted data... would be discarded"). Evidence for precisely the least-active (and often most-sensitive) subjects evaporates by configuration, with only operator-side alarms. The contradiction between 5.2 and C.2.2 is unreconciled in the text. Severity: medium.

### 13. Namespace anarchy — non-canonical identifiers and unmanaged BER tags

The correlation scheme's uniqueness is advisory ("should be internationally unique", 6.2.1). `operator-Identifier` is 1..5 ASCII octets — no registry, no country prefix, cross-operator collisions trivially realizable; NEID `iP-Format`/`dNS-Format` are *textual* strings (1..25), so `192.168.1.1`, `192.168.001.001`, and DNS aliases of the same node are distinct NIDs — correlation bypass or duplication at the LEMF by spelling. D.1 opens the PRIVATE tag class to "users of the protocol" who "risk conflict with other users' extensions," and the tag-240–255 avoidance for national parameters is only "recommended" while tag 255 is already the `national-HI2-ASN1parameters` slot (D.5) — colliding extensions are parsed by the wrong handler or ignored per annex G. Severity: medium (implementation-seeded, spec-guaranteed).

### 14. Sequence fragmentation and wrap

GLIC's sequence number is 16-bit (table F.3.1, octets 5–6) — at a modest 50 packets/s per PDP context it wraps every ~22 minutes, while the FTP CC-header `CCSeqNumber` is a 32-bit TLV (F.3.2.5) and HI2 records have no sequence at all; the LEMF is *trained to tolerate* gaps (F.3.1.2 NOTE) and reorders "in line with the sequence numbers" (F.3.1.4). Deletion/injection timed to a 16-bit wrap (or to a format transition GLIC↔TLV↔file) is indistinguishable from legitimate reordering. Correlation numbers compound this: 8 octets = 32-bit Charging-ID + GGSN-ID (F.3.2) — 32 bits per GGSN invites birthday collisions across long-lived nodes, merging two targets' content at the LEMF. Severity: medium.

### 15. Scope-filter paradox — IRI-only warrants must parse attacker-crafted content

To honor IRI-only authorizations the MF must strip content while preserving party data embedded *in* the content: SMS receiving MSISDN lives "as header information in the SMS message body" and must still be delivered (A.8.2 and NOTE — the spec concedes jurisdictions differ on SMS bodies); SIP filtering deletes known content types but "unknown headers are not deleted," and SDP is retained for correlation (H.1.4 NOTE 2, H.1.5). Consequences: (a) *scope leak by design* — unknown/custom SIP headers and free-text SDP attributes (`a=` lines) flow into "IRI" records, delivering content an IRI-only warrant excludes; (b) *filter integrity depends on parsing target-crafted TPDUs/headers* — an A2 target choosing exotic Content-Types or malformed UDH boundaries mis-splits the filter (content leak or correlation loss) and simultaneously feeds the FND-001 parser attack surface. Severity: medium-high (compliance failure class).

### 16. Provisioning fiction — records mandated to misattribute

A.5.5: at an exchange where target subscriber data is modified "via a remote control procedure, an IRI-REPORT record shall be generated **as if the control procedure had taken place locally**." Operator OSS/provisioning actions on the target's profile are, by mandate, recorded as the target's own Subscriber Controlled Input. A provisioning script toggling CFU presents in evidence as "the target activated call forwarding at 14:02." Combined with the absence of any provenance field, this is a designed evidentiary falsehood, exploitable by an A3 insider to launder system actions as target actions. Severity: low-medium but structural.

### 17. DST-fold and cross-node time ambiguity

`TimeStamp` may be `localTime` (GeneralizedTime, no zone) with `winterSummerIndication = notProvided`, minimum resolution 1 s (D.5); CC payloads carry a *different* time format (Unix seconds, F.3.2.5 IE 134) produced by different nodes (MSC/GGSN/CSCF) with unsynchronized clocks. At the fall-back DST transition the local-time namespace repeats an hour: any event inserted into the folded hour is timestamp-identical to a genuine one, and cross-stream ordering (IRI TimeStamp vs payload PayloadTimeStamp) is heuristic, not specified. A one-hour-per-year per-timezone forgery window plus perpetual cross-node skew ambiguity for ordering-sensitive evidence. Severity: low-medium.

### 18. Filesystem pivot via the LEMF FTP server

The only filesystem control is informative: "It is strongly recommended that at the LEMF machine the structure and access and modification rights of the storage directories are adjusted to prevent unwanted directory operations by a FTP client" (C.2.6, F.3.2.6). The MF credential holder — or an A1 attacker who sniffed `user <leauser> <leapasswd>` (C.2.3, cleartext, no lockout specified) — gets the LEMF account's full write scope: `cd`/`put`/`mput` become arbitrary file planting on LEA infrastructure (pickup directories of other tools, anything the service account can write). Pairs with Panopticon's `nlist` inventory leak on the same credential. Severity: medium.

## Impact

Echo-Flip and Rollback attack evidentiary *attribution* and *history* rather than availability — both leave audits green. Panopticon converts the LI infrastructure into a real-time map of ongoing investigations for any transit-level observer. The implementation-seeded classes (13–15, 18) mean conformant deployments fail in predictable ways without any attacker creativity; findings 12, 16, 17 fail with no attacker at all.

## Novelty boundary

Known prior art: plaintext-transport weakness (conceded by ETSI TS 103 172/TS 102 232), SS7 spoofing, BER parser abuse (used by FND-001). New in this finding, beyond FND-001's six attacks: the one-nibble direction inversion (7), filename-keyed replace-by-name rollback (8), the duplicate-transaction/nlist/transit-UUS1 intelligence triad (9), CID-less REPORT timeline manipulation plus designed exclusion channels (10), the frozen-optional-version downgrade plus the spec's internal module skew (11), the 5.2/C.2.2 batching contradiction (12), non-canonical textual identifier namespaces (13), 16-bit GLIC wrap with tolerated gaps (14), the scope-filter/attacker-PDU paradox (15), the A.5.5 mandated misattribution (16), DST-fold ambiguity (17), and the informative-only LEMF filesystem hardening (18).

## Countermeasures

1. **Bind direction cryptographically to the channel** (R10): sign the UUS1/subaddress correlation block, or derive stereo attribution from an authenticated per-channel identifier rather than an in-band digit; reject mono(0) for new deployments.
2. **Content-addressed, append-only ingest** (R9): LEMF ingest keyed on signed manifests with per-file hashes and explicit duplicate detection — reject same-name replacement rather than overwrite; coordinate `eeee` allocation or make method B names content-derived.
3. **Metadata minimization** (9): encrypt HI2/HI3 transport end-to-end (per TS 103 172), strip LIIDs from filenames, never `nlist` across the wire, and obfuscate duplicate multi-LEA transactions at the MF (or accept and document the clustering risk).
4. **Canonical byte-form identifiers** (R13): binary IP/GGSN encodings, registered operator namespaces, reject non-canonical NEID strings at the LEMF.
5. **Monotonic 64-bit sequences on every stream plus handoff-aware gap alarms** (R14); rate the correlation-number entropy (charging-ID is not a credential).
6. **Allowlist scope filters, not denylist parsers** (R15): strip SIP/SDP/SMS to a *positively enumerated* field set for IRI-only warrants; treat unknown content types as content, not metadata.
7. **Reconcile 5.2 with the delivery mechanism** (R12): hard upper bound on batch hold time; T2=0 forbidden; alarm to the LEA (not only the operator) on discard.
8. **Provenance field for SCI-like records** (R16): distinguish subscriber-initiated from OSS-initiated; **UTC-only timestamps** with a defined cross-stream ordering key (R17); **require** (not recommend) LEMF filesystem confinement — chroot/jail the FTP service account (18).
9. Spec hygiene: fix the annex J / D.5 version contradiction and pin all intra-spec imports to one module vintage (11) — file via ETSI's comment channel.

## References

- ETSI TS 101 671 V3.14.1 (2016-03), clauses cited inline.
- FND-etsi-ts-101-671-001 (same target, first wave).
- ETSI TS 102 232 series; ETSI TS 103 172; 3GPP TS 33.108 — successor context.
