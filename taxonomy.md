# Taxonomy

## Domains

| Domain | Scope | Example targets |
|--------|-------|-----------------|
| `telecom` | Mobile core & signaling (SS7/SIGTRAN, Diameter, GTP-C/U, MAP/CAMEL), IMS/SIP, PSTN/ISDN signaling (ISUP/DSS1), lawful interception & mediation handover interfaces, TETRA/P25, SMS/SMPP/UCP | ETSI TS 101 671, ETSI TS 102 232 series, 3GPP TS 33.107/33.108, GTP-C, Diameter S6a |
| `network` | Interdomain and IGP routing (BGP, OSPF/IS-IS), name & infrastructure services (DNS, DHCP, NTP), L3/L4 (IP, TCP, UDP, ICMP, QUIC), VPN/tunneling (IKE/IPsec, WireGuard, GRE), CDN/edge | BGP route leaks, DNS cache poisoning, QUIC handshake |
| `wireless` | 802.11 family, Bluetooth/BLE, 802.15.4/Zigbee/Thread, NFC, cellular access layer (RRC/NAS) where radio-specific, SDR/RF | WPA3 SAE, BLE pairing, Thread commissioning |
| `web` | HTTP/1-3 semantics, proxies/CDN behavior, browser security, web frameworks & template engines, identity federation (OAuth2, OIDC, SAML) | OAuth2 redirect flows, request smuggling, SAML signature wrapping |
| `crypto` | Applied protocol cryptography: negotiation/downgrade, nonce & KDF misuse, oracle & padding classes, RNG, and ASN.1/BER parsing of crypto containers | TLS cipher negotiation, JWS/JWE misuse, X.509 BER leniency |
| `systems` | OS kernels, hypervisors, firmware/boot (UEFI, secure boot), container runtimes & orchestration, sandboxes, local privilege escalation | container escapes, VT-d/IOMMU, efi variables |
| `applications` | Named vendor products, SaaS platforms, desktop/mobile apps, product APIs beyond web-generic | file parsers, update pipelines, mobile IPC |

**Placement rule:** file a finding under the domain of the *protocol/product attacked*; cross-domain aspects are referenced, not duplicated. New domains are added by editing this file, not by creating ad-hoc folders.

## Target classification

- `protocol-spec` — the attack holds against the specification itself; any conformant implementation is exploitable
- `protocol-implementation` — the spec is sound; a class of implementations is not
- `product` — a specific vendor software/SaaS/firmware release
- `standard` — process or semantic issues in a standards-body deliverable
- `algorithm` — a mathematical construction

## Actor model (prerequisites)

- **A1 — on-path/infrastructure:** transit provider, route/DNS hijack, shared segment, signaling interconnect
- **A2 — end-party:** the affected participant acting only through legitimate protocol inputs (e.g., an interception target via its own signaling; a protocol endpoint user)
- **A3 — insider:** operator/vendor/admin staff
- **A4 — state/agency-scale:** A1 capabilities at scale, or with legal coercion

## Severity

| Level | Criteria |
|-------|----------|
| `critical` | Undetectable break of the core trust function — fabrication/destruction of evidence or authentication with no alarm possible |
| `high` | Silent integrity or loss of a major function; alarm suppression; zero-credential impersonation |
| `medium` | Integrity/confidentiality break with prerequisites or detectability; noisy DoS of core function |
| `low` | Side channels, metadata leakage, detectable DoS |
| `info` | Hardening observations, defense-in-depth |

## Novelty boundary (required in every finding)

- `known-gap` — already documented publicly
- `extension` — new combination or prerequisite of known techniques
- `novel` — new attack class or vector; the finding must state the prior art checked

## Status

`draft → review → published`; `superseded` (with `superseded_by`). Published findings are corrected by publishing new findings, never by silent edits.

## Identifiers

`FND-<target-slug>-NNN` — assigned in the target README, immutable, never reused. One ID per finding document; a document may bundle closely-related attack variants of the same root cause (as in `FND-etsi-ts-101-671-001`).
