---
id: FND-<target-slug>-NNN
title: "<one-line finding>"
date: YYYY-MM-DD
domain: <telecom|network|wireless|web|crypto|systems|applications>
target: "<product/spec name>"
target_versions: ["<exact versions analyzed>"]
classification: <protocol-spec|protocol-implementation|product|standard|algorithm>
severity: <info|low|medium|high|critical>
status: <draft|review|published>
actors: [A1-on-path, A2-end-party, A3-insider, A4-agency]
novelty: <known-gap|extension|novel>
references:
  - <spec doc / prior art / successor mitigation>
superseded_by: # only when status=superseded
---

# <Title>

## Summary

One paragraph: what breaks, for whom, with what prerequisites.

## Target & versions

What the target is; exact versions/editions analyzed; where the relevant text lives.

## Root causes

Numbered (R1, R2, ...), each cited to clause/section (specs) or `file:line` + commit (code).

## Threat model

Actor prerequisites (A1–A4 per `taxonomy.md`) and the trust assumption being violated.

## Attack(s)

Per attack: name, numbered procedure, protocol-conformance argument, impact. Bundle closely-related variants in this one document.

## Impact

Confidentiality / integrity / availability / evidentiary-value consequences, including symmetric damage (e.g., what the finding does to the evidentiary value of legitimate records).

## Novelty boundary

What is known prior art (with references) versus what this finding contributes.

## Countermeasures

Concrete, ordered, mapped to root causes; note successor specs/products where relevant.

## References
