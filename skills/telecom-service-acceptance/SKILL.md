---
name: telecom-service-acceptance
description: Review carrier circuit turn-up, service acceptance, and pre/post-change evidence from sourced orders, SLA criteria, endpoint mappings, and test results. Use when comparing expected and actual service delivery or preparing a local change-review draft; this Skill does not approve or execute changes.
metadata:
  version: 0.1.0
---

# Telecom service acceptance

Use this Skill to compare a supplied service order and acceptance criteria with source-backed service and test evidence. Keep technical conformance, change-review readiness, and human acceptance separate. M2 documents and operator mappings are declarations with provenance, not authenticated truth.

## Workflow

1. Define the selected service, circuit, distinct endpoint A and endpoint B sites, reference time, test window, and requested change phase. Keep customer and infrastructure identifiers pseudonymous.
2. Inventory the supplied order, current-authority evidence, approved field and criterion inventories, topology links, directional mappings, actual observations, methods, windows, and any calibration or change records. Preserve source/native identities, event and collection times, clock uncertainty, units, and counterevidence.
3. Compare each expected field to its own actual target. Require explicit service-to-circuit, service-to-endpoint, and site-to-measurement-point relations. Require source-backed A-to-B and B-to-A mappings independently; do not derive absolute direction from ingress/egress or endpoint names.
4. Apply the complete evidence rules in [the service-acceptance reference](references/service-acceptance.md). Report an observed mismatch only when the expected and actual values are comparable and correctly scoped. Missing, stale, conflicting, ambiguous, unsupported, or incomparable inputs remain unverified.
5. For a requested change, review scope, impact, approval chronology, planned window, required prechecks, rollback ownership and trigger, residual risk, and required postchecks. A pre-change review may describe planned checks but cannot invent their results. A post-change review requires actual ordered checks.
6. Produce a local draft with evidence references, counterevidence, gaps, and bounded follow-up. Human signoff stays pending. A requested change review that is blocked keeps `acceptance_status` blocked even when technical criteria are conformant. Never infer approval, acceptance, recovery, or permission to execute.

This Skill can be used manually from supplied records. If the host explicitly discovers the incident-owned `scripts/review_service.py` provider and its runtime, its complete request, output, metrics, and gap contract is bundled in that provider's `service-review.md` reference. The provider is optional and independent of this manual workflow. It consumes checked local runs and returns deterministic JSON with a bounded Markdown handover draft and qualified evidence refs; it does not create or send files, contact a network, mutate an incident, or perform a change. Do not assume an installed sibling Skill or a native MobileWork API.
