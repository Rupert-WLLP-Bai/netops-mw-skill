---
name: telecom-transport-diagnostics
description: Assess supplied BGP, OSPF/IS-IS, MPLS/SR, VRF, ECMP/LAG, interface, queue/QoS, MTU, or PMTUD transport evidence offline. Separate control-plane events from measured service impact, preserve uncertainty and counterevidence, and localize only to supported scope. Use for IP bearer and carrier transport investigations; it does not connect to or change a network.
metadata:
  version: 0.1.0
---

# Telecom transport diagnostics

Use this skill to reason from supplied, offline IP bearer and transport evidence. Work from explicit service scope, source identity, resource mapping, direction, units, timestamps, and observation windows. Treat source mappings and profiles as operator declarations with provenance, not authenticated truth.

## Workflow

1. Define the affected service, the reported time window, the traffic direction, and the observed symptom. Keep customer identifiers pseudonymous.
2. Inventory the supplied records and their source, source-native alias, event time, collection time, clock quality, unit, direction, counter semantics, and scope. Keep conflicting and counterevidence visible.
3. Establish each service/resource binding from explicit evidence. Match prefix, VRF, flow, class, source, resource, direction, and time only where the records state them. Do not infer an identity or topology from a hostname, similar label, route text, or path.
4. Apply the evidence rules in [the transport reference](references/transport-diagnostics.md). Report observations separately from hypotheses, name gaps and limitations, and request the next measurement that would resolve them.
5. If the incident installation provides `scripts/diagnose_transport.py`, it may be used as an optional deterministic analyzer after checked M2 runs and explicit mappings are available. Its exact request, result, metric, code, and bound contract is documented in the provider's bundled `transport-analysis.md` reference. Without that provider, use this skill's manual workflow; do not assume a sibling skill or installation exists.

## Reporting

Return a concise evidence-led summary with: observed events; any supported scoped correlation or hypothesis; actual supporting and counterevidence references; unresolved gaps; and bounded next checks. Distinguish control-plane state from data-plane service observations. A queue threshold condition is not itself customer outage evidence. Do not name a faulty PE, P, interface, router, or AS unless supplied evidence independently establishes both its role and causal scope.
