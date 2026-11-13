---
name: telecom-access-diagnostics
description: Assess supplied FTTH/PON, optical, PPPoE/IPoE, DHCP/AAA, or VLAN service-mapping evidence offline. Separate observations, scoped hypotheses, counterevidence, and gaps.
metadata:
  version: 0.1.0
---

# Telecom access diagnostics

Use only supplied records or explicitly authorized local evidence bundles. Establish the affected service, incident window, topology context, source identity, and evidence age before comparing observations. Keep source facts separate from hypotheses; cite each material statement with run-qualified evidence references and state counterevidence and limits.

Compare only observations with an explicit source-qualified service/resource mapping, compatible unit, direction, denominator, sampling window, clock quality, and counter semantics. Treat stale data, missing reverse direction, reset counters, uncertain clocks, unknown mappings, and unsupported metrics as evidence gaps. Localize only as specifically as verified topology and cited evidence support. Authentication acceptance, one optical sample, or absence of an alarm does not establish end-to-end health or recovery.

This Skill supports manual offline reasoning from supplied Agent-visible records. If the host explicitly discovers the incident-owned `diagnose_access.py` provider and its required runtime is available, follow its documented interface; do not assume a sibling Skill path or install a provider. The provider is optional. It reads bounded, hash-checked local M2 run bundles and does not import evidence, mutate cases, access a network, or issue device commands. If the provider or its runtime is unavailable, continue manually when the supplied records suffice; otherwise state the missing capability or input.

Read [access diagnostics](references/access-diagnostics.md) for evidence comparison, supported observation boundaries, and interpretation limits.
