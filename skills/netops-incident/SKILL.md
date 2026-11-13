---
name: netops-incident
description: Guide a network incident from scoped evidence through operator decisions, action records, and recovery checks. Use for coordinated incident investigation or follow-through; use a focused capture or handoff workflow when that is the whole request.
metadata:
  version: 0.2.0
---

# Network incident

Start with the affected business operation, impact, original vantage, identity, target, protocol and address family, proxy, workload, and time window. Mark unknowns explicitly. Establish the owner's success criterion, stability window, check cadence, coverage, available permissions, and finite collection budget. Do not claim an unknown value is known.

Use supplied evidence first. Keep observation separate from hypothesis, cite evidence with its run ID, and compare only compatible scope and times. Identify counterevidence and limitations. Choose a next test only if its expected support and counterevidence distinguish the remaining hypotheses and it fits the authorized budget; stop when no permitted test or budget remains. Do not turn a supplied cause into a finding.

The local [case controller](references/case-contract.md) persists this workflow when its bundled `scripts/case.py`, Python 3.10+, a private case directory, and a supported local filesystem are available. Use its documented CLI and JSON inputs; budgets persist across cancellation, restart, and reopening. If persistence is unavailable, work from supplied inputs and explicitly say that no durable controller is enforcing state or budgets. Do not invent a case, an action, or a completed check.

For collection, discover a compatible installed `internet-access-triage` provider using the host's supported discovery mechanism; use its declared CLI only when explicitly authorized. The controller accepts a user-selected trusted provider and reserves its budget before execution. Missing provider or access is a capability gap, not permission to install a tool or substitute a probe. Existing capture analysis stays offline.

An operator performs any action. Record owner, authorization, preconditions, intended change, actual or unknown outcome, evidence, and rollback responsibility. Reconcile an unknown outcome with its authoritative owner before another action. Verify the original operation against the agreed scope and stability criterion using independent timestamped observations. Failed, missing, stale, or incomparable checks and recurrence prevent a recovered conclusion. When the case cannot progress, produce an open or unresolved draft handoff with evidence, uncertainty, owner, and next action; never send it unless explicitly asked through an authorized channel.
