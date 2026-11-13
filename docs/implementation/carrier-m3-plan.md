# M3: offline access and subscriber diagnostics

Implement [issue #7](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/7) from merged M2
`147c2af0fb244cf913af105d148051bee316a679`, on `feat/carrier-m3-access-diagnostics`.
Terra owns the incident-private analyzer, CLI, meaningful tests, shared bounded read extension and
explicit suite allowlist/inventory updates. Luna owns the independently usable access Skill, its
focused references, twelve synthetic visible scenarios and separate evaluator-only answers.
The parent owns integration, final execution, review records and the phase PR. All documentation is English.

## Contract and diagnostic scope

The selected interface is an incident-owned `scripts/diagnose_access.py --input REQUEST.json`.
A strict versioned request supplies explicit reference/incident times, freshness policy, at most eight
M2 runs with four expected summary hashes each, source-qualified operator bindings into verified M1
topology, and optional applicable optical profiles with real evidence citations. Values are read
from checked M2 observations and carrier envelopes; declarations never supply measurement values.
A profile must cite the imported limit and observed device-model evidence. Keep raw files, reversible
pseudonyms and evaluator answers outside runtime inputs and packages.

Bound request bytes, depth, strings, records, links, artifact reads, total bytes, worker elapsed time
and output. Reuse existing confined evidence readers; preserve ordinary case-import defaults when
adding tighter optional read limits. Cache each checked artifact once to prevent repeated-source
amplification. A bounded worker provides a five-second whole-analysis watchdog. Strict malformed
inputs fail without case mutation. Analysis performs no network or device operations.

Recompute collection and event freshness against the request time. Require same explicitly mapped
service/resource, compatible direction/unit/denominator, synchronized known clock uncertainty and
ordered comparable windows. Alias equality or a hostname cannot establish identity. Mapping,
clock, reset/wrap, sampling and missing reverse-direction gaps remain visible. Unknown metrics
remain unused evidence; they are never silently interpreted as a supported vendor format.

Cover optical trend/profile applicability, LOS/LOF and PON session flaps, FEC/CRC counter quality,
PPPoE/IPoE and AAA, DHCP lease/pool, VLAN/QinQ service mapping, forwarding, Wi-Fi and application
boundaries. Distinguish source observations from hypotheses and counterevidence. Preserve the four
existing statuses; parsing and authentication success do not establish service health or recovery.
Every finding cites actual run-qualified evidence and states limitations. Missing usable support
requires abstention. Normal optical evidence cannot rule out failures outside its observed scope.

## Independent entry and verification

`telecom-access-diagnostics` provides manual offline reasoning from supplied records without assuming
the incident Skill is installed. Its optional executable provider is discovered explicitly; no sibling
imports or duplicated case controller. Preserve all five existing entries and the original collector.
Add twelve visible synthetic cases covering the issue's full inventory with evaluator-only truth in
a separate test directory. Include negative stale/wrong-object/wrong-source/direction/profile/clock
and hash cases, localization/over-attribution checks and public CLI-to-existing-case integration.

No tests, validators, builds or runtime checks execute during implementation. After all code, tests,
fixtures and packaged docs are frozen, run full regressions, clean-extraction tests, per-Skill
structural validation and deterministic package/member/hash verification. Then Sol independently
reviews Standards and Spec. Required corrections restart the implementation/freeze/final-check/review
sequence. Open and merge only the independently reviewed phase PR, as explicitly authorized by the
current completion goal. Actual MobileWork/native Windows/external security execution remains user-deferred.

