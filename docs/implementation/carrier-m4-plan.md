# M4: offline IP bearer and transport diagnostics

Implement [issue #8](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/8) from merged M3
`4087d4e0627fcd08ebaeaf6b9d6d4def7af7741a`, on `feat/carrier-m4-transport-diagnostics`.
The existing access provider remains compatible. The original collector, five original entries,
25-second live budget, four diagnosis states and single SQLite controller remain protected.

## Interface and rules

Add incident-owned `scripts/diagnose_transport.py --input REQUEST.json` and a separately usable
`telecom-transport-diagnostics` manual Skill. A narrow private shared module now has two actual callers:
access and transport. It owns checked M2 loading, explicit M1 bindings, time/clock checks, bounded input
and worker execution. Access/transport own their diagnostic vocabulary and rules. Preserve existing
access requests/results and ordinary case-import defaults; do not introduce another controller.

Transport requests retain the checked-run/reference/service/binding fields and add explicit
`transport_profiles` and `measurement_windows`. Measurements, limits, window boundaries and aggregation
come from checked source observations, not caller-supplied numeric assertions. A polling interval does
not establish measurement coverage. Queue correlation requires source-supported equal windows,
compatible units/direction/counter semantics, no discontinuity and applicable cited profile aggregation.
All required evidence and topology/profile/window declarations remain traceable through qualified refs.

Distinguish BGP/IGP/MPLS/SR/LAG control events from measured service failure. Scope route/service
correlation by explicit prefix, VRF, flow, source, resource and time; no guessed subnet/identity mapping.
Queue or class drop increments alone are neutral. A profiled queue condition does not prove customer
outage. MTU comparison requires an explicit L3 packet-size basis and supplied overhead; missing PMTUD
feedback cannot prove filtering or a black hole. ECMP/asymmetry requires independently supplied scoped
directions. A single traceroute cannot identify a failed router or AS. Preserve counterevidence,
conflicts, stale/unknown clock/mapping/sampling/reset and coverage gaps, with correct abstention.

Use bounded strict UTF-8 JSON, eight checked runs, 512 observations/bindings/links, two MiB per run,
16 MiB aggregate, one MiB request/result, depth/string/work bounds, at most 256 window declarations,
and a five-second trusted worker watchdog. Zero/unknown samples cannot manufacture direction coverage.
Unknown fields/metrics never become facts or a device action. Output source observations, hypotheses,
actual support/counterevidence and gaps; do not infer a faulty PE/P/interface/AS from an observation point.

## Ownership and verification

Terra owns runtime/shared extraction, public CLI and integration/boundary tests, suite inventory and
explicit allowlists. Luna fixture author owns twelve opaque synthetic cases, separate evaluator-only
oracle and source/license/hash provenance. Luna documentation author owns the independent Skill and
its reference plus the installed incident-owned request/output contract. The parent owns integration,
README/glossary/status documents, final execution and PR. Coordinate exact versioned fields/codes before
authoring dependent test inputs. Do not derive oracle truth from an implementation's returned answer.

Cover the issue's twelve scenarios and wrong-object/source/time/unit/window/class/profile/clock controls,
conflicting observations, malformed/oversized/symlink/encoding/count inputs, real M2-to-provider-to-case
references and full M3 parity. Developer source/config/templates and oracle stay outside product archives;
only rendered sanitized evidence and resolved requests enter the analyzer. Actual OS isolation belongs
to M6; local engine checks are not a live LLM or MobileWork benchmark.

No tests, validators, builds or runtime checks execute during any authoring/correction phase. After all
three implementers freeze, run full regression, clean extraction, seven Skill validators, provenance
checks, reproducible suite and independent archives, and the managed PCAP compatibility check. Then
Sol independently reviews Standards and Spec. Correct required findings before renewed final checks
and review. Open and merge the verified phase PR under the active completion authorization. Actual
MobileWork/native Windows/external security acceptance remains user-deferred for M7 preparation.

