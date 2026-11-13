# M6: independent offline carrier evaluation

Issue [#10](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/10) follows merged M5
([PR #16](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/pull/16), `6a7eed1`). This milestone
adds developer evaluation infrastructure, not another incident controller or production integration.

## Deliverables and boundaries

| Component | Responsibility |
| --- | --- |
| `evaluation/carrier/corpus.py` and developer fixtures | Validate 36 unique cases; materialize checked, permitted evidence and independent parent-only truth |
| `evaluation/carrier/contract.py` | Bound JSON interfaces and mechanically project actual provider output |
| `evaluation/carrier/isolation.py` and `bootstrap.py` | Restrict the adapter and descendants before arbitrary code loads; fail closed when unavailable |
| `evaluation/carrier/adapter.py` | Invoke the actual copied offline providers; preserve their raw results |
| `evaluation/carrier/scoring.py` | Score separate dimensions from claim-specific evidence and independently authored truth |
| `evaluation/carrier/experiments.py` | Validate experiment stages; invalid injection/cleanup is not a model verdict |
| `scripts/evaluate_carrier.py` | Orchestrate bounded trials, reports and substantive deterministic replay |

The six exclusive primary groups contain 6 true faults, 6 healthy/misleading cases, 4 unreliable
tickets, 4 insufficient-evidence cases, 8 service-acceptance cases and 8 compound cases. These are
self-authored adaptations of existing M3/M4/M5 evidence with fresh tickets and compositions.
Their role labels are evaluator-only: the healthy/misleading group includes a false optical premise
with a supported endpoint Wi-Fi finding. A group label is not an expected diagnosis.

The existing Internet design cases and three original plus six derived PCAP inputs remain separate.
No external benchmark source, dataset, capture or production data enters the new corpus or archives.
See [the adaptation note](../research/carrier-evaluation-adaptations.md).

## Evidence and truth contract

The parent imports bounded synthetic sources using M2, resolves actual emitted evidence IDs and
staged M5 references, and exposes only the task, ticket, ordinary provider requests and checked run
bundles. A run includes the four hashed summaries and the manifest-declared `carrier-visible.json`.
Raw evidence, pseudonym maps, source configurations, logical row keys, provenance, parent case IDs,
group labels and expected outcomes stay outside the visible tree. Paths and run/job identities are
opaque; measurement meanings and required source associations remain intact.

The oracle is authored independently of provider output. Support belongs to an individual claim,
layer, field target or absolute test direction. A lucky correct label, unrelated valid reference,
or support combined across findings/jobs does not establish grounding or finer localization.
Neutral observations and evidence gaps are not fault classes. M5 measurement points remain
observation scope, never an inferred faulty device. Technical, acceptance and change states are
scored separately; human signoff remains pending.

Compound cases assess one operator complaint using at least two domain jobs. The supplied evidence
does not establish a cross-job service/time identity; the expected behavior retains independent
findings and withholds a causal join. Matching aliases or adjacent observations cannot create one.

## Execution boundary

Linux Landlock, `no_new_privs` and architecture-aware seccomp restrict a fresh bootstrap before the
adapter or provider imports. Read grants cover copied code, permitted evidence and necessary runtime
files; writes cover only a dedicated temporary directory. Parent oracle/private/repository paths
must not be covered. Filesystem mutation, metadata mutation, process-memory/descriptor acquisition,
network sockets, io_uring and alternate-ABI paths are addressed by the explicit implemented policy.
The actual provider's spawn/exec worker must inherit it. Missing support fails closed rather than
running an unisolated scored trial. The parent bounds time/output and reaps the process group.

This is a tested local worker boundary on a supported Linux environment, not protection from host
root, a compromised evaluator/kernel, all side channels, or a general hostile-host certification.

## Scoring and experiment validity

Reports keep state, layer/resource localization, grounded fault class, evidence grounding,
counterevidence recall/precision, over-attribution, tool completion, parent wall time and reported
cost separate, with raw denominators and null reasons for inapplicable axes. Unknown tokens/cost
remain null. A completed supported abstention differs from timeout, malformed output or tool error.
Canonical replay excludes volatile timings/paths while preserving substantive results and refs.

The [controlled-lab plans](../labs/carrier-controlled-experiments.md) are unexecuted procedures for
disposable local netem, Toxiproxy and DNS experiments. No injection runtime is added. Experiment
records require baseline, injection proof, diagnosis, cleanup, original-operation recovery and
residual-resource evidence with matching operation scope. Missing/failed setup, injection, cleanup
or recovery makes the experiment invalid and model scores unscored.

## Completion gate

Luna authors the implementation/tests; Sol independently reviews Standards and Spec. All code,
fixtures, tests and contracts freeze before tests, validators, builds, provider execution or host
isolation probes. The final gate covers focused controls, all 36 restricted trials and deterministic
replay, leakage/mutation/inheritance controls, full regression, explicit package membership and
standalone extraction. Existing package runtime is unchanged; preserve and cite exact-byte M5
extracted regression evidence where applicable rather than inventing a new run.

Record actual commands, failed/interrupted checks, source hashes, environment and limitations in
[the validation record](../validation-carrier-m6.md). Create and merge a separate verified-head PR
under the user's authorization. M7 real-client/native-Windows/external-security execution remains
user-deferred; fixture replay does not substitute for it.
