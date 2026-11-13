# Run the offline carrier evaluation

This developer tool evaluates the actual offline providers with permitted synthetic evidence.
It does not operate network equipment, call a live LLM, inject a fault or validate MobileWork.
The independent corpus contains 36 cases in six exclusive groups; its oracle remains parent-only.
See [the implementation plan](implementation/carrier-m6-plan.md) and
[design references](research/carrier-evaluation-adaptations.md).

## Commands

From a checkout, using Python 3.10 or later on a supported Linux host:

```sh
python3 scripts/evaluate_carrier.py --case case-001 --output-dir /tmp/carrier-one
python3 scripts/evaluate_carrier.py --all --output-dir /tmp/carrier-all
python3 scripts/evaluate_carrier.py --replay /tmp/carrier-all --output-dir /tmp/carrier-repeat
```

Choose fresh output directories. The tool materializes checked M2 bundles, copies the provider
code, restricts the adapter and its descendants, invokes the actual provider CLI and scores its
bounded answer. It never supplies raw/private importer artifacts, authoring labels or truth to the
adapter. A normal run reads the task and visible evidence; it cannot read checkout or oracle
file contents. The confined reader walks ancestor directories with Linux `O_PATH` handles;
private directory listing is not granted. Filesystem metadata and other side channels are
outside the confidentiality claim.
The parent retains audit output under `<output-dir>/<case-id>/report.json`.

The current bootstrap targets x86-64 Linux with Landlock ABI 3 through 11 and seccomp-BPF.
It handles the required file rights through ABI 3, additional ioctl rights at ABI 5+, and UNIX
resolution rights at ABI 9+; syscall filtering denies socket operations and ioctl requests except
`FIOCLEX` (`0x5451`), which sets close-on-exec on a file descriptor. ABI 12+
is rejected until its additional interfaces are represented. This is an implementation support
range; the validation record separately identifies the environment actually exercised.
Linux filesystem/syscall restrictions must install successfully. Unsupported setup yields
`isolation_unavailable` and unscored diagnosis dimensions; it does not fall back to unisolated
execution. A failed tool call, timeout or invalid output is a completion result, not a successful
abstention. Reports distinguish fixture replay, actual adapter execution, controlled experiment
execution and real-client validation. The last two are `not_run` for ordinary corpus evaluation.

## Read the dimensions separately

| Dimension | Interpretation |
| --- | --- |
| State | Supported fault/insufficient decision; M5 technical, acceptance and change results remain separate |
| Localization | Supported layer precision; a null resource or observation point is not a faulty-device claim |
| Fault class | Expected fault code with its applicable support; neutral observations do not count as faults |
| Grounding | Complete claim-specific support set, with every ref independently present in that job's evidence |
| Counterevidence | Required-counter recall and returned-counter precision, assessed for the same claim |
| Over-attribution | Forbidden cause/code/scope, unsupported precision or cross-job causal joining |
| Completion | Actual completion/error/timeout category, separate from diagnostic correctness |
| Runtime | Parent-measured wall time, separate from substantive replay comparison |
| Cost | Actually reported tokens/cost; unknown is null |

An empty or inapplicable denominator has a null score and reason. A correct label without relevant
evidence cannot receive grounded-class or finer-localization credit. References collected across
different findings or jobs do not ground an individual claim. Source-declared fields and test
directions are compared independently; an A-to-B pass cannot establish a B-to-A result.

The parent mechanically checks normalized claims against raw provider output. Worker-supplied
normalization or a plausible evidence ID cannot invent a fact. An independent parent-only emitted
evidence index supplies membership. If that index is unavailable to a standalone scoring caller,
membership-dependent axes are unscored rather than credited from the answer itself.

Replay compares canonical substantive outputs and score counts while excluding wall timings and
volatile temporary paths. It does not replace independent truth with an earlier provider answer.
Fresh false-premise tickets and compound cases test evidence discipline; this deterministic adapter
does not establish how an untested LLM would respond to those tickets.

## Optional captured experiment records

```sh
python3 scripts/evaluate_carrier.py --experiment-record captured-lab-record.json --output-dir /tmp/carrier-lab-record
```

This command validates a supplied record only and writes `experiment-validation.json`; it starts
no provider and performs no injection. Missing/failed baseline, injection proof, cleanup,
original-operation recovery or residual-resource checks make a trial invalid. Diagnosis and
evidence must refer to the same original operation. Invalid experiments have no model verdict.
The [three disposable-lab plans](labs/carrier-controlled-experiments.md) describe future manual
experiments; they remain unexecuted until their actual evidence is recorded.

## Scope of the isolation evidence

The trusted evaluator and OS enforce a narrow local worker boundary. Only copied code, permitted
inputs, necessary runtime files and a dedicated writable temporary directory are granted. The
policy grants file-content and directory reads only to the selected inputs/code/runtime trees.
The null device is writable for subprocess input.
The policy is inherited into actual provider spawn/exec workers; the parent bounds output/time and
cleans the process group. Final validation must include a working provider control and attempted
oracle/sibling access from direct and spawned code. See [the validation record](validation-carrier-m6.md)
for the exact tested platform and results; implementation intent is not a passing record.

This boundary does not protect against a compromised privileged host, kernel or evaluator, or
claim every possible side channel is absent. Developer inputs, oracle and evaluation reports are
outside Skill release archives. Runtime remains standard-library Python under the repository's
Apache-2.0 license. Optional lab tools and reference-only research are not bundled dependencies.
