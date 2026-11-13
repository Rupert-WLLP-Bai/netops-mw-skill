# Carrier M6 validation record

Implementation base: merged M5 `6a7eed154889d44a089f9c7fead1f0ed55aa0084`.
Issue: [#10](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/10).

Initial implementation froze at `abfd0cc8fa028444a9cd5ca58090cdb3d3a41dfc` before execution.
Focused scoring passed 10 tests. The first corpus check reported one error in four tests;
the first isolation check reported two failures and one error in five tests. Logs are
`.tools/carrier-m6/focused-{scoring,corpus,isolation}-v1.log`.

Frozen-source diagnostics found an identifier-valued telemetry record whose value did not
match its remapped allowlist. The isolation trace found Python 3.14's script-open path uses
`ioctl(FIOCLEX)`, which the blanket ioctl filter denied. These are failed first gates, not
passing release evidence. All check processes ended before correction authoring began.
The correction also preserves the existing importer's line-size limit when serializing larger
M5 inputs. No checks run during authoring; refreeze, final gates and independent Sol review
remain pending.

Subsequent frozen focused runs retained these results:

| Run | Result | Diagnosed correction |
| --- | --- | --- |
| v2, `53f594e` | Corpus 6 and scoring 10 passed; isolation 4/5 passed | Permit read/write on the exact null device for subprocess input |
| v3, `50fa155` | Isolation 4/5 passed | Use `fcntl` for adapter pipe nonblocking flags; retain the ioctl restriction |
| v4, `c7bfa40` | Isolation 4/5 passed | Permit directory reads for the existing confined reader's ancestor traversal |
| v5, `5f44f74` | Isolation 4/5 passed | Copy the provider's schema dependency and preserve its scripts/schemas layout |

Each failed isolation run retained its working oracle/sibling denial, output cap, process-group
timeout cleanup and unavailable-setup control. The actual provider control remained a failure
until the complete dependency tree was supplied. See `focused-isolation-v2.log` through
`focused-isolation-v5.log` and the corresponding `diagnose-*`/`isolation-strace-*` logs under
`.tools/carrier-m6/`. No failed run is counted as release success.

Later frozen runs retained these results:

| Run | Result | Follow-up |
| --- | --- | --- |
| v6, `363ff2c` | Five isolation controls passed; full regression interrupted with exit 130 | Remove an extra per-job oracle field rejected by the strict CLI contract |
| v7, `661d201` | Corpus execution stopped at case 018 | Keep source-declared ordering rather than infer a source key from its run ID |
| v8, `58d515d` | 36 cases completed, but service semantics were incorrect | Preserve protocol field/criterion IDs and independently expand complete service truth |
| v9, `956a265` | 36 cases / 44 jobs completed; all 36 substantive replays matched | Retain measured citation and coverage limitations |
| v9 focused/full | 56 focused and 257 full tests each reported one failure | A new test selected M6 catalog IDs instead of the intended M5 parent cases; correct inputs only |

The final isolation policy removes the temporary global directory-read grant: Linux `O_PATH`
ancestor handles let the shared confined reader traverse without granting private directory listing.
The final controls also cover combined pipe-EOF timeout/output limits. The original Internet
collector, four diagnosis states and 25-second collection budget remain unchanged.

## Frozen runtime evidence

Runtime and fixtures: `956a265`. Environment: Kali 2026.3 rolling under WSL2 Linux
`6.18.58.1-microsoft-standard-WSL2`, x86-64, Python 3.14.7, Landlock ABI 7.

| Check | Actual result | Local evidence |
| --- | --- | --- |
| Actual restricted providers | 36 cases, 44 completed valid jobs | `.tools/carrier-m6/all-v9/`, `all-v9.log` |
| Canonical replay | 36 compared, zero mismatches | `.tools/carrier-m6/replay-v9/`, `replay-v9.log` |
| Fresh extracted runtime regression | 153 tests passed in 304.418 seconds | `.tools/carrier-m6/delivery-v9.log` |
| Suite and eight individual archives | Double builds, member hashes/manifests and clean extraction passed | `.tools/carrier-m6/delivery-v9/delivery-verification.json` |
| Original standalone Internet archive | 16 files; SHA256 `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a` | Same delivery record |
| Managed original web PCAP | Passed offline; capture hash verified; no live collection | Same delivery record |
| Eight Skill validators | Passed | `skill-validators-v9.log` |
| Python 3.10 grammar | Passed; not an actual Python 3.10 execution | `grammar-v9.log` |

The suite has 61 files / 698,920 bytes, SHA256
`fde2933c383e85a8864b2dac525fa1e1e4b10c70fdaf645c5a6572356f4013dd`.
The shared reader changed, so the fresh extracted regression above supersedes reuse of M5 results.
Developer evaluation files, hidden truth, raw evidence and private mappings are absent from archives.

These deterministic provider measurements are separate dimensions, not a perfect overall grade:
state 34/34; service technical, acceptance and change states each 10/10; grounded fault class and
layer each 28/28; claim recall 336/349; complete claim grounding 78/334; counterevidence precision
and recall each 12/21. Resource localization and unknown token/cost fields remain null. Citation
and coverage shortfalls are measured baseline limitations; independent truth was not weakened to
make them pass. No conclusion about an untested LLM follows from these results.

## Final regression

The test-only correction selects M6 cases 023 and 025 for the intended M5 calibration/direction
inputs. The latter intentionally supplies only five forward measurements: its independently
required matrix still contains ten criterion/direction scopes. The test now checks that complete
scope set and retains the original forward-pass/reverse-unverified assertions. The first corrected
focused run exposed the erroneous supplied-row-count assertion (9 tests, one failure); its log is
`focused-corpus-v10.log`. The subsequent focused run passed nine tests in 5.640 seconds
(`focused-corpus-v11.log`). No provider or truth was changed for either test correction.

The sequential full-v11 process stopped before a terminal test result; its partial log is retained
as interrupted, not passed. Frozen source `e643365873609397ace6fe2eda6f82b9a551b7a8` then passed
all **257 tests across 18 test modules in 158.810 seconds**, using four independent module workers.
Every module exited zero and reported a test count. The module commands, timings and counts are
in `.tools/carrier-m6/full-v12/result.json`; individual logs are alongside it. Each command uses:

```sh
.tools/carrier-m1/schema-venv/bin/python -B -W error::ResourceWarning -m unittest discover -s tests -p test_MODULE.py -v
```

The runtime, scripts, Skills and fixture trees are byte-identical to `956a265`
(`git diff 956a265 -- evaluation scripts skills tests/fixtures` is empty), so the completed v9
36-case/replay/package gates apply to this final test correction without rebuilding unchanged
artifacts.

## Independent review correction and final gates

Sol R1 found one P2 scoring defect: a complete required support set plus a fabricated or other-job
reference could retain grounding-dependent credit. Source `7b9c83c4825c4a2b6a801d8c53725cbd0fd21450`
requires every supplied support reference to belong to that job's independent evidence index.
Two new controls deny grounding, grounded class and layer credit while preserving separate state
and claim-recall results. No provider, fixture or hidden truth changed.

The frozen correction passed 12 focused scoring tests (`focused-scoring-v13.log`) and all
**259 tests across 18 modules in 165.638 seconds** (`full-v13/result.json`). All 36 restricted cases /
44 actual jobs completed again (`all-v13.log`), and fresh actual replay compared 36 cases with
zero mismatches (`replay-v13.log`). The measured dimension counts above stayed identical.
Python 3.10 grammar passed again for evaluation sources (`grammar-v13.log`). Packaged Skill sources
remain byte-identical to the completed v9 package/extracted-runtime gate; only developer scoring
and its tests changed. [Independent final Sol re-review](review-carrier-m6.md) closed the P2:
Spec has zero current findings; Standards has zero hard violations and one nonblocking P3 suggestion.

R1 Standards also recorded one nonblocking P3 maintainability suggestion: reuse shared task
validation in the adapter. The parent validates the task before invocation; this duplication does
not affect the completed corpus or grant extra evidence access. It remains a disclosed follow-up
rather than expanding this release correction. Both original reports are retained locally as
`sol-standards-r1.md` and `sol-spec-r1.md`.

Controlled-lab injection plans are unexecuted. No live LLM, MobileWork, native Windows, real-device
or external security acceptance is claimed. Actual M7 client/Windows/security validation remains
explicitly deferred to the user.
