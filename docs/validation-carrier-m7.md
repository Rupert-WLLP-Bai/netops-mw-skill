# Carrier M7 engineering validation and pending user acceptance

Base: merged M6 `cda64923918214325a9cb703b109160a2a5b80fc`, PR #17.
Issue: [#11](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/11).
Scope: [release engineering and user handoff](implementation/carrier-m7-plan.md).

Initial implementation froze at `89ea2b5d29470285003946a4bc939572091a834f` after both Luna owners
released all source, tests and guidance. No tests, validators, builds or providers ran during authoring.
Environment: Kali 2026.3 under WSL2 Linux 6.18.58.1, x86-64, Python 3.14.7.

| Evidence class | Current state |
| --- | --- |
| Initial complete engineering regression | 264 tests across 21 modules; one new builder test error, retained as failed |
| Suite and eight individual deterministic builds | Passed; two complete handoffs byte-identical, 103 files each |
| Exact archive membership/hash/license verification and clean extraction | Passed for all nine archives and eight independent Skill roots |
| Fresh extracted runtime regression | 153 tests in six independently executed modules, all exited zero |
| Extracted offline normal/changed/error provider checks | Passed against the independent incident ZIP; details below |
| Independent final Sol Standards and Spec review | Pending final engineering gates |
| Actual MobileWork V-01/V-02/V-03 | `pending_user`; explicitly deferred |
| Native Windows execution | `pending_user`; Linux/WSL does not substitute |
| External 43 static / 17 dynamic security assessment | `pending_user`; no report exists here |
| Real device/vendor acceptance and live fault injection | Not performed or claimed |

The user-owned short Word draft will retain actual results and original screenshot positions for
the user to complete. The original PPT/Word files and personal paths are private local materials;
the public handoff includes derivative guidance and source hashes only. One report covers one
actual Skill/version. All official security criteria retain pending status regardless of local
engineering checks.

## Actual initial gates and correction

The full run took 224.932 seconds. Its sole error was `test_unknown_skill_and_overwrite_are_rejected`:
the standalone builder reloaded the suite module on every call, creating distinct `ReleaseError`
classes. Rejection worked but a caller could not reliably catch the earlier exported exception
identity. The correction caches that module load; the original assertion and rejection behavior
stay unchanged. All gate processes ended before correction authoring. The failed log remains
`.tools/carrier-m7/full-v1/test_skill_release.log`; counts and module exits are in `full-v1/result.json`.

The independent delivery gate passed before that correction. Evidence is
`.tools/carrier-m7/delivery-v1/result.json`, its build/individual-module logs, and the retained
`delivery-v1/handoff/` tree. It verifies every generated file against the non-self-referential hash
ledger, compares both complete builds, checks ZIP/member manifests and licenses, extracts every
independent Skill, runs all available CLI help entry points, and executes the three prepared inputs:

| Input | Observed technical result | Observed acceptance/signoff |
| --- | --- | --- |
| Normal historical sample | `conformant`; ten directional tests passed | `awaiting_human_signoff`; human `pending` |
| Missing reverse evidence | `unverified`; five forward passes, five reverse rows unverified | `blocked`; human `pending` |
| Malformed JSON | Nonzero exit, empty stdout, invalid-input message on stderr | No fabricated result |

| Package | Version / files | Actual SHA256 |
| --- | --- | --- |
| Suite | 0.2.0 / 61 | `e9f54e3a853f116d7def0e4ffcab9fae5c79288ffee3dfeea3e758e406c680bf` |
| Incident | 0.2.0 / 26 | `a111e49858aecc8ff223e82116db978a7a23e69d49e576332ef32667c1a815a4` |
| Original Internet | 0.1.0 / 16 | `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a` |

The other seven individual Skill versions remain 0.1.0. Their actual archive/member hashes are
recorded in the handoff sidecars and delivery result. No source or dependency is inferred from a
filename. All 60 security ledger criteria and all eight target-client records remain `pending_user`.

Actual gate commands:

```sh
.tools/carrier-m1/schema-venv/bin/python -B .tools/carrier-common/run_parallel_tests.py .tools/carrier-m7/full-v1
.tools/carrier-m1/schema-venv/bin/python -B .tools/carrier-common/verify_m7_handoff.py .tools/carrier-m7/delivery-v1
```

The helpers record each actual module/build/provider command. Public build entry points are
`scripts/build_handoff.py`, `scripts/build_skill.py` and `scripts/build_suite.py`; each test module
can be rerun with `python -B -W error::ResourceWarning -m unittest discover -s tests -p test_NAME.py -v`.
Eight Skill validators passed (`skill-validators-v1.log`). Python 3.10 grammar passed for 42 sources
(`grammar-v1.log`); this is not actual Python 3.10 runtime or Windows validation.

Final correction regression, output-equivalence check and independent Sol review remain pending.
