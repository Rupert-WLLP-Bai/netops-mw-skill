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
| Final complete engineering regression | Passed: 264 tests across 21 modules in 160.074 seconds at `eebcaab` |
| Suite and eight individual deterministic builds | Passed; two complete handoffs byte-identical, 103 files each |
| Exact archive membership/hash/license verification and clean extraction | Passed for all nine archives and eight independent Skill roots |
| Fresh extracted runtime regression | 153 tests in six independently executed modules, all exited zero |
| Extracted offline normal/changed/error provider checks | Passed against the independent incident ZIP; details below |
| Independent final Sol Standards and Spec review | Complete: 0 hard Standards breaches, 2 nonblocking P3 suggestions; 0 remaining Spec findings |
| Actual MobileWork V-01/V-02/V-03 | `pending_user`; explicitly deferred |
| Native Windows execution | `pending_user`; Linux/WSL does not substitute |
| External 43 static / 17 dynamic security assessment | `pending_user`; no report exists here |
| Real device/vendor acceptance and live fault injection | Not performed or claimed |

The user-owned short Word draft reserves actual results and original screenshot positions for
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

## Final correction gates

After the cache correction froze at `eebcaab07c6e6d42162b9a1dbfef3111c928ab68`, both focused
standalone-builder tests passed. The complete regression then passed all 264 tests across 21 modules
in 160.074 seconds (`.tools/carrier-m7/full-v2/result.json`). Two fresh complete handoffs each
matched every byte of all 103 files in the previously verified handoff, including manifests and
hash ledgers (`.tools/carrier-m7/rebuild-v2/result.json`). The fresh extracted 153-test regression
and three sample checks therefore apply to those unchanged artifacts; they were not rerun merely
for nonpackaged validation prose or the separate Word layout.

```sh
.tools/carrier-m1/schema-venv/bin/python -B .tools/carrier-common/run_parallel_tests.py .tools/carrier-m7/full-v2
.tools/carrier-m1/schema-venv/bin/python -B .tools/carrier-common/rebuild_m7_compare.py
```

The focused run is retained in `focused-release-v2.log`. All gate processes finished before the
independent final Sol review. Actual client, native Windows and external security verdicts remain
pending user execution.

## Published layout correction

The initial independent Spec review found a P2 setup error: the guide placed the extracted incident
directory beside the handoff while its commands expected both the incident directory and
`validation-inputs/` inside the handoff root. Luna corrected that paragraph at `ecdfd18`, after both
reviewers released ownership. No runtime, test, fixture or archive member changed.

The frozen correction passed `.tools/carrier-common/verify_m7_published_layout.py`; evidence is in
`.tools/carrier-m7/layout-v3/`. Two fresh 103-file handoffs were identical. Compared with the
previously verified handoff, only `guide/README.md` and its top-level hash ledger changed; all nine
ZIPs and their manifests remain byte-identical. The gate extracted the incident ZIP into the
handoff root and executed all six published shell commands from that root. Normal, missing-reverse
and malformed inputs produced the expected technical results and exit statuses, with human
signoff pending. Actual command transcripts and output files are retained beside `result.json`.

```sh
.tools/carrier-m1/schema-venv/bin/python -B .tools/carrier-common/verify_m7_published_layout.py
```

This guide-only correction does not invalidate the unchanged 264-test source regression or
153-test extracted-runtime regression. Final independent re-review passed after these completed gates; the [separate review axes](review-carrier-m7.md) retain two nonblocking maintenance suggestions.
