# Carrier M1 validation

This record covers [issue #5](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/5), the domain
model and optional evidence contracts, at corrected source commit `f244b65` (initial implementation
`f2c1b73`). It does not cover M2 adapters,
access/transport diagnosis, service acceptance, or actual MobileWork invocation. The implementation
branch is `feat/carrier-m1-domain-contracts`, based on `main` at `dfe326a`. The initial Sol review
requested compatibility and resource-bound corrections, described below. Final
[Sol re-review](review-carrier-m1.md) passed both standards and specification with zero open findings;
the milestone is submitted as a PR for maintainer review without merging.

## Implementation and compatibility

The root glossary defines the 15 object types requested by the issue and six network layers. Two
bundled JSON Schemas, an incident-private standard-library validator, and a bundled contract describe
optional versioned service context, explicit topology relationships and carrier evidence provenance.
They do not parse vendor output or infer object identities, counter meanings, thresholds, causes or
recovery. Unknown measurements and mappings remain explicit. Comparison gaps preserve heterogeneous
observations while withholding unsupported comparison.

Optional source context and carrier records live in the existing imported manifest's hashed bytes;
their evidence IDs, object references and visible artifact hashes are checked before transactional
publication. Source context is retained without assuming equivalence to the receiving case. Case
context creation, update and removal use existing persistence and policy identity. Context changes
invalidate old verification and decision eligibility; omitted fields preserve old case behavior.

The five Skill names, entry instructions, four diagnosis states and collector budget are unchanged.
The standalone collector's complete source tree and builder have no diff from `dfe326a`; its exact
16-file ZIP remains unchanged. The suite allowlist grows from 35 to 39 files solely for the carrier
validator, two schemas and the bundled contract. Test inputs and expected results are not packaged.

## Execution order and results

Terra and Luna completed and froze runtime, schemas, fixtures, tests and contract documents before
any tests, validators, syntax checks, package builds or new runtime commands were executed. Tests
were authored before implementation but were first run after completion, following the user's
explicit override of the ticket's intermediate-test wording.

The initial implementation's first final run under system Python ran 137 tests: 136 passed and one independent schema check was skipped
because `jsonschema` was unavailable. A project-local validation environment then supplied that
independent checker; no product implementation changed between those initial runs. Review corrections
were subsequently completed and frozen before another final validation run.

| Final command or check | Actual result |
| --- | --- |
| `.tools/carrier-m1/schema-venv/bin/python -B -W error::ResourceWarning -m unittest discover -s tests -v` | 141 tests passed in 64.528 seconds; no skips |
| Controller and carrier tests copied into an independent suite extraction | 62 tests passed in 29.510 seconds; no skips |
| `quick_validate.py` on the five Skill directories | Five passes |
| `python3 -B scripts/validate_real_pcap.py --out .tools/pcap-corpus/carrier-m1-validation` | Nine real capture cases passed, 20 checks per case |
| Two independent suite builds and sidecars | Byte-identical; 39 allowlisted files; all member hashes checked |
| Two independent standalone builds and sidecars | Byte-identical; 16 allowlisted files; unchanged baseline hash |
| Extracted collector/controller help/version, managed web-PCAP run/import and export | Passed with empty `PYTHONPATH`; no live collection; summary and artifact hashes checked |
| `git diff --check` | Passed |
| Final Sol standards and specification re-review at frozen `f244b65` | Both passed; zero open findings |

The suite includes ten carrier contract tests and six added public case tests, in addition to the
125-test baseline. Coverage includes structurally valid/invalid schemas, known/unknown measurements,
duplicate and unresolved references, unverified mappings, time skew, counter reset/wrap, unit/direction
gaps, source/hash declarations, metadata limits, legacy payloads, contextual policy invalidation,
transactional carrier imports, and FIFO/oversize public input rejection. The independent schema check
uses `jsonschema` Draft 2020-12; referential integrity and comparison rules are additional runtime
semantics documented in the bundled contract.

The first Sol review found that ordinary CLI inputs incorrectly inherited the stronger evidence
importer's `O_NOFOLLOW` requirement, blocking legacy commands on hosts lacking that primitive. It also
found that oversized arrays were expanded into the traversal stack before the node-budget check.
A standards reviewer identified an additional structural-contract discrepancy: Draft 2020-12 accepts
integral JSON numbers such as `1.0`, while the private runtime checker accepted only Python `int`.
All three findings were corrected in `f244b65`. Ordinary CLI JSON input now has its own bounded
regular-file reader with identity/change checks and optional platform flags; evidence import retains
its stronger confinement requirements. Traversal checks child and pending-node counts before queue
expansion and checks string budgets incrementally. Integral finite JSON numbers are accepted without
converting their supplied values; booleans, nonintegral and nonfinite values remain invalid.

New regressions cover the actual legacy CLI with `O_NOFOLLOW` hidden, symlink/changed input, bounded
allocation for a 500,000-element malformed array, and schema/runtime integer boundaries. The platform
check is a controlled local API simulation, not a native Windows run. The corrected final results
are in the table above. Sol independently confirmed that the ordinary CLI works with `O_NOFOLLOW`
hidden while checked imports remain guarded; the malformed-array reproduction used 584 additional
traced bytes rather than the original 36.2 MB; and runtime/schema integer acceptance agrees. These
are local controlled checks, not native-platform or production evidence.

The three original PCAPs and six generated variants remain under `.tools/pcap-corpus/downloads/`
and `.tools/pcap-corpus/derived/`, respectively. The existing pinned corpus manifest and provenance
remain authoritative. All nine diagnoses are still `insufficient_evidence`; visibility changes in
the generated captures do not prove network loss, cause or service recovery.

## Artifacts and reproducibility

The M1 suite candidate is `network-skill-suite-m1.zip`, SHA-256
`2fa0dadef0a8eed67aef4d49a7f40b7b1e258e36f4b4b600f2f259c8869df01a` (364,394 bytes).
The standalone `internet-access-triage-0.1.0.zip` retains SHA-256
`f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a` (209,807 bytes).
Both retain the current development version metadata; this milestone does not publish a new release.

The verification helper was run as:

```sh
M1_VERIFY_OUT=.tools/carrier-m1/review-fix-delivery \
  .tools/carrier-m1/schema-venv/bin/python -B .tools/carrier-m1/verify_delivery.py
```

It ran each builder twice into new directories with equal archive filenames, compared ZIP and manifest
bytes, checked the exact member lists and every hash, then extracted into a new temporary directory.
Only development test modules and their synthetic fixtures were copied beside that extraction for
testing; they are not archive members. The real-PCAP smoke used the extracted collector and controller
with a copied pinned web capture. Case export did not mutate state. This is independent extraction,
not an operating-system sandbox or host skill-discovery test.

Retained local evidence is under `.tools/carrier-m1/`: `full-suite-reviewed.log`, `skill-validators.json`,
`environment.json`, `validation-dependencies.json`, `schema-validator-install.json`, and
`review-fix-delivery/{delivery-verification.json,extracted-tests.log,build-a/,build-b/}`. Initial results
and first-round review reports remain separately retained. The PCAP results
are `.tools/pcap-corpus/carrier-m1-validation/validation.json`. These ignored local artifacts are not
part of the product packages.

## Dependencies and licenses

Validation ran on Linux/WSL2 with Python 3.14.7 and TShark 4.6.6. Product code remains Python 3.10+
standard library under the repository's Apache-2.0 license; optional collector tools retain their
existing declarations. TShark was invoked as an installed external tool and was not redistributed.

The following packages were installed only in `.tools/carrier-m1/schema-venv/` to independently check
JSON Schemas. Their installed metadata declares MIT licensing. None is bundled or required by the
incident runtime:

| Validation dependency | Recorded version |
| --- | --- |
| jsonschema | 4.26.0 |
| jsonschema-specifications | 2025.9.1 |
| attrs | 26.1.0 |
| referencing | 0.37.0 |
| rpds-py | 2026.9.1 |

To recreate the independent schema validation environment without changing product dependencies:

```sh
python3 -m venv .tools/carrier-m1/schema-venv
.tools/carrier-m1/schema-venv/bin/python -m pip install \
  jsonschema==4.26.0 jsonschema-specifications==2025.9.1 \
  attrs==26.1.0 referencing==0.37.0 rpds-py==2026.9.1
```

## Limits and remaining review

Inputs are synthetic contract records and operator-sanitized offline data. Hash relationships do not
authenticate sources, verify topology or prove effective redaction. The metadata validator does not
perform redaction, vendor parsing, conversion, diagnosis, device access or production operations.
No external messages, uploads, scans, polling, repairs or production probes were performed.

Actual vendor/version interoperability, network-practitioner terminology sign-off, native Windows,
MobileWork V-01/V-02/V-03, strict host isolation and external 43-static/17-dynamic security acceptance
remain unvalidated. These require their actual environments and approval records; none follows from
unit tests, local package extraction or the structural Skill validator.
