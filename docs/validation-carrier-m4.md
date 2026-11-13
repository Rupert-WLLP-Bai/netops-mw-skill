# Carrier M4 validation

This record covers issue #8 from merged M3 `4087d4e`. The final R3 engineering gate passed on frozen
source `45a0743`. Both final Sol R3 reviews passed with zero remaining findings; see
[the separate review axes](review-carrier-m4.md). No MobileWork, native Windows, vendor or
external-security acceptance is claimed.

## Initial final-gate results

- Full suite: 204 tests in 120.526 seconds, failed with five failure records.
- Extracted suite: 125 tests in 87.941 seconds, failed with four failure records.
- Seven Skill structural validators, Python 3.10 grammar checks, and 30 fixture provenance hashes passed.
- The combined suite contains 55 allowlisted files and seven Skill roots. The initial extracted
  runtime failure prevented the delivery harness from reaching its managed-PCAP step.

One full-suite failure came from the transport Skill's cross-Skill relative Markdown link, which
violated independent installation. Its own manual reference remains locally linked; the discovered
optional provider's bundled contract is now named in plain text without an assumed installation path.
The same correction was applied to the standalone manual reference.

Four failures repeated one profile-source authoring problem in queue/QoS cases 005 and 006: the source
contained denominator `1`, but its explicit configuration allowed only unit `%`. M2 correctly rejected
the undeclared denominator. The configuration now includes the supplied denominator unit and its
provenance hash is updated. Source observations, strict ingestion rules and oracle expectations were
preserved. No expected result was changed to conceal a product failure.

Initial evidence is retained in `.tools/carrier-m4/full-suite.log`, `delivery.log` and
`skill-validators.json`. Corrections completed and froze before the next final gate. Product/provider
code uses the standard library under Apache-2.0. Inputs are self-authored synthetic Apache-2.0 data;
source and evaluator answers are excluded from product archives. These developer checks do not prove
OS oracle isolation, live LLM quality, vendor interoperability, native Windows, MobileWork or external
security acceptance. Actual M7 client/platform/security execution remains user-deferred.

## Second gate and reference correction

After the link/config correction at `1e025c5`, the full suite ran 204 tests in 121.396 seconds and
the extracted suite ran 125 tests in 88.269 seconds; each retained three failures in queue/QoS checks.
Parsing succeeded, but intended source rows 10 and 11 were referenced using decimal-looking IDs.
The existing M2 producer uses `format(index, '012x')`: those records actually have IDs ending `00a`
and `00b`. Their unresolved declarations correctly withheld service-pass counterevidence and class
association. The request bindings, oracle reference metadata and focused-test references now identify
the same intended source records by their actual IDs. Semantic statuses, codes, localization levels,
gaps and source values were preserved; the runtime was not weakened to accept nonexistent references.

The failed logs remain `.tools/carrier-m4/full-suite-corrected.log` and `delivery-corrected.log`.
Fixture hashes were refreshed after the reference correction, and all owned changes froze before
the next gate. Corrected final results and independent review remain pending.

## Post-review test setup correction

The first renewed gate after the Sol fixes at `a591ce0` ran 210 full tests in 163.005 seconds and
131 extracted tests in 129.860 seconds. Both ended with three setup errors: three new multi-variant
tests called the exclusive baseline fixture initializer repeatedly under the same temporary root.
The second call correctly refused the existing `topo1-src` path. Each test now creates its immutable
baseline once and deep-copies the request for its independently named variants. Assertions, fixture
exclusivity and product runtime code are preserved. The error logs remain
`.tools/carrier-m4/full-suite-reviewed.log` and `delivery-reviewed.log`; the next gate follows a new freeze.

## Pre-review gate completed; Sol corrections required

Before the independent Sol reviews, the final gate passed: 204 full-suite tests and 125 extracted
tests. The reproducible 55-file suite archive had SHA-256
`55758687166ce515bd95856d7dbf763c6eed385fed952fef81729f7614ee5daa`. Seven Skill validators,
package/hash verification, and managed-PCAP compatibility also passed. Evidence is retained at
`.tools/carrier-m4/full-suite-final.log`,
`.tools/carrier-m4/final-delivery/extracted-tests.log`,
`.tools/carrier-m4/delivery-final.log`,
`.tools/carrier-m4/final-delivery/delivery-verification.json`,
`.tools/carrier-m4/skill-validators-corrected.json`,
`.tools/carrier-m4/final-delivery/build-a/network-skill-suite-m4.manifest.json`, and
`.tools/carrier-m4/final-delivery/build-b/network-skill-suite-m4.manifest.json`.

The independent Standards review identified two P2 findings and the Spec review identified four
P2 findings. Corrections are now in progress; this successful gate does not cover them. Renewed
full/extracted checks, package/provenance/managed-PCAP verification, and independent Sol review
remain pending. Earlier failed gate records above are preserved.

## R2 pre-review gate and corrections required

After the first correction pass at `c7625bf`, a pre-R2 gate passed 210 full-suite tests and 131
extracted tests. The reproducible 55-file suite archive had SHA-256
`de814a87a24a9390aa6a4ce4a63d260a38b137a4d0900628ac87467841d8588e`; seven Skill validators,
package/hash verification, and managed-PCAP compatibility also passed. Evidence is retained at
`.tools/carrier-m4/full-suite-isolated.log`,
`.tools/carrier-m4/isolated-delivery/extracted-tests.log`,
`.tools/carrier-m4/isolated-delivery/delivery-verification.json`,
`.tools/carrier-m4/delivery-isolated.log`,
`.tools/carrier-m4/skill-validators-reviewed.json`, and the two build manifests under
`.tools/carrier-m4/isolated-delivery/build-{a,b}/network-skill-suite-m4.manifest.json`.

The R2 Standards review found one P2: categorical `profile_aggregation` conflicts were filtered by
optional unit labels. The R2 Spec review found two P2s: applicable profile changes during the used
measurement window were missed, and an observed cumulative decrease could be skipped while deriving
an outer delta. Findings and reproductions are retained in `.tools/carrier-m4/sol-standards-r2.md`,
`.tools/carrier-m4/sol-spec-r2.md`,
`.tools/carrier-m4/standards-probes-r2/profile-aggregation-units.json`,
`.tools/carrier-m4/sol-spec-r2-profile-window.json`, and
`.tools/carrier-m4/sol-spec-r2-counter-decrease.json`.

The c7625bf gate is a successful pre-review result only; it does not cover these R2 findings. Their
corrections are in progress. Renewed full/extracted checks, validators, package/provenance/managed-PCAP
verification, and independent Sol review remain pending. Earlier failed gate records are preserved.
Actual M7 MobileWork, native Windows, and external-security validation remains user-deferred.

## R3 final engineering gate and independent reviews passed

After the R2 corrections, the final R3 gate passed on frozen source `45a0743`. The full suite ran 210
tests in 155.627 seconds with no failures or skips. The extracted delivery suite ran 131 tests in
120.791 seconds with no failures or skips. Seven Skill validators passed; Python 3.10 grammar checks
and all 30 fixture provenance hashes passed.

The reproducible suite archive contains 55 files, is 557675 bytes, and has SHA-256
`87a53b62eef075c5057bc25539fbb8b4e0e726dd07b6617ffb9c09188d380f83`. Both suite builds and their
manifests were byte-identical, and all per-file hashes were checked. All seven individual Skill
archives and manifests were produced in duplicate builds. The original 16-file
`internet-access-triage` archive remains SHA-256
`f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`. The managed PCAP compatibility
check passed with its prior input hash `92e06382a4f2e12bd569a104ceeecf908b89ccdb801f3dc4ae430b0f1a967f9b`;
the delivery record reports `insufficient_evidence` and confirms no live network collection.

Authoritative R3 evidence is in `.tools/carrier-m4/full-suite-r3.log`,
`.tools/carrier-m4/delivery-r3.log`, `.tools/carrier-m4/auxiliary-r3.log`, and
`.tools/carrier-m4/skill-validators-r3.json`. Duplicate suite builds, the extracted-test log,
delivery verification, and seven individual Skill build archives/manifests are under
`.tools/carrier-m4/r3-delivery/` (`build-a/`, `build-b/`, `individual-a/`, and `individual-b/`).

The schema-venv quick-validator attempt first stopped because that environment lacked the `yaml`
module. Only the auxiliary validator was rerun, using `/usr/bin/python3` with PyYAML 6.0.3; the
recorded seven validators, Python 3.10 grammar check, and 30 fixture hashes passed. This was an
environment-only validation adjustment; no runtime or product files changed for it. The R3 engineering
gate is complete. Both independent Sol R3 reviews passed at the same frozen source, with zero remaining
findings per axis. Reports and focused public CLI evidence are retained under
`.tools/carrier-m4/sol-standards-r3.md`, `sol-spec-r3.md`, `standards-probes-r3/`, and
`sol-spec-r3-*`; the reports are reproduced separately in the linked final review. Earlier failed-gate
and review correction records above are preserved. Actual M7 MobileWork, native Windows, and external-security
validation remains user-deferred.

