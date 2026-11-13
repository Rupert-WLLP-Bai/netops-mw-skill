# Carrier M3 initial validation gate

This report records the initial local engineering verification for issue #7 at source commit `5cfc8e2`. It covers offline access analysis, the standalone `telecom-access-diagnostics` Skill, and suite packaging. Subsequent Sol Standards and Spec reviews found three required corrections and reopened implementation. The figures and package hash below are initial-gate evidence only; final correction-phase verification and review results are pending and must be recorded separately. This report does not establish MobileWork, native Windows, vendor interoperability, live-network, or external-security acceptance.

## Final results

| Initial-gate check | Result |
| --- | --- |
| Full repository suite | 178 tests passed in 92.143 seconds; see `.tools/carrier-m3/full-suite.log` |
| Clean extracted suite | 99 tests passed in 51.129 seconds; see `.tools/carrier-m3/delivery-fixed-helper/extracted-tests.log` |
| Skill structural validation | All six Skills passed; see `.tools/carrier-m3/skill-validators.json` |
| Python compatibility | Changed Python modules parsed with Python 3.10 grammar |
| Suite archive | Two builds and manifests were identical; 48 files; SHA-256 `8da40b4d643a44aa4b01763e1f9364abffbb8d281544a5eba1d8b4dfa6003807` |
| Independent Skill archives | All six builds were reproducible; archive hashes and member counts are in `.tools/carrier-m3/delivery-fixed-helper/delivery-verification.json` |
| Standalone Internet collector | Unchanged 16-file archive; SHA-256 `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a` |
| Managed PCAP regression | Passed for retained capture SHA-256 `92e06382a4f2e12bd569a104ceeecf908b89ccdb801f3dc4ae430b0f1a967f9b`; no live collection |

The initial delivery manifest records that all archive member hashes were checked and both combined suite builds and manifests were identical. The package contains no M3 evaluator oracle or synthetic case source inputs. Do not treat this hash as the corrected release hash.

## Latest correction-gate attempt

After the Sol-driven corrections, the next full-suite run executed 183 tests in 102.592 seconds and failed one test: `test_reverse_direction_requires_same_supported_operation_and_scope`. The independent extracted run executed 104 tests in 68.256 seconds and failed the same assertion. Both logs show the expected `missing_reverse_direction` gap remained because the new positive reverse-direction input had `sample_interval_seconds: null`, while its ingress baseline declared 60 seconds. The analyzer correctly treats those fields as incompatible, so the test input did not satisfy its own no-gap expectation.

Terra will correct only that positive test input to use a 60-second interval, preserving the assertion that the compatible pair removes the gap and retaining a separate incompatible-interval negative case. No expected product result is being changed to force a pass. This correction-gate attempt remains failed; rerun results, package verification, and final review are pending. Evidence is retained in `.tools/carrier-m3/full-suite-reviewed.log` and `.tools/carrier-m3/delivery-reviewed.log`.

## Review findings and correction phase

The initial Sol reviews identified four P2 issues and one P3 contract mismatch: contradictory optical observations were omitted instead of retained as counterevidence; unsupported or missing observations could falsely satisfy reverse-direction coverage; strict UTF-8 decoding was missing on the new request path; counter semantics, sample-count, and interval gaps could disappear; and the provider documentation described only up/down/up although down/up/down was also accepted. The sampling-gap finding appeared in both review tracks. Terra owns the implementation and tests for these findings. The access contract and manual Skill reference now reflect the agreed correction semantics. Final implementation verification and Sol re-review are pending; no pass is claimed for the corrected head.

## Delivery helper correction

The first delivery verification failed after the full test suite had ended. Its archive verifier reused a mutable `ZipInfo` object and changed in-memory read offsets; Python's ZIP reader then reported mismatched member names and headers. The helper was corrected to use `copy.copy` for the entry before reading it. No product source changed for this correction. The original failure is retained in `.tools/carrier-m3/delivery.log`; the rerun and passing delivery record are in `.tools/carrier-m3/delivery-fixed-helper.log` and `.tools/carrier-m3/delivery-fixed-helper/`.

## M3 behavior and evidence scope

The developer fixture set contains twelve deterministic, self-authored synthetic scenarios and a separate evaluator-only oracle. Cases cover profile-backed optical trends, ordered PON flaps, normal optical evidence as Wi-Fi counterevidence, stale evidence and missing profile, reset counters plus neutral counter increments, an otherwise plausible flap blocked by unverified topology, authentication rejection, AAA acceptance as DHCP counterevidence, DHCP pool exhaustion, VLAN mismatch, one-way application failure, and unknown clock quality. The harness creates sanitized M2 run bundles and resolves the request before invoking the analyzer; it passes no oracle labels to the analyzer. The case directories are test inputs, not an OS isolation boundary, live LLM evaluation, or proof of actual-client behavior.

The provider consumes checked local M2 evidence and M1 topology bindings. It emits only `fault_observed` or `insufficient_evidence`; it does not emit healthy or reproduction conclusions. Findings keep `resource_id` null and do not attribute a fault to a mapped device. The synthetic profile limit is test data, not a universal or vendor optical threshold.

## Dependencies and platform limits

Packaged M3 provider and Skill code use the Python standard library. Any independent schema-validation dependency was confined to the existing M1 validation environment and is not a packaged runtime dependency. Validation ran locally under Linux on WSL2. The results do not establish native Windows behavior, execution in the actual MobileWork client, compatibility with vendor-specific exports, or external security acceptance. Those user-owned M7 validations remain pending.

## Retained evidence

- `.tools/carrier-m3/full-suite.log` — final repository suite output.
- `.tools/carrier-m3/skill-validators.json` — all six Skill validation results.
- `.tools/carrier-m3/delivery-fixed-helper/delivery-verification.json` — final package hashes, member counts, archive checks, extracted-suite result, and managed PCAP record.
- `.tools/carrier-m3/delivery-fixed-helper/extracted-tests.log` — clean extracted-suite output.
- `.tools/carrier-m3/delivery.log` — preserved initial delivery-helper failure.
- `.tools/carrier-m3/delivery-fixed-helper.log` — corrected delivery rerun output.
- `.tools/carrier-m3/sol-spec.md` and `.tools/carrier-m3/sol-standards.md` — initial independent review reports.
- `.tools/carrier-m3/sol-spec-reproduce.py`, `.tools/carrier-m3/sol-spec-reproductions.json`, and `.tools/carrier-m3/standards-probes/` — retained local review reproductions.
