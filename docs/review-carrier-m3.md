# Carrier M3 final review

Two independent Sol reviewers assessed frozen source `60e7e8b697afd677c11185d594d6793ee1dbba32`
against merged M2 `147c2af0fb244cf913af105d148051bee316a679`. Corrections completed and all
code, test inputs and packaged references froze before final validation; these R3 reviews followed
185 full and 106 extracted tests passing. The parent finalized nonpackaged status records afterward.
See [the validation record](validation-carrier-m3.md) for actual commands, hashes and retained history.

Initial Standards findings were two P2s and one P3; initial Spec findings were three P2s.
R2 reported one shared remaining P2. All were corrected and independently rechecked in R3.
Earlier reports and failed-gate evidence remain retained rather than overwritten.

## Standards

# M3 final Standards re-review, R3

Reviewed frozen `60e7e8b697afd677c11185d594d6793ee1dbba32` against merged M2 `147c2af0fb244cf913af105d148051bee316a679`, focusing on `fc18225..60e7e8b`. Earlier reports and failed-check evidence remain preserved.

Applied the same standards sources: `AGENTS.md`, agent guides, glossary/ADR, README, roadmap/domain expansion, issue #7, M3 plan, six Skill entries, incident/carrier/ingestion/access contracts, and explicit release inventory/allowlist. Repository requirements override Fowler heuristics; tooling-enforced style is excluded.

**Verdict: Standards pass. Zero remaining documented-standard violations, required corrections, or material baseline-smell findings.**

The shared R2 P2 is closed. `_coverage_eligible` now requires a positive finite nonboolean sample count before enum, VLAN, and numeric branches. This changes coverage eligibility without converting categorical facts into numeric measurements. Source, resource, metric, comparison-field, and event-time compatibility checks are unchanged. Public categorical and VLAN controls retain `missing_reverse_direction` for null, zero, and `0.0`; compatible `1` and `1.0` controls satisfy coverage.

Independently repeated the three retained R2 cases, ten public categorical/VLAN controls, and five earlier contract reproductions. All passed: UTF-16/32 are rejected without stdout, UTF-8 succeeds, missing CRC counts remain explicit, and the PON result matches the corrected contract. Legacy JSON-reader defaults are preserved. Evidence is retained in `.tools/carrier-m3/standards-probes-r3/public-results.json` and `package-checks.json`.

Independently verified every suite/standalone member against frozen source and manifests, equal double builds, six individual Skill packages, all 30 fixture hashes, Python 3.10 grammar, standard-library imports and Apache licensing. Suite: 48 files, 477692 bytes, SHA-256 `d3d9d4e80f1ed5735edba9c2fabb97453ce3955bc9f666b4ace10f86d0342b9a`. Standalone: unchanged 16 files, SHA-256 `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`. Five original entries, controller defaults, 25-second collector budget and four states remain compatible. Synthetic fixtures, evaluator answers and private inputs remain outside packages and analyzer inputs.

Reviewed final logs record 185 full tests in 102.539 seconds and 106 extracted tests in 69.161 seconds, no skips, retained six structural validators, and managed-PCAP success. No maintained edits or external actions were performed.

Review ownership is released to the parent for authorized integration. Actual MobileWork, native Windows and external security acceptance remain user-deferred and unclaimed.

## Spec

# Spec re-review R3 — M3 / issue #7

Reviewed frozen `60e7e8b697afd677c11185d594d6793ee1dbba32` against M2 `147c2af0fb244cf913af105d148051bee316a679`, focusing on the correction after `fc1822542720bdf86f0774a949136d479d16cdbf`. Earlier reports and evidence remain preserved.

**Verdict: pass. All prior material findings are resolved; no new material specification regression identified.**

Independently repeated public CLI checks with actual M2-produced bundles:

- For both categorical application records and VLAN records, reverse observations with counts null, `0`, or `0.0` retain `missing_reverse_direction`; compatible counts `1` and `1.0` fill coverage. The uniform positive finite nonboolean count check now precedes both early returns. Adding another supported operation without its own compatible reverse observation still retains the gap, confirming coverage is not based on one global opposite-direction pair.
- The original contradictory optical case remains `insufficient_evidence`, emits neutral `optical_conflict` with actual counterevidence, and preserves `conflicting_observations` instead of optical degradation.
- Unsupported/null-valued reverse evidence cannot satisfy coverage. The original uncertain FEC comparison retains explicit `unknown_counter_semantics` and `missing_sample_interval` gaps without deriving a delta.

Retained results: `.tools/carrier-m3/sol-spec-r3-coverage.json` and `sol-spec-r3-reproductions.json`; the original-counterexample executable helper is `sol-spec-r3-reproduce.py`. The correction leaves strict UTF-8 handling, legacy reader defaults, both documented PON alternating sequences and independent Skill/provider behavior unchanged from the prior reviewed checks.

Reviewed final evidence records 185 full tests and 106 extracted tests passing; the 48-file suite, manifests and six individual archives reproduce. Suite SHA-256 is `d3d9d4e80f1ed5735edba9c2fabb97453ce3955bc9f666b4ace10f86d0342b9a`; the original 16-file collector remains unchanged. These are local/offline results and do not establish native Windows, MobileWork, vendor or external-security acceptance.

No maintained source was edited. Review ownership is released for the authorized verified-head PR/integration workflow.

Standards: zero open findings. Spec: zero open findings. Actual client, native Windows and external security acceptance remain user-deferred.
