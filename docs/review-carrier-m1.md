# Carrier M1 final review

Two independent Sol reviewers assessed corrected frozen source
`f244b65c995fc5cbf3b08fa8c4914d26b1ec2f84` against baseline
`dfe326aac49c17ab3f88f4a82159411787e56ba0`, including the correction diff from initial M1 source
`f2c1b73`. They read issue #5, its parent milestone boundary, and both design documents from PR #4
at `9ecc55570f89772717aad4b5ae38315a056b7ceb`.

Terra/Luna implementation and all corrections were complete before tests or review ran. Review
findings were routed back to Terra only after both initial reviews ended; corrections were frozen
and fully validated before this re-review. The parent finalized status documentation afterward;
packaged source bytes remain those reviewed. The [validation record](validation-carrier-m1.md)
contains commands, counts, package hashes, dependencies and actual platform limits.

The initial review found two P2 specification defects: an import-only OS requirement applied to
ordinary CLI input, and traversal allocation before budget enforcement. The standards reviewer also
reported a P2 JSON Schema integer acceptance discrepancy. All three were corrected and independently
rechecked. Initial reports and validation artifacts are retained under `.tools/carrier-m1/`.

## Standards

# M1 final Standards re-review

Reviewed frozen commit `f244b65c995fc5cbf3b08fa8c4914d26b1ec2f84` against `dfe326aac49c17ab3f88f4a82159411787e56ba0`, focusing on corrections since `f2c1b73`. The reviewed commit list contains `f2c1b73` and `f244b65`. The original report remains unchanged.

Applied the same repository standards: `AGENTS.md`, the three agent guides, root glossary and ADR 0001, M1 implementation plan and issue #5, five Skill entry points and their contracts, suite proposal and release allowlists. Repository requirements override the Fowler smell baseline.

**Documented-standard violations: none. Baseline smells: no material findings. Required corrections: none.**

The prior shared P2 integer-contract finding is closed. The schema interpreter now accepts finite integral JSON floats, preserves the supplied representation, and rejects booleans and fractional values. The new regression confirms runtime/schema agreement. The interpreter remains private and limited to the bundled schema subset; it makes no full JSON Schema compliance claim.

CLI input reading no longer requires platform-specific no-follow support. It bounds reads, rejects observed symlinks and special files, checks identity and metadata, and leaves the stronger imported-artifact confinement unchanged. The contract states the remaining race limitation when platform flags are unavailable and does not claim native Windows validation. Traversal now checks pending child counts before allocating their work-stack entries and checks string-byte limits incrementally.

Independently reran ten carrier-contract tests and three CLI input regressions: all 13 passed. Reviewed final logs record 141 full tests in 64.528 seconds and 62 extracted tests in 29.510 seconds, with no skips. Changed Python parses with Python 3.10 grammar; product additions remain standard-library code.

Independently verified both archive/manifest pairs reproduce exactly and every archived file matches its manifest and frozen source. Suite: 39 files, SHA-256 `2fa0dadef0a8eed67aef4d49a7f40b7b1e258e36f4b4b600f2f259c8869df01a`. Standalone: unchanged 16 files, SHA-256 `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`. Collector and standalone builder remain unchanged; fixtures, development dependencies and hidden answers are excluded.

**Verdict: Standards pass, zero open findings.** No maintained source edits or external actions were performed. The authorized milestone PR still requires maintainer review; merge and release remain with the maintainer.

## Spec

# Spec re-review — M1 / issue #5

Reviewed frozen `f244b65c995fc5cbf3b08fa8c4914d26b1ec2f84` against baseline `dfe326aac49c17ab3f88f4a82159411787e56ba0`, focusing on the correction diff from `f2c1b73`. The prior report is preserved.

**Verdict: pass. No unresolved material specification findings or new contract regressions identified.**

- **CLI compatibility finding resolved.** Ordinary input uses its own bounded regular-file reader. In a controlled local API simulation hiding `os.O_NOFOLLOW`, the real CLI successfully created a legacy case (return code 0). The same simulation confirmed `read_confined` still rejects an unavailable no-symlink primitive. Its import implementation is unchanged. This establishes the tested API behavior, not native Windows validation. The updated contract accurately describes the reader and remaining platform limits.
- **Traversal-budget finding resolved.** Container child counts are checked against pending work before stack expansion; string bytes are checked incrementally. Repeating the prior 500,000-item malformed-array reproduction rejected the input with only 584 additional traced bytes, compared with 36,168,112 before correction.
- **Integer parity correction verified.** Both the runtime and independent JSON Schema validator accept finite integral `1.0` for `sample_count` and preserve its supplied representation. Controlled runtime checks reject booleans, fractional values, negatives, NaN, and infinity. No new dependency enters the packaged runtime.

The full diff retains the 15 canonical object types, six layers, optional versioned context, provenance/missingness contracts, persisted context changes and policy invalidation. No vendor diagnostics, production actions, changed diagnosis states, or standalone-collector changes were introduced.

Reviewed final evidence records 141 full-suite tests and 62 extracted controller/carrier tests passing; two identical 39-file suite builds have SHA-256 `2fa0dadef0a8eed67aef4d49a7f40b7b1e258e36f4b4b600f2f259c8869df01a`. The unchanged standalone archive remains 16 files with SHA-256 `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`. These results do not establish MobileWork, native Windows, vendor, or external-security acceptance.

No maintained source was edited. Review ownership is released; integration still awaits maintainer review.

Standards: zero open findings. Spec: zero open findings. Maintainer review, merge and release remain
separate; neither automated verdict establishes native Windows, vendor, MobileWork or external security acceptance.
