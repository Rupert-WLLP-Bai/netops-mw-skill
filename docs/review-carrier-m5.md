# Carrier M5 final review

Independent Sol reviewers assessed frozen source `f1c8441c35e9bce53e7652c420380825ddd0bbac`
against merged M4 `8b210ebbdbe09f05933da831e126378b2b0a8981`. Runtime, tests, inputs and
packaged references froze before checks. Final evidence: 22 focused, 232 full and 153 clean-extracted
tests passed. The parent finalized these nonpackaged status records afterward.

Earlier review findings and failed/interrupted gates remain preserved in the
[validation record](validation-carrier-m5.md). Both final axes below are reproduced separately.

## Standards

# M5 independent final Standards attestation

Reviewed frozen `f1c8441c35e9bce53e7652c420380825ddd0bbac` against M4
`8b210ebbdbe09f05933da831e126378b2b0a8981`, using the three-dot diff,
nine-commit log and complete R4 Standards report.

Applied `AGENTS.md`, `docs/agents/*.md`, root `GLOSSARY.md`, ADRs 0001/0002,
README, M5 plan, packaged manual/provider and case contracts, inventory and
release allowlists. No separate CONTRIBUTING/coding-standards file exists.
Repository rules override the full Fowler heuristic baseline; tooling-enforced
issues are excluded.

**Standards PASS: zero material documented-standard violations; zero actionable
Fowler smell findings (judgment calls).**

R4 remains valid: `_criterion_roles` validates facts before complete or incomplete
matrix rows cite them, retaining independently valid direction facts. Supplied
instrument identities are validated independently of calibration policy. Optional
calibration metadata uses narrowly scoped authority, role and instrument-association
checks without manufacturing required calibration. These helpers serve current
requirements and do not introduce material duplicated validation or speculative
abstraction. Alias semantics, static/actual separation, bounded worker/CLI,
fixture-reference materialization and domain terminology remain consistent.

Inspected completed exact-freeze gate evidence:

- `service-check-f1c8441.log`: 22 tests, 119.129s, OK.
- `full-suite-f1c8441-resume2.log`: 232 tests, 366.278s, OK.
- `f1c8441-delivery-resume2/extracted-tests.log`: 153 tests, 326.587s, OK.
- `auxiliary-f1c8441.log`: eight Skill validators, Python 3.10 grammar,
  80 fixture hashes and 17 unique scenarios passed.

Independently checked archive bytes and member hashes against frozen Git blobs:
the suite has exactly the 61 allowlisted files, 698349 bytes, SHA-256
`6063112c2ec058f87b6f10f2a4ecf3f18835e8ee28ab0b7ceb9f732e6629d35c`.
Suite/standalone archives and manifests match their second builds; all eight
independent Skill packages match their second builds and frozen sources. The
original five Skill entries and collector tree are unchanged; the 16-file
standalone retains `f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a`.
Delivery evidence records managed offline PCAP compatibility without live collection.
Interrupted earlier logs are not passes.

HEAD and runtime/package/test sources still match the freeze; concurrent parent
documentation updates are outside these package checks. No maintained files were
edited or tests/builds/runtime probes rerun for this attestation. Standards is
independent of Spec. Actual MobileWork, native Windows and external-security
acceptance remain user-deferred to M7. Review ownership is released to the parent
for documentation and authorized delivery.

## Spec

# Final Spec attestation — M5 / issue #9

Reviewed frozen `f1c8441c35e9bce53e7652c420380825ddd0bbac` against M4 `8b210ebbdbe09f05933da831e126378b2b0a8981` (nine commits), complete issue #9 and its zero comments, the M5 plan, glossary, ADR 0002, provider/manual contracts, independent R4 report and preserved counterexample outputs, and final gate artifacts.

**Spec pass; zero material missing/partial requirements, scope creep, or wrong-behavior findings.** The independent R4 conclusion remains valid at this unchanged source: incomplete criteria omit role-invalid refs while retaining valid direction facts; an invalid supplied optional instrument blocks the affected test, while absent optional metadata creates no invented requirement. The R4 counterexamples were not rerun.

Whole-change consistency holds: approved inventories cover the 21 service/endpoint targets and all five capabilities in both absolute directions; scoped sourced mappings govern cross-source aliases; static authority remains separate from actual freshness. Tests retain source thresholds, methods, windows, instrument/calibration policy, full observation uncertainty, supporting refs and counterevidence. Change review requires selected-change approval association, usable pre-change plans and ordered postchecks. Human signoff remains pending; a blocked requested change blocks acceptance. The local draft/provider introduces no network, ticket, message, device or case mutation. Existing controller states, recovery eligibility, collector and 25-second budget remain preserved. Seventeen public scenarios include the eight required issue cases and positive controls.

Final exact-source evidence inspected:

- `service-check-f1c8441.log`: 22 tests / 119.129 seconds, OK.
- `full-suite-f1c8441-resume2.log`: 232 tests / 366.278 seconds, OK.
- `f1c8441-delivery-resume2/extracted-tests.log`: 153 tests / 326.587 seconds, OK.
- Delivery verification: suite 61 files / 698349 bytes, SHA-256 `6063112c2ec058f87b6f10f2a4ecf3f18835e8ee28ab0b7ceb9f732e6629d35c`; identical double builds/manifests, member hashes, eight independent packages, unchanged 16-file collector, and managed offline PCAP passed.
- `auxiliary-f1c8441.log`: eight validators, Python 3.10 grammar, 80 fixture hashes and 17 unique scenarios passed.

Earlier environment-interrupted runs remain preserved and are not passes. Actual M7 MobileWork, native Windows and external-security acceptance remain explicitly user-deferred. No maintained edits or test reruns performed. Review ownership released.

Standards: 0 remaining findings. Spec: 0 remaining findings.
