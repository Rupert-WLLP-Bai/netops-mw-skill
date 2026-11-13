# M1: carrier domain model and evidence contracts

## Scope and baseline

Implement [issue #5](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/5) only, from `main`
at `dfe326aac49c17ab3f88f4a82159411787e56ba0`, on `feat/carrier-m1-domain-contracts`.
The two documentation changes in [design PR #4](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/pull/4)
at `9ecc55570f89772717aad4b5ae38315a056b7ceb` are the design basis. That PR remains a separate draft;
the latest instruction requires milestone PRs to await review. No merge is part of this milestone.

Preserve the five existing Skill entry points, the four diagnosis states, the standalone collector's
16-file package, its 25-second budget, and the existing incident controller. M1 introduces contracts
and their validation, not vendor parsers, diagnostics, live access, notifications, or production actions.

## Contract decisions

- Define the 15 canonical object types listed in issue #5 and the six network layers in root
  `GLOSSARY.md`. Source-native identity is provenance, not a sixteenth inferred business object.
- Keep optional, explicitly versioned `service_context` on case creation and scope updates. Its
  registry contains pseudonymous local object IDs, source-qualified native identities, explicit
  unknown/ambiguous identity state, and topology links whose verification status is separate from
  confidence. Verified links require known endpoint identities.
- Place optional source context and carrier evidence inside the imported manifest's hashed bytes.
  Records reference existing evidence IDs and declared context objects. Import retains source
  context without assuming that it identifies the same service as the receiving case.
- Preserve event time, collection time, timezone, clock quality and uncertainty; raw units,
  direction, sample counts, denominator, sample interval and reset/wrap semantics; artifact hashes
  and the declared relationship between restricted originals and visible redacted artifacts.
  Hashes establish consistency, not source authenticity or successful sanitization.
- Accept valid incomplete observations without filling missing identities, units, thresholds, or
  mappings. A small pure comparison function reports why observations cannot be compared, including
  unit/direction mismatch, uncertain clocks, counter resets and unverified topology. It does not
  diagnose a fault or perform unit conversion.
- Omitted carrier fields preserve legacy behavior. An explicit context change increments policy
  identity and invalidates old verification and decision eligibility. Omission on update preserves
  the current context; explicit null removes it through the same guarded transaction.
- Bound the additive carrier data before semantic traversal: byte size, nesting depth, string
  length, object/link/record counts and traversal work. Use existing confined, nonblocking evidence
  reads; do not dereference new metadata paths or introduce file import adapters in M1.

## File changes and ownership

Terra owns the incident-private `case_runtime/carrier.py`, two bundled JSON Schemas, small integrations
in existing create/scope/import/decision/run/report paths, synthetic fixtures, compatibility and
negative tests, suite allowlist changes and their packaging assertions. The schemas describe structural
constraints; documented runtime semantics also check identity/reference integrity and comparability.

Luna owns root `GLOSSARY.md`, the bundled `references/carrier-evidence-contract.md`, and a short ADR
recording the additive incident-owned contract choice. The parent owns this plan, README links, final
validation/review records, package verification and the milestone PR. The original collector and its
standalone builder stay unchanged. No hidden benchmark answers or test fixtures enter either package.

## Implementation and final validation order

1. Inspect current contracts, all five Skill instructions and existing tests; agree field semantics.
2. Write compatibility, valid/unknown and invalid-data tests, then implement the complete M1 scope.
3. Finish all runtime, schema, fixture, test and contract-document edits before executing any tests.
   The user's explicit instruction overrides ticket wording that suggests intermediate test runs.
4. Freeze implementation, then run the complete existing and new test suite. Check independent
   JSON Schema validation, old evidence compatibility, duplicate identities, clock skew, counter
   reset, unit/direction mismatch, topology uncertainty and pseudonymous references. Verify public
   case persistence/import behavior, transaction rollback and recovery/decision invalidation.
5. Build the standalone collector and suite twice; verify archive/manifest hashes, exact allowlists,
   unchanged standalone bytes and independent extraction of all five entry points. Recheck the
   three original PCAPs and six variants with the existing offline validator.
6. Only after implementation and final checks, request Sol's independent standards/specification
   review. Record exact commands, counts, source commit, package hashes and actual platform limits.
7. Commit, push and open an independent M1 PR against `main`; stop for maintainer review. Do not
   close issue #5 as integrated, merge a PR, publish a release, or start M2 in this milestone.

If final validation finds a defect, finish that correction before rerunning the relevant final checks.
No intermediate red/green development loop is authorized. Native Windows, MobileWork V-01/V-02/V-03,
vendor interoperability, operator terminology sign-off and external security review require their
actual environments and remain unvalidated unless separately executed and recorded.
