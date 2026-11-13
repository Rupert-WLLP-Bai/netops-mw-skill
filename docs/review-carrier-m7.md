# Carrier M7 independent final review

Base: `cda64923918214325a9cb703b109160a2a5b80fc`. Reviewed head: `8c0966147bd548f9db63adff68e54e0da95a0c05`.
Both Sol reviewers released ownership before publication. The first Spec review's P2 layout
instruction was corrected by Luna and checked against the exact published commands before
re-review. Historical first-round reports remain in the local evidence directory.

The two Standards P3 suggestions are nonblocking maintenance work and are deferred during this
release-preparation closeout. Actual MobileWork, native Windows and external security execution
remain pending user acceptance, outside the amended implementation scope.

## Standards

# M7 final Standards review

Reviewed `git diff cda64923918214325a9cb703b109160a2a5b80fc...8c0966147bd548f9db63adff68e54e0da95a0c05`. The follow-up changes only the release guide setup paragraph and validation prose; the two code suggestions below remain applicable.

Documented standards: no hard breaches found. The changed repository documentation, code, comments and test descriptions use English (`AGENTS.md`), and preserve the established domain vocabulary and acceptance boundaries (`docs/agents/domain.md`, `GLOSSARY.md`, ADRs 0001–0002). No tooling-enforced concerns are reported.

Two nonblocking Fowler-baseline judgement calls:

1. **P3 — possible Duplicated Code**, `scripts/build_skill.py:44–63` and the changed manifest hunk at `scripts/build_suite.py:165` (with its surrounding publication transaction). The standalone builder repeats the suite's archive manifest construction, sidecar serialization and rollback sequence: `'files': [{'path': path, 'sha256': hashlib.sha256(data).hexdigest(), ...}]`, followed by `created = []`, two `write_exclusive(...)` calls and `for path in reversed(created): path.unlink(...)`. Future manifest or publication-policy changes must remain synchronized. Consider a shared helper for manifest creation and exclusive archive/sidecar publication, while retaining separate source selection. Sharing the existing allowlist/archive primitives already reduces duplication; this suggestion concerns the remaining repeated sequence.

2. **P3 — possible Duplicated Code**, `scripts/prepare_validation_inputs.py:194–220`, inside the generated materializer. Both `bounded_json` and `bounded_bytes` repeat `flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)`, descriptor opening, `fstat`, regular-file/size checks and `stream.read(MAX_BYTES + 1)`. Consider having `bounded_json` decode and parse the result of `bounded_bytes`, keeping JSON node/depth/deadline checks in `bounded_json`. This would give bounded file reading one maintenance point without adding a new abstraction.

No tests, builds, validators, probes or product execution were performed during this review. Actual MobileWork, native Windows and external security acceptance remain user-owned pending work.

Standards findings: **0 hard breaches; 2 nonblocking judgement calls. Worst within this axis: P3 Duplicated Code.**

Final Standards review ownership is released.

## Spec

# Spec review

**PASS — 0 findings; worst severity: none.**

Reviewed the frozen M7 change `cda64923918214325a9cb703b109160a2a5b80fc...8c0966147bd548f9db63adff68e54e0da95a0c05` against complete Issue #11 and its empty comment history, the M7 plan, release guidance, and user amendments. This was read-only source and retained evidence inspection; no tests, builds, validators, probes, or product execution performed.

- **Missing or partial requirements:** 0 findings within the amended preparation scope.
- **Scope creep:** 0 findings.
- **Implemented incorrectly:** 0 remaining findings. The original P2 setup instruction is corrected: the guide now places the extracted incident directory inside the handoff root, beside `validation-inputs/`, matching every published command. Retained `layout-v3/result.json` and `commands.json` record execution of all six commands, normal conformance, missing-reverse uncertainty, malformed-input rejection, and pending human signoff. Two fresh 103-file handoffs match; only guide prose and its checksum ledger differ from the earlier verified delivery. All nine archives and manifests retain identical bytes.

Explicit package allowlists, versioning, source/member hashes, dependency/license records, standalone extraction, portable inputs, pending security criteria, and manual-only expert routing satisfy the amended release scope. The original collector archive hash and runtime/controller boundaries remain preserved. The existing 264-test source and 153-test extracted-runtime evidence continues to apply to unchanged code and package bytes.

Actual MobileWork, native Windows, and external security execution remain user-owned and pending. No native expert archive, orchestration API, external publication, or actual client/platform/security pass is asserted. The private Word layout remains a separately finalized deliverable outside this frozen source review.

The first report is preserved as `.tools/carrier-m7/sol-spec-r1.md`. Review ownership released to the coordinating agent; no source or gate ownership retained.

Standards: 0 hard breaches, 2 nonblocking judgement calls (worst P3); Spec: 0 remaining findings
(worst none). These are independent axes, not a combined severity ranking.
