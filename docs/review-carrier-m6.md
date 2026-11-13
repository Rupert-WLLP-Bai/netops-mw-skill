# Carrier M6 independent review

Base: `6a7eed154889d44a089f9c7fead1f0ed55aa0084`. Reviewed source: `7fa33a399e6c2ef25727b5ecaf8fdafc35fe5457`.
Luna implemented; independent Sol agents reviewed Standards and Spec after all final gates.
The R1 P2 evidence-membership defect was corrected before R2.

## Standards

Reviewed `6a7eed154889d44a089f9c7fead1f0ed55aa0084...7fa33a399e6c2ef25727b5ecaf8fdafc35fe5457`, including the commit list, changed source/tests/documentation and recorded gates. R2 inspected the scoring correction, two new regressions and validation update against the previously reviewed full diff. Review was read-only; no tests, builds, imports, provider calls or isolation probes were executed.

Documented standards: **pass**. No hard violations found against `AGENTS.md`, `docs/agents/{issue-tracker,triage-labels,domain}.md`, `README.md`, `GLOSSARY.md`, or ADRs 0001/0002. English, domain terminology, additive carrier boundaries and source-qualified alias semantics remain consistent. No finding concerns formatting already checked by tooling.

- **P3, nonblocking judgment — possible Duplicated Code:** `evaluation/carrier/adapter.py:135–151` repeats the task/job schema validation in `evaluation/carrier/contract.py:101–125`, although the adapter already imports `contract`. Both hunks check `set(task) != {'schema_version', 'task_id', 'prompt', 'jobs'}` and validate the same job fields. The copies already differ: the adapter caps prompt/ticket strings at 32,768 and accepts boolean schema version `True`; the shared contract uses `MAX_STRING` and explicitly rejects booleans. Maintaining two definitions makes future contract changes require coordinated edits. Reuse `contract.validate_task` for the common structure, then retain clearly named adapter-specific size and visible-path checks. This is a maintainability heuristic, not a documented-standard breach or a failure of the measured 36-case corpus.

The R2 correction uses `actual_support <= actual_refs` (`evaluation/carrier/scoring.py:87`) to require every supplied support reference to belong to the current job. The new test inputs separately cover fabricated and other-job references, preserving state/recall while denying grounded credit. No new documented-standard violation or substantive baseline smell was found.

The validation record reports 259 passing tests across 18 modules, 12 focused scoring tests and fresh 36-case/44-job restricted execution with 36 replay matches. It retains citation/coverage limitations and distinguishes completed gates from unexecuted lab/M7 acceptance. Unchanged packaged sources retain the recorded v9 package/extracted-runtime evidence. This review makes no broader host-security certification claim.

Standards totals: **0 hard violations; 1 nonblocking judgment finding. Worst within Standards: P3 duplicated task validation.**

## Spec

Reviewed frozen `7fa33a399e6c2ef25727b5ecaf8fdafc35fe5457` against merge-base `6a7eed154889d44a089f9c7fead1f0ed55aa0084`, retaining the complete Issue #10 (zero comments), M6 plan, evaluation guide, adaptation notes and lab-plan requirements. This was a read-only source/document review; no tests, builds, imports, probes or providers executed.

**No current Spec findings.** No missing/partial requirements, unrequested behavior or incorrectly implemented requirements identified.

The R1 P2 is resolved at `evaluation/carrier/scoring.py:87`. Grounding now requires both the complete claim-specific required set and membership of every supplied support reference in that job's independent index. This satisfies “Complete claim-specific support set, with every ref independently present in that job's evidence” (`docs/carrier-evaluation.md:47`). The two added controls cover fabricated extra references and references present only in another job's index; each denies grounding, grounded-class and layer credit while preserving independent state and claim-recall scores. The correction changes no provider, fixture or hidden truth.

The complete scope remains satisfied: 36 cases in the required six exclusive groups; independently authored parent-only truth; inherited restricted worker execution; separate dimensions, completion and unknown cost; canonical replay; and six-stage captured-experiment validation. Local injection plans remain unexecuted and M7 actual-client/native-Windows/security execution remains explicitly user-deferred.

The updated validation record reports 12 focused scoring tests and 259 full tests across 18 modules; 36 cases/44 completed valid jobs; and fresh replay of 36 cases with zero mismatches. Unchanged packaged sources retain the recorded 153 fresh-extracted-test and reproducible-archive evidence. Measured baseline counts remain candidly disclosed: state 34/34; service axes 10/10; class/layer 28/28; claims 336/349; grounding 78/334; counters 12/21. These limitations were not hidden by weakening the oracle.

**Spec total: 0 current findings; worst: none. R1 P2 closed.**

Standards: 0 hard violations, 1 nonblocking judgment (worst P3); Spec: 0 current findings (worst none).
