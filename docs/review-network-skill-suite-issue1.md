# Network skill suite: final issue #1 re-review

Two independent Sol reviewers assessed frozen source `354b402a8cf41703ecf7c8e34f8a535d002d7ea5`
after implementation and all required source/package/real-PCAP checks finished. They reviewed the full
suite against base `1d197d143ff8efa92d6d4ce73f250c3a0317be8a`, prioritizing the four corrections
since checkpoint `376e65d`. Neither reviewer changed maintained files. The parent finalized status
documentation afterward; packaged source bytes remain those reviewed.

The [validation record](validation-network-skill-suite-issue1.md) contains the commands, actual counts,
package hashes and retained acceptance limits. The [original review](review-network-skill-suite-2026-11-13.md)
remains historical evidence for the four corrected findings.

## Standards

**Verdict: pass. No required standards corrections.** Reviewed frozen `354b402a8cf41703ecf7c8e34f8a535d002d7ea5` against `1d197d143ff8efa92d6d4ce73f250c3a0317be8a`, with particular attention to `376e65d..354b402`.

No documented-standard violations found. Sources were `AGENTS.md`, all three `docs/agents/` guides, the approved suite proposal, implementation plan, case contract, and historical review. No additional `CONTRIBUTING.md`, coding-standards file, root glossary, or ADR directory exists. English usage, Python 3.10+ standard-library implementation, one maintained controller, five self-contained skill folders, explicit deterministic packaging, and declared optional provider integration conform to those rules. The collector and standalone builder have no changes from the base. Inspected code contains no automatic capture, action dispatch, external messaging, installation, or ticket/device writes.

**Optional judgment call — possible Duplicated Code:** `skills/netops-incident/scripts/case_runtime/evidence.py:168–193` and `skills/netops-incident/scripts/case_runtime/recovery.py:120–146` repeat private staging, exclusive file creation, flush/fsync, no-replace publication, and rollback cleanup. Both hunks contain:

```python
rename_noreplace(stage, destination)
created.append(destination)
```

Consider extracting the common checked-byte publication/cleanup operation if these paths change again, keeping validation and event assembly in their current modules. This is a maintainability heuristic, not a documented-standard breach or release blocker.

Independent local verification: 2 skill-structure tests and 5 suite-release tests passed; all 11 changed Python files parsed with Python 3.10 grammar; all four new skill licenses exactly matched root `LICENSE`. No maintained files were changed by this review. Historical checkpoint warnings were evaluated as historical records, not current-code defects.

## Spec

Specification verdict: PASS for frozen `354b402a8cf41703ecf7c8e34f8a535d002d7ea5`, compared with `1d197d143ff8efa92d6d4ce73f250c3a0317be8a`, prioritizing `376e65d..354b402`. No material missing, partial, incorrectly implemented, or unrequested requirement was found within the authorized scope.

Read repository agent instructions, issue #1 and its complete comments response (none), the prior review/handoff, implementation plan, and both proposals. Reviewed controller, focused skills, packaging, restoration, tests, and validation changes. The original collector and standalone builder have no diff from the base.

All four issue requirements are addressed on their actual execution paths:

- Recovery eligibility follows the latest action/reconciliation through event revisions and action time (`recovery.py:162`). Independent persisted-case checks reject an older window even with identical timestamps, permit a new qualifying window, preserve historical checks, and gate a reopened prior-episode unknown action until reconciliation.
- Reservation preflight checks durable attempted-run payloads transactionally and requires the latest decision (`collection.py:64`). An interrupted reservation remains charged; its identical retry neither spawns nor mutates state. Reuse remains rejected after operation reconciliation; a newly recorded changed-condition decision permits another attempt.
- The confined reader opens the final descriptor nonblocking before testing regular-file status (`evidence.py:61`). A public FIFO-artifact import failed cleanly in 0.088 seconds with unchanged case/imports and an immediately available write transaction.
- Policy validation bounds every timing duration (`store.py:73`); window creation handles datetime overflow and recovery rejects nonpositive stored intervals (`recovery.py:72`, `:159`). Direct checks verified both supported bounds, subresolution/excessive rejection, overflow rollback, clean closure rejection, and available Markdown export for zero/inverted stored windows.

Additional local behavioral evidence is in `sol-spec-checks.json` and `sol-spec-timing.json`. Full-suite, package, extracted-runtime and nine-capture evidence supplied by the parent was inspected, not independently rerun here.

Strict R08 isolation, actual host discovery/invocation, native Windows and MobileWork remain explicitly unvalidated. This verdict grants no merge, publication, production-readiness claim, or external action.

Standards: zero required corrections, one optional duplication judgment call. Spec: zero findings.
The optional cleanup is deferred; neither axis requires another implementation change.
