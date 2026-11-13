# Carrier milestone completion tracker

The active user objective is to finish all seven carrier milestones through separate PRs and merge
their verified implementations. Earlier milestone prompts that required stopping before a merge are
superseded by that explicit authorization. Offline/device/production boundaries remain unchanged.

| Item | Authoritative state at this checkpoint | Remaining work |
| --- | --- | --- |
| Design PR #4 | Merged, `04587e2` | Historical design basis retained |
| M1 / #5 / PR #12 | Merged, `b2e7ee5`; source `f244b65`; 141 full and 62 extracted tests; final Sol pass | No implementation work remains |
| M2 / #6 / PR #13 | Merged, `147c2af`; source `f78c897`; 162 full and 83 extracted tests; final Sol pass | No implementation work remains |
| M3 / #7 / PR #14 | Merged, `4087d4e`; source `60e7e8b`; 185 full / 106 extracted tests, 12 cases and final Sol R3 pass | No implementation work remains |
| M4 / #8 / PR #15 | Merged, `8b210eb`; source `45a0743`; 210 full / 131 extracted tests, 12 cases and final Sol R3 pass | No implementation work remains |
| M5 / #9 | In progress on `feat/carrier-m5-service-acceptance` | Source-backed service acceptance/change review, synthetic cases, final checks and Sol review |
| M6 / #10 | Open | At least 36 scenarios, independent scoring, hidden/visible isolation and experiment validity |
| M7 / #11 | Open; user-owned validation execution deferred | Prepare versioned packages/hashes, prompts, acceptance criteria and evidence/document handoff; PR and merge |

Terra/Luna implement. Code, fixtures and contract documents freeze before any tests/builds or new
runtime checks; Sol reviews only after final verification. A review finding starts a new correction
phase, followed by complete relevant final checks and re-review. No passing result is inferred from
intent, a test inventory, a schema, or a package manifest alone.

The user explicitly deferred M7 validation execution and will perform it and prepare their acceptance
documents later. The local source-preparation index and handoff notes are under `.tools/carrier-delivery/`;
the user's client, native Windows and security results remain pending. Do not execute or claim native
Windows, actual MobileWork or external security acceptance. Their results remain pending user
validation, never prefilled as passed. Package preparation and engineering regression/build checks
remain separate from those acceptance runs. No operational publication or production access is
authorized by repository merge permission.
