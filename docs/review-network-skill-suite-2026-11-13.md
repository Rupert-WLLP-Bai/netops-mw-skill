# Final review: network skill suite

> Transfer note: this report reviews the frozen implementation at `44dbedf`. The handoff evidence bundle retains the exact original reproduction as `reproduce-original.txt` and supplies `reproduce-portable.py`, which uses a fresh temporary directory. Restore the evidence bundle using [the handoff instructions](HANDOFF-2026-11-13.md) before running it. The original review cases and SQLite files are not distributed; the portable script regenerates them temporarily.

Reviewed branch `feat/network-skill-suite` at frozen HEAD `44dbedf3b714e5b4d9bb18ce365d0db12baf4167`, against base `1d197d143ff8efa92d6d4ce73f250c3a0317be8a`, on 2026-11-13.

**Verdict: changes required before treating the controller as ready.** Four reproducible specification defects remain: one P1 false-recovery path and three P2 enforcement/input-handling defects. The existing tests and packaging checks pass, but do not cover these paths. This review does not block preserving the branch and evidence as an explicitly unfinished cross-machine checkpoint.

No maintained source or tests were edited, no commits were made, and no tools, downloads, network probes, production actions, external writes, or subagents were used. Review-generated files are confined to `.tools/network-suite/sol-review/`.

## Standards

Read root `AGENTS.md` and `docs/agents/domain.md`; no root `GLOSSARY.md` or `docs/adr/` directory exists. This review did not handle tickets or classify/change triage labels. Documentation, comments, code, test descriptions and reports in the change use English. The controller has one maintained private implementation, and focused skills use documented optional provider discovery rather than sibling imports. The suite uses a deterministic explicit file allowlist. The legacy collector and `scripts/build_release.py` have no diff against the base.

No separate material documented-standard breach or maintainability finding is required. The specification findings below concern observable behavior rather than stylistic preferences.

## Specification: required fixes

### 1. P1 — A later action can reuse a verification window that ended before the action

**Location:** `skills/netops-incident/scripts/case_runtime/recovery.py:56`, `:155`, and `:220`.

`record_action` appends an action without invalidating prior verification eligibility. Closure selects checks by episode, policy, scope and window identity, but never requires their observation window to follow the latest relevant action. A legal transition back through investigation and awaiting action can therefore record a new completed action and then close recovered using only earlier observations.

**Reproduction:** `python3 -B .tools/network-suite/sol-review/reproduce-portable.py`, result `pre_action_window`. Using the supported injectable clock and actual persisted case operations:

1. Create a complete policy; enter verification, start a one-second window and record an independent passing check at `00:00:00.100000Z`.
2. Return to investigating with a recorded permitted decision and remaining budget, then enter awaiting action.
3. Record a completed proxy configuration change at `00:00:02Z`.
4. Enter verifying and stabilizing, then close at `00:00:03Z`, without starting another window or recording another check.

**Observed:** status becomes `closed_recovered`; the only window ended at `00:00:01Z` and every check predates the action. This can declare recovery after a new service-affecting change without any evidence of the resulting service behavior. Existing freshness checks do not prevent it while old checks remain within the freshness allowance.

**Requirement:** the approved proposal's action/verification journey requires a fresh original-flow check after the owner action; the plan's review focus 4 forbids recovered closure when original-flow evidence for the reported action is missing.

**Required correction:** bind eligibility to the latest relevant recorded action/reconciliation or invalidate previous verification attempts when such an action is recorded. Require a current post-action window and qualifying post-action observations. Preserve spontaneous recovery when no action was recorded, prior failures, and history. Add a regression covering the legal transition sequence above.

### 2. P2 — New run events bypass the repeated-test/no-progress guard

**Location:** `skills/netops-incident/scripts/case_runtime/collection.py:64` and `skills/netops-incident/scripts/case_runtime/evidence.py:216`.

The repeated-test guard exists only when recording a new decision. Run preflight accepts any matching stored decision with a next test; it does not record that the decision's test was attempted or reject its reuse. Two distinct `run` event IDs and output directories can therefore invoke the same test under the same decision without a changed condition or new discriminating test.

**Reproduction:** result `repeated_test` in the same script. One decision authorizes inspection of the same local capture. A local fake provider records every invocation and emits a compatible version but no collection output. Two investigation runs reference that single decision with otherwise identical inputs.

**Observed:** provider invocation log is `version, collect, version, collect`; both operations settle and the remaining rounds fall from 3 to 1. The case still contains exactly one decision and no changed condition. This is distinct from an identical event retry, which is correctly idempotent. With live mode the same hole can repeat approved network collection; finite budgets still limit the total.

**Requirement:** Task 2 and the approved bounded-loop design require refusing an additional identical test unless a changed condition or a new discriminating test explains information gain.

**Required correction:** persist the relationship between an attempted operation and the decision/test, and enforce reuse checks transactionally before reservation and spawn. A repeated operation must need a newly recorded meaningful decision/change condition, while an identical event retry remains harmless. Add a regression using a new event ID and the already-used decision.

### 3. P2 — A FIFO blocks the bounded evidence reader before the regular-file check

**Location:** `skills/netops-incident/scripts/case_runtime/evidence.py:61`.

The final source path is opened with blocking `O_RDONLY` before `fstat` verifies that it is regular. On POSIX, opening a named pipe with no writer blocks indefinitely. The file-size and regular-file guards are never reached. `import-run` calls this reader inside `BEGIN IMMEDIATE`, so a named pipe in a summary or referenced artifact can hang import and hold the case write transaction; the same reader is also used by verification and managed-output import.

**Reproduction:** result `fifo_read` creates a named pipe beneath the permitted source directory and calls `read_confined(root, 'pipe', 1024)` in a subprocess.

**Observed:** the subprocess exceeds the one-second deadline and must be killed by the reproduction harness; it does not promptly reject the nonregular source. There is no controller timeout around this read. This is a local malformed-input path, not a claim of remote exploitation.

**Requirement:** Task 2 requires checked, bounded source reads and rejection of nonregular sources; managed collection must also remain bounded through result handling.

**Required correction:** open the final descriptor without blocking on special files (for example using supported nonblocking flags), then reject nonregular files before reading. Preserve descriptor-based no-symlink/confinement checks. Add a public import regression with a named-pipe summary or artifact and assert prompt failure without state change or retained transaction.

### 4. P2 — Accepted positive finite durations can produce a zero-length verification window

**Location:** `skills/netops-incident/scripts/case_runtime/store.py:67`, `skills/netops-incident/scripts/case_runtime/recovery.py:72` and `:179`.

Policy validation accepts every positive finite duration, but Python `timedelta` has microsecond resolution. `window_seconds: 1e-20` passes validation and rounds to zero when verification starts. The stored window therefore has identical start and end. Once a qualifying check at that timestamp exists, coverage calculation divides by zero. `ZeroDivisionError` is not converted into a CLI validation error; closure and Markdown export can fail with a traceback.

**Reproduction:** result `tiny_window` creates the accepted policy, starts verification and records a check using the supported clock injection.

**Observed:** both stored endpoints equal `2026-11-13T00:00:00.000000Z`; `recovery_gaps` raises `ZeroDivisionError: division by zero`.

**Requirement:** the plan explicitly requires valid positive timing ranges and finite numeric coverage. An accepted plan must produce a positive representable observation window and a defined coverage calculation.

**Required correction:** validate representable duration bounds and ensure the constructed end is later than the start before committing a window; reject unsupported ranges cleanly. Consider the corresponding finite values too large for `timedelta`/`datetime`, and protect export/closure from invalid stored intervals. Add a regression for a positive duration below clock resolution.

## Verification evidence

- Fresh full test run: `python3 -B -m unittest discover -s tests -v` — **119 tests passed in 48.672 seconds**, exit 0. Full output: `unittest.log`.
- Fresh creator structural validation — all five skill folders returned exit 0 and `Skill is valid!`. Results: `verification.json`.
- Two fresh independent suite builds and sidecars are byte-identical. Archive SHA-256: `c8a91b58ee56d73a882b103bc141187728ef881ca5088d4eb9dc1c05fefeb3da`, matching the delivery record. Evidence summaries: `build-a.json`, `build-b.json`, and `verification.json`; the build ZIPs can be regenerated from the reviewed source.
- Direct comparison confirms no branch changes to the legacy collector or standalone release builder. Maintained working tree remained clean.
- Ran the four focused reproductions against the actual controller modules, SQLite cases, local fake provider, local artifacts and POSIX named pipe. Original script: `reproduce-original.txt`; safe transferable adaptation: `reproduce-portable.py`; exact reviewed outcomes: `repro-results.json`. The review cases are regenerated in temporary storage and are not transferred. The lifecycle/numeric reproductions use the same supported injectable-clock approach as the maintained tests; no business service recovery was simulated as fact.
- Inspected the preexisting real-PCAP validator JSON itself: `passed: true`, nine case records, with the sample original web record containing all 20 checks and the pinned capture hash. This review did not rerun the full corpus or behavior evaluators. The validation document identifies their actual artifacts and distinguishes simulated observations from real traffic facts.

## Tested-scope limitations and optional notes

No additional feature or host support is requested by this review. Matched R02, R04 and R13 evaluations, extracted lifecycle results, and scoped real-capture findings remain evidence for their recorded inputs, not proof of production diagnosis or universal skill selection. Strict R08 missing-tool isolation and actual Linux/WSL host discovery, native Windows and MobileWork integration remain explicitly unvalidated. The designed R01–R16 inventory is not a claim that every scenario ran. Missing access and provenance authentication remain declared limitations.

No optional code changes are required beyond the four findings. Preserve these findings and the available capture/artifact provenance as open checkpoint work if moving machines before fixes. This report is a review of frozen `44dbedf`, not approval of later fixes or a publication.
