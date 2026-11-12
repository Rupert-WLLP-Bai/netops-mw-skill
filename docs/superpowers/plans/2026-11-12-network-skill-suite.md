# Network Skill Suite Implementation Plan

> **For agentic workers:** Use the already selected Terra/Luna implementation method, then one Sol review after all
implementation is complete. Do not schedule Sol or per-task review gates during implementation. Steps use
checkboxes for tracking.

**Goal:** Deliver five directly usable network skills and a small durable local incident controller that preserves
evidence, budgets, operator decisions, and honest recovery outcomes.

**Architecture:** Keep `internet-access-triage` as the sole bounded collector and retain its standalone release.
`netops-incident` owns one local standard-library controller; three focused instruction-only skills handle existing
captures, recovery assessment, and handoff drafts independently. A versioned suite ZIP contains all five
self-contained skill folders and an explicit provider inventory; optional composition discovers a declared provider
rather than importing sibling code.

**Tech Stack:** Python 3.10+ standard library, `unittest`, JSON, Markdown, ZIP; existing optional TShark and
collector CLI.

**Spec:** [Approved suite proposal](../../research/network-skill-suite-proposal.md), [design
review](../../research/network-skill-suite-review.md), [routing
cases](../../research/network-skill-suite-routing-cases.json), and [closed-loop
workflow](../../research/closed-loop-workflow-proposal.md). Read these and the applicable repository instructions
before execution.

## Global Constraints

- Write project documentation, code, comments, tests and reports in English. Use concrete terms and preserve the
  existing 16-file standalone collector and its tests.
- Python 3.10+ and the standard library only. Do not install tools, alter global/user skill directories, or assume
  a target host can discover a folder without an actual host test.
- No automatic live capture, external messages, ticket/device writes, configuration changes, credential
  acquisition, or external action dispatch. A configured, authorized local URL may use the existing bounded
  collector; never choose a public diagnostic target.
- Retain the existing 25-second round including two seconds reserved for completion; at most two targets, three
  GETs per target, concurrency two, and 64 KiB HTTP body read per response. These limits do not establish a hard
  bound on wire bytes.
- Offline collector limits remain 64 MiB input, 100,000 frames, 8 MiB event output, 64 KiB stderr and 25 seconds.
  PCAP-only entry never causes a live probe. Missing parser or provider is a visible capability gap.
- Preserve the four run diagnosis values `fault_observed`, `healthy_within_scope`, `not_reproduced`, and
  `insufficient_evidence` separately from case workflow status. Evidence references are `(run_id, evidence_id)`; an
  `E001` from another run is distinct.
- Actual substantial public captures and traceable variants are primary offline validation; short synthetic
  captures are unit inputs only. The three originals and six variants in the existing corpus and paired TLS
  evidence establish only scoped visible facts, not incident cause or recovery.
- Manual recovery and handoff work from supplied inputs even without the incident skill. New skills have
  discriminating descriptions and only necessary references; automatic selection remains enabled by default.
  `agents/openai.yaml` is optional, not required by this request.
- Case budgets persist across restart, cancel and reopen; no implicit increase or reset. All collector execution
  through the controller requires a persisted reservation before spawn. Direct standalone collector use remains
  possible and is outside controller enforcement.
- A human or external owner performs actions; the controller records them but never sends, executes, retries or
  claims to cancel them. Unknown action outcome requires reconciliation before another action.
- No new NMS, DNS/path collector, live capture, automatic multi-vantage analysis, MTU diagnosis, actuation, or
  universal health threshold is in this slice.

## Review Focus

1. Two runs both contain `E001`: retain distinct references and reject an ambiguous unqualified ID (Task 2).
2. A source artifact is changed, symlinked or escapes its declared run directory: reject import without changing
   case history (Task 2).
3. A collector crashes or its acknowledgment is lost after reservation: charge the reserved allocation and prevent
   budget reset on restart (Task 3).
4. A reported action succeeds but original-flow evidence is missing, stale, failed, or has a gap in the agreed
   window: never close recovered (Task 4).
5. A requested offline analysis has neither an installed provider nor a permitted parser: report the missing
   capability, do not fabricate findings or probe (Tasks 5 and 7).

## First-slice decisions and file map

Create `skills/netops-incident/SKILL.md`, `references/case-contract.md`, and `scripts/case.py`. The thin CLI wires
lifecycle and rendering to its private `scripts/case_runtime/` package: `__init__.py`, `store.py` for SQLite,
`evidence.py` for imports/decisions, `collection.py` for managed processes, and `recovery.py` for actions/checks.
All code has one maintained copy inside the incident skill; other skills never import it. Create the other three new
`SKILL.md` files and their focused references in Task 5. The public seam remains the CLI. Create `scripts/build_suite.py`, `tests/test_case.py`, `tests/test_suite_skills.py`,
`tests/test_suite_release.py`, and a versioned suite inventory `skills/suite-inventory.json` outside all skill
folders. Add a concise validation record under `docs/validation-network-skill-suite.md`. Do not modify
`scripts/build_release.py` or its 16-file allowlist.

Each case is a private user-selected directory with `case.sqlite3` and `imports/`. Python standard-library SQLite
provides a single transactional source of truth for events, state, revisions and budget reservations; JSON export
remains the portable artifact interface. Use rollback-journal mode and `BEGIN IMMEDIATE` for cross-process
compare-and-swap and atomic commits, avoiding custom dual-file recovery. This is a local embedded file, not a
daemon or external database. The CLI accepts one JSON input file per mutating operation, prints JSON results, uses
a nonzero exit for validation/conflict errors, and never accepts shell command strings. All timestamps are UTC RFC
3339 and IDs are nonempty safe ASCII tokens; an episode ID is generated on create and reopen.

Create input contains `case_id`, `actor`, `event_id`, `occurred_at`, `symptom`, `business_impact`, `scope` and
`verification_plan`, and optional `budget` with `rounds`, `active_seconds`, `http_requests`, `concurrency`,
`verification_reserve_rounds`, `verification_reserve_seconds`, and `verification_reserve_requests`; omitted budget
uses the defaults below. `scope` explicitly contains `vantage`, `identity`, `operation`, `target`, `protocol`,
`address_family`, `proxy`, `workload`, and `original_window`; each may be explicitly null at intake. Every
`verification_plan` field may likewise be null at intake. A complete plan has owner-agreed `criterion` as
`{operator, value}` (`eq`, `gte`, `lte`; finite numeric value), a nonempty `unit`, positive `window_seconds`,
`cadence_seconds`, `maximum_gap_seconds`, `freshness_seconds`, integer `minimum_checks` ≥ 1, and
`minimum_coverage` in (0, 1], plus nonempty `owner` and `agreement_ref`. Reject booleans as numbers, NaN, infinity and invalid ranges. Checks contain a finite
numeric value in the exact unit and an outcome `pass` or `fail`; recompute the criterion and reject disagreement.
Other criteria are unsupported for automated closure. Comparable scope and complete plan are required before action
or recovered closure.

The implementation choice for initial budget defaults is 3 rounds, 75 active collector seconds, 18 HTTP requests,
and concurrency 1, with one round/25 seconds/6 requests reserved for verification. These are new case defaults, not
existing collector promises. Set finite nonnegative totals and reserves no greater than their corresponding totals;
reject concurrency other than exactly 1. Record explicit later increases with actor, reason and authorization
reference. The fixed per-round ceiling remains unchanged. Request
accounting is a conservative maximum of six GET attempts per live reservation; actual measured values may settle
lower only when reliable. Track HTTP request budget separately from DNS/ICMP and bytes: retain the collector's own
bounded limits, record reported bytes and other costs when available, and do not claim a case-wide wire-byte cap.

Workflow statuses are `intake`, `investigating`, `awaiting_action`, `action_outcome_unknown`, `verifying`,
`stabilizing`, `closed_recovered`, `closed_unresolved`, and `cancelled`. Transition rules and gate inputs are
defined in Tasks 3–4; the controller has no generic graph engine. Event payloads include `event_id`, `actor`,
`occurred_at`, `expected_revision`, and operation-specific fields. For `create` only, omit `expected_revision`;
creation commits revision 1. Resolve an identical event ID and payload before checking the expected revision, so a
retry returns its original result even after later events; conflicting duplicates and stale revisions fail without
writes. All mutating commands perform that lookup before file writes or provider spawn.

The supported CLI is `python <installed-incident>/scripts/case.py COMMAND --case DIR [--input FILE]`. Commands are
`create`, `scope`, `import-run`, `decision`, `action`, `run`, `verification`, `transition`, `cancel`, `reopen`,
`get`, and `export`. `create` requires a new case directory, except an identical create retry returns the existing result;
other pre-existing paths are rejected. `get` and `export` need no input. `get` prints the complete
redacted case as JSON; `export` prints the Markdown handoff draft to stdout. Neither reads a hidden repository
path. Every other input includes the event fields above. `run` is the only process-spawning command and accepts an
explicit absolute `provider_cli`, `mode` (`live` or `offline_pcap`), and structured `target`/`symptom` or `pcap`
plus a new `out` directory; it invokes only the documented `diagnose.py` interface using an argument array. Live
mode accepts only a single explicitly approved HTTPS target and nonempty symptom in this slice; offline accepts an
existing local capture only. No arbitrary arguments or shell commands are accepted. `provider_cli` is a
user-selected trusted local `diagnose.py` file; version output establishes interface compatibility, not
authenticity. Never discover or execute an untrusted script automatically. Explicitly selected provider must report
compatible `internet-access-triage 0.1.x` via `--version`; unavailable or incompatible providers stop without
collection.

Before Task 1, run `python3 -B -m unittest discover -s tests -v` and record the actual baseline count and failures;
the historical 72 passing tests are context, not a current result.

### Task 1: Durable case store and CLI

**Files:** Create `skills/netops-incident/scripts/case.py`, `skills/netops-incident/scripts/case_runtime/__init__.py`,
`skills/netops-incident/scripts/case_runtime/store.py`, `skills/netops-incident/references/case-contract.md`, and
`tests/test_case.py`.

**Interfaces:** `case_runtime/store.py` provides `create_case(case_dir: Path, data: dict) -> dict`,
`apply_event(case_dir: Path, data: dict, kind: str) -> dict`, `update_scope(case_dir: Path, data: dict) -> dict`,
and `get_case(case_dir: Path) -> dict`; `case.py` exposes `create`, `scope`, and `get` as above. JSON
objects are returned as snapshots including `schema_version: 1`, `case_id`, `episode_id`, `revision`, `status`,
`scope`, `verification_plan`, `policy_revision`, `policy_hash`, `budget`, and event-derived records.

- [ ] Write `test_create_get_and_permissions`, `test_scope_update_from_null_and_policy_revision`,
  `test_stale_and_conflicting_events`, and `test_interrupted_transaction_is_atomic`. Assert null intake can be
  updated, policy revision/hash changes and old values remain in history, revision survives process restart,
  interrupted transactions change nothing, create returns revision 1, and an identical create or old event retry
  after later events returns its original result without a write. Changed duplicates and new stale events fail;
  POSIX files are private. Exercise these through the public CLI.
- [ ] Run `python3 -B -m unittest discover -s tests -p test_case.py -v`; expect failure because the case CLI does
  not exist.
- [ ] Implement `store.update_scope` and the CLI `scope`: input is the event fields, full
  `scope` and `verification_plan` objects and `reason`. Allow explicit null fields; increment `policy_revision`
  and hash canonical JSON of both objects when either changes. Record prior values and invalidate eligibility of
  earlier checks; never erase prior failures. Reject updates on terminal cases until reopened.
- [ ] Implement event insertion, revision compare-and-swap, materialized state update and budget mutation in one
  SQLite `BEGIN IMMEDIATE` transaction with unique event IDs, full synchronous durability and bounded lock timeout.
  Resolve identical retries before revision checks; roll back failures and reject conflicting duplicates/stale new
  events. Reject symlink case roots, nonregular database files, unsafe IDs and existing unrelated case paths;
  recognize only an identical create retry for an existing case. Create directories `0700` and database/import files `0600`
  where supported; report unsupported permission guarantees on other platforms. Never follow a database, journal or
  import symlink. SQLite local filesystem locking is required; unsupported network filesystems are not claimed
  safe.
- [ ] Document input shape, event history, local trust/retention and restricted evidence in `case-contract.md`. No
  payload, credential or raw capture is copied to history.
- [ ] Run `python3 -B -m unittest discover -s tests -p test_case.py -v`; expect all Task 1 tests passing. Commit:
  `git add skills/netops-incident/scripts/case.py skills/netops-incident/scripts/case_runtime/__init__.py
  skills/netops-incident/scripts/case_runtime/store.py skills/netops-incident/references/case-contract.md
  tests/test_case.py && git commit -m "feat: add durable local incident cases"`.

### Task 2: Immutable run imports and case decisions

**Files:** Create `skills/netops-incident/scripts/case_runtime/evidence.py`; modify
`skills/netops-incident/scripts/case.py`, `skills/netops-incident/scripts/case_runtime/store.py`,
`skills/netops-incident/references/case-contract.md`, `tests/test_case.py`.

**Interfaces:** `case_runtime/evidence.py` provides `import_run(case_dir: Path, data: dict) -> dict`, which consumes `run_dir`, `run_id`, event fields, and
`expected_summary_hashes` mapping each of the four summary paths to SHA-256, including the manifest itself;
this external map is distinct from `manifest.artifact_hashes`, which does not contain a self-hash.
Require `run_id` to match `manifest.json.run_id`; reject invalid JSON or nonempty `validation_errors`.
`case_runtime/evidence.py` also provides `read_confined(root: Path, relative: str, max_bytes: int) -> bytes`
for checked, bounded source reads and `record_decision(case_dir: Path, data: dict) -> dict`, which consumes `observations`, `hypotheses` (at most two),
`support`, `counterevidence`, `confidence`, `limitations`, `next_test`, `expected_support`,
`expected_counterevidence`, and `changed_condition`. Evidence refs are objects `{run_id, evidence_id}`; decision
fields may explicitly say unknown.

- [ ] Write `test_import_qualified_ids_and_diagnosis`, `test_import_rejects_escape_symlink_and_changed_hash`, and
  `test_decision_requires_existing_refs`. Assert two separate `E001` references remain distinct,
  unqualified/unknown refs fail, original diagnosis is unchanged, an input changed during import is rejected, and
  invalid imports leave revision and history unchanged.
- [ ] Run `python3 -B -m unittest discover -s tests -p test_case.py -v`; expect the new import/decision tests to
  fail.
- [ ] Implement `import-run`: read the collector's `manifest.json`, `evidence.jsonl`, `diagnosis.json`,
  `report.md`; verify expected summary hashes, `manifest.artifact_hashes` for referenced source artifacts, the
  manifest run window and run ID, and diagnosis references against evidence records, requiring canonical relative
  paths, regular files, no symlinks or traversal and source confinement. Bound each summary file to 16 MiB and all
  four to 32 MiB; fail closed on overflow. Read each once through a no-symlink file descriptor into private staged
  bytes, hash those exact bytes, parse and validate them, and recheck the opened source identity/size/mtime before
  accepting. Commit only those staged bytes, never a second path read. Atomically rename the private staging
  directory without overwrite to `imports/<run_id>/` before committing the database event. On failure remove that
  unreferenced directory; on restart
  identify and ignore orphan directories, never treat them as committed imports. Record their hashes, scoped
  source, event/collection timestamps, omissions and redaction/access class. Never copy `raw/` or captures. Refuse
  duplicate run IDs with changed content. Manual imports do not consume a collection round.
- [ ] Implement `decision` with existing qualified refs and observation/hypothesis separation. Refuse an additional
  identical test unless `changed_condition` or a new discriminating `next_test` explains expected information gain.
  Persist explicit stop reason if no permissible test or budget remains.
- [ ] Run `python3 -B -m unittest discover -s tests -p test_case.py -v`; expect Task 1–2 tests passing. Commit:
  `git add skills/netops-incident/scripts/case.py skills/netops-incident/scripts/case_runtime/evidence.py
  skills/netops-incident/scripts/case_runtime/store.py skills/netops-incident/references/case-contract.md tests/test_case.py && git commit -m "feat: import scoped incident evidence"`.

### Task 3: Persistent budgets and managed collector runs

**Files:** Create `skills/netops-incident/scripts/case_runtime/collection.py`; modify
`skills/netops-incident/scripts/case.py`, `skills/netops-incident/scripts/case_runtime/store.py`,
`skills/netops-incident/references/case-contract.md`, `tests/test_case.py`.

**Interfaces:** `case_runtime/collection.py` provides `run_collector(case_dir: Path, data: dict) -> dict` and
`cancel_case(case_dir: Path, data: dict) -> dict`; `case.py` wires `reopen_case(case_dir: Path, data: dict) -> dict`. A `run` input additionally includes `purpose`
(`investigation` or `verification`), `provider_cli`, `mode`, `out`, `authorization_ref`, `decision_event_id`,
`actual_vantage` and `vantage_source`, plus mode-specific fields from the first-slice contract. Live target and
vantage must match the explicitly authorized decision and case scope; a mismatch or unknown vantage fails before
spawn. Return JSON `{operation_id, accepted_run_id, stopped_reason}` with nullable latter fields. A `transition`
input can record a budget increase using `budget_increase`, `reason` and `authorization_ref`.

- [ ] Write `test_reserve_before_spawn_and_budget_exhaustion`, `test_crash_charges_reservation_and_resume`,
  `test_cancel_reaps_managed_child`, and `test_standalone_manual_import_costs_no_round`. Use a temporary fake
  version-compatible provider and local test endpoint only. Assert zero-budget prevents even `--version`, invalid
  reserve/concurrency and mismatched target/vantage reject before spawn, investigation cannot spend the reserve,
  and restart/lost acknowledgment retains full charge. Race cancellation against settlement and import; assert
  cancelled status persists, a valid run is imported once, invalid output reports a reason, and the child is reaped.
- [ ] Run `python3 -B -m unittest discover -s tests -p test_case.py -v`; expect the new managed-run tests to fail.
- [ ] Preflight path, authorization, scope, decision, new output and available budget without spawning. Atomically
  reserve 1 round, 25 seconds and 6 requests for live mode before launching even `--version`; enforce the purpose
  reserve and concurrency 1. Run the trusted provider with `sys.executable` and argument arrays only. Probe version
  with a 2-second timeout; version and collector share the reserved 25-second deadline, so the collector may receive
  less time while its own existing 25-second cap remains unchanged. Incompatibility launches no network collection
  and consumes the reservation. Use only `--url URL --symptom TEXT --out DIR` or `--pcap FILE --out DIR`.
- [ ] Do not hold a SQLite transaction while the supervisor polls cancellation and owns the child. Terminate at
  the shared deadline or cancellation and allow at most two extra seconds for cleanup; report unverified descendant
  cleanup. Charge 25 seconds and six live requests unless a valid manifest unambiguously reports fewer HTTP calls.
  In a new transaction reload the latest revision and operation ID, settle exactly once, and preserve any concurrent
  cancelled state. Validate and automatically import completed outputs through Task 2 using hashes of the staged
  summary bytes; missing/invalid outputs produce a recorded stop reason, never invented evidence. A cancelled or
  failed run may import only complete valid outputs; keep partial files local and restricted.
- [ ] After supervisor crash leave the reservation spent and in-flight outcome unknown; never kill a stale PID or
  start another run until explicit `transition` reconciliation records owner, evidence and confirmation that the
  prior process ended. Internal settlement retries revision conflicts using operation identity, never overwrites a
  newer user event, and returns the accepted run ID or stop reason.
- [ ] Implement cancel, reopen and explicit budget increases as events; cancel blocks new work, preserves unknown
  external action and partial evidence, and reopen creates a new episode while retaining budget. Explicitly report
  that the controller cannot stop unrelated processes or enforce standalone runs.
- [ ] Run `python3 -B -m unittest discover -s tests -p test_case.py -v`; expect Task 1–3 tests passing. Commit:
  `git add skills/netops-incident/scripts/case.py skills/netops-incident/scripts/case_runtime/collection.py
  skills/netops-incident/scripts/case_runtime/store.py skills/netops-incident/references/case-contract.md tests/test_case.py && git commit -m "feat: enforce incident collection budgets"`.

### Task 4: Action records, verification, and complete lifecycle

**Files:** Create `skills/netops-incident/scripts/case_runtime/recovery.py`; modify
`skills/netops-incident/scripts/case.py`, `skills/netops-incident/scripts/case_runtime/store.py`,
`skills/netops-incident/references/case-contract.md`, `tests/test_case.py`.

**Interfaces:** `case_runtime/recovery.py` provides `record_action(case_dir: Path, data: dict) -> dict` and
`record_verification(case_dir: Path, data: dict) -> dict`; `case.py` wires `transition_case(case_dir: Path, data:
dict) -> dict` and `export_report(case_dir: Path) -> str`.
`action` includes owner, intended change, affected scope, refreshed preconditions, authorization reference,
expected check, rollback trigger/owner, correlation key, time, outcome (`proposed`, `completed`, `partial`,
`unknown`, or `failed`) and evidence refs. `verification` uses `kind: start|check`; start includes `reason` and
creates `window_id`, `episode_id`, `policy_revision`, `policy_hash`, `window_start` and `window_end`. Check includes
those identifiers, check ID, original scope, observed/collection times, source/actor, numeric value, unit, outcome,
raw reference/hash, provenance, trust grade (`independent_observation` or `owner_claim`) and differences. A hash proves byte
consistency, not authenticity or truth; retain source attribution and mark the provenance unverified unless
independently established. The controller checks recorded declarations and artifacts; it cannot authenticate an
observer or prove a supplied observation actually occurred, so report this limit with any closure.

- [ ] Write `test_failed_check_and_recurrence_do_not_close`, `test_spontaneous_recovery_with_complete_window`,
  `test_unknown_action_requires_reconciliation`, `test_missing_or_changed_check_artifact_rejected`, and
  `test_unavailable_original_vantage_stays_unresolved`, `test_invalid_numeric_policy_and_timestamps`, and
  `test_window_end_failure_stale_gap_wrong_policy`. Assert null fields can be completed before action; reject
  NaN/Inf, invalid durations/coverage, mismatched units, outcome/criterion disagreement and future timestamps.
  Checks from a different episode/policy/window, missing or altered refs, gaps, stale final checks, failure exactly
  at window end or recurrence after it block closure; a policy update cannot turn an earlier failure into a pass. A spontaneous recovery passes only with qualifying checks.
- [ ] Run `python3 -B -m unittest discover -s tests -p test_case.py -v`; expect the new lifecycle tests to fail.
- [ ] Implement only these transitions: intake→investigating; investigating→awaiting_action or verifying or
  closed_unresolved; awaiting_action→verifying, action_outcome_unknown or closed_unresolved;
  action_outcome_unknown→awaiting_action or verifying only after recorded authoritative reconciliation, or
  closed_unresolved; verifying→stabilizing, investigating or closed_unresolved; stabilizing→closed_recovered,
  investigating or closed_unresolved; any nonterminal→cancelled; closed/cancelled→intake only via `reopen`.
  Recurrence returns to investigating only with a meaningful permitted next test and budget; otherwise close
  unresolved or stay open.
- [ ] Before action require known original scope, complete valid plan and refreshed preconditions. A verification
  start event uses the controller's current UTC time (not a caller-selected past window) as `window_start`, with
  `window_end = start + window_seconds`; bind it to the current episode, scope/policy revision and hash. Any scope
  or plan update invalidates prior eligibility. A new attempt after failure requires an explicit reason; prior
  failures remain visible and cannot be rewritten or made successful retroactively.
- [ ] Import each check's local artifact with `case_runtime.evidence.read_confined` and Task 2 hash checks. Require
  `observed_at <= collected_at <= event recorded_at <= now`, UTC timestamps and exact matching episode, policy,
  scope, window ID, start and end. Assign `recorded_at` from the controller clock, not caller input;
  owner claims are context only. Compare the finite value and exact unit to the criterion. Evaluate observations
  in the inclusive window; any eligible failure including at `window_end` fails it, and any later same-scope
  failure before closure is recurrence. Out-of-window passes never fill coverage. At closure require now ≥ end,
  the last in-window passing observation no older than `freshness_seconds`, required count and coverage; reject
  gaps longer than `maximum_gap_seconds`. Sum disjoint intervals from each passing timestamp to the earlier of the
  next passing timestamp, timestamp plus cadence or window end; divide by window duration. Use an injectable clock
  in tests. Hashes and declared provenance establish consistency, not authenticated ground truth.
- [ ] `export` produces a local redacted Markdown draft with scoped observations, evidence refs and hashes,
  decision/counterevidence, action outcome, verification gaps, budget, status, owner and next action; it never
  sends or writes a ticket. Provide reproducible simulated failed-verification and spontaneous-recovery journeys in
  tests, including cancel/restart and unknown outcomes.
- [ ] Run `python3 -B -m unittest discover -s tests -p test_case.py -v`; expect Task 1–4 tests passing. Commit:
  `git add skills/netops-incident/scripts/case.py skills/netops-incident/scripts/case_runtime/recovery.py
  skills/netops-incident/scripts/case_runtime/store.py skills/netops-incident/references/case-contract.md tests/test_case.py && git commit -m "feat: record incident recovery and handoff"`.

### Task 5: Five focused skill entry points

**Files:** Create `skills/netops-incident/SKILL.md`, `skills/netops-pcap-analysis/SKILL.md`,
`skills/netops-pcap-analysis/references/offline-analysis.md`, `skills/netops-verify-recovery/SKILL.md`,
`skills/netops-verify-recovery/references/verification.md`, `skills/netops-handoff/SKILL.md`,
`skills/netops-handoff/references/handoff.md`, `tests/test_suite_skills.py`. Retain
`skills/internet-access-triage/SKILL.md` as the fifth entry point.

**Interfaces:** Each `SKILL.md` has valid `name`, discriminating `description`, and `metadata.version: 0.1.0`.
Incident references its own local CLI and contract. Others consume supplied reports, captures, checks or notes
directly; when a compatible installed provider is discoverable, use its declared CLI interface, not an assumed
`../` path or fictional skill invocation.

- [ ] Write `test_skill_references_resolve` and `test_skill_inventory_frontmatter`. Assert all referenced local files
  exist and each of the five folders has matching name and description metadata. Task 7 tests independent entry
  and absent-provider behavior with clean-session prompts; structural tests cannot establish model behavior.
- [ ] Run `python3 -B -m unittest discover -s tests -p test_suite_skills.py -v`; expect failure because four skills
  do not exist.
- [ ] Author incident instructions for scope, evidence, discriminating next test, budgets, operator action,
  verification, stop and draft handoff. State exactly when controller persistence is available and distinguish
  standalone manual work. Discover installed provider by host-supported mechanisms and declare missing capability
  if unavailable.
- [ ] Author PCAP instructions for file-only analysis, scoped visible frames and capture limits. Use the existing
  offline collector if discovered; otherwise use an actually installed permitted offline parser, or report its
  absence. Never install tools, initiate capture or contact a target. Avoid unsupported automatic multi-vantage or
  causation claims.
- [ ] Author verification instructions comparing the original operation, vantage, identity, target,
  protocol/family, proxy, workload, criterion, timestamped independent checks and owner-agreed stability coverage.
  Author handoff instructions producing a draft with evidence, counterevidence, unknowns, owner and next action;
  never send. Both must work without the controller.
- [ ] Run `python3 -B -m unittest discover -s tests -p test_suite_skills.py -v` and `python3
  /home/pejoy/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/<name>` for each of the five
  actual names; expect all checks passing. Commit: `git add skills/netops-incident/SKILL.md
  skills/netops-pcap-analysis skills/netops-verify-recovery skills/netops-handoff tests/test_suite_skills.py && git
  commit -m "feat: add focused network workflow skills"`.

### Task 6: Versioned suite release and clean extraction

**Files:** Create `scripts/build_suite.py`, `skills/suite-inventory.json`, `tests/test_suite_release.py`.

**Interfaces:** `build_suite(source_root: Path, output_zip: Path, manifest_path: Path | None = None) -> dict`; CLI
`python3 -B scripts/build_suite.py --out NEW.zip [--manifest NEW.json]`. Inventory version `0.1.0` lists exactly
five names/versions and provider `internet-access-triage 0.1.x` with its supported `scripts/diagnose.py --version`,
`--url`, and `--pcap` interface; incident controller is `netops-incident/scripts/case.py` schema version 1.
Inventory describes optional discovery, not an implicit sibling import.

- [ ] Write `test_suite_exact_allowlist_and_reproducibility`, `test_reject_extra_missing_symlink_and_overwrite`,
  and `test_clean_extract_entrypoints_and_missing_provider`. Assert two builds have identical ZIP bytes and hashes;
  exactly the five named skill roots plus inventory appear, no tests/research/PCAP/logs/caches appear, and
  extracted collector/controller `--help` and `--version` or `get` as applicable run without repository access.
  Missing provider produces a bounded result.
- [ ] Run `python3 -B -m unittest discover -s tests -p test_suite_release.py -v`; expect failure because the
  builder does not exist.
- [ ] Implement an explicit per-file allowlist: the existing 16 collector files; incident `SKILL.md`,
  `references/case-contract.md`, `scripts/case.py`, and the five files explicitly named in
  `scripts/case_runtime/`: `__init__.py`, `store.py`, `evidence.py`, `collection.py`, and `recovery.py`; the six Task 5 instruction/reference files; the four new skill licenses; and inventory. Follow existing
  deterministic ZIP timestamp, ordering, file-mode, UTF-8, symlink, path, no-overwrite and manifest SHA-256
  practices; reject missing and unexpected source files. Copy the repository `LICENSE` into each of the four new
  skill folders and list those four license files explicitly; document the repository license consistently in the
  inventory. Do not bundle raw evidence or dependencies.
- [ ] Run `python3 -B -m unittest discover -s tests -p test_suite_release.py -v` and `python3 -B -m unittest
  discover -s tests -p test_release.py -v`; expect both passing and the old standalone release unchanged. Commit:
  `git add scripts/build_suite.py skills/suite-inventory.json tests/test_suite_release.py` plus any explicitly
  licensed new skill files, then `git commit -m "feat: package versioned network skill suite"`.

### Task 7: Corpus, routing, and end-to-end validation

**Files:** Create `docs/validation-network-skill-suite.md`; modify tests only for defects exposed by validation, in
the owning task files.

**Interfaces:** Consume Task 1–6 CLI and suite archive, the 16 R01–R16 designed scenarios, and existing
`docs/research/real-pcap-corpus.json`, `real-pcap-postfix-validation.json`, and
`multi-site-packet-analysis-cases.json`. Evaluation input contains only a realistic prompt and permitted raw
inputs; keep `category`, expected result and `private_rubric` with the grader.

- [ ] Run `python3 -B -m unittest discover -s tests -v` after implementation; compare with the recorded
  pre-Task-1 baseline, require no regression and record actual results.
- [ ] Run `python3 -B scripts/validate_real_pcap.py --out .tools/pcap-corpus/suite-validation` only if the
  preexisting local corpus, hashes and TShark are available; use a new output directory. Verify originals and six
  `omit`/`snap96` variants, provenance, frame/truncation/direction counts, artifacts, evidence refs and known
  scoped diagnosis using the existing validator. If inputs or tools are unavailable, record the exact blocker as
  unvalidated; do not download, install or substitute short test captures. Keep raw results outside release.
- [ ] Use the paired TLS reference cases for scoped comparison of visible facts, clock/vantage and missing
  intervals; do not treat simulated omissions as real loss or filenames as causal ground truth. Execute the
  controller's failed-check and spontaneous-recovery journeys with local records, plus cancel/restart and
  unknown-action paths; verify no false recovery or action repetition.
- [ ] Run four independent clean-session forward probes, with identical permissions and inputs for the old
  collector or no-suite baseline and suite. R02 gets the existing full `.tools/pcap-corpus/downloads/lotsofweb.pcapng`
  with SHA-256 `92e06382a4f2e12bd569a104ceeecf908b89ccdb801f3dc4ae430b0f1a967f9b` and its corpus-recorded actual
  capture window; adapt the prompt's placeholder time to that window. R04 gets Task 4's typed positive and failed
  check-window records, scope and policy. R08 gets the same full capture, with an isolated evaluator policy exposing
  no parser, shell or collector capability; do not modify the host or global tools. R13 gets Task 4's case/action
  record with unknown outcome. If a fixture or isolation is unavailable, report that probe unvalidated, not passed.
- [ ] Provide only each prompt and its stated allowed raw inputs to evaluators; keep case categories, expected labels
  and rubrics private. Record traces, outcomes, side effects, duration and token counts when available; otherwise
  mark token counts unavailable. Expand to relevant R01–R16 cases if overlap, routing or safety concerns appear;
  do not mandate 16 agents. Store generated artifacts in isolated temporary directories.
- [ ] Build twice in separate empty directories with the same archive filename, compare SHA-256 and extract in a
  clean directory. Run supported offline entry points with a real permitted capture if available and without
  repository access; record absent tools. Check real host discovery, explicit invocation and missing-skill behavior
  only on an actually available target host without installing globally; separately mark Linux/WSL, native Windows
  and MobileWork unvalidated when unavailable.
- [ ] Record source revision, commands, test counts, package hashes, evidence provenance, limitations and each
  actual forward-test result in the validation record. Distinguish structural checks, behavioral sessions,
  real-corpus results and conditional host smoke; do not present designed cases or historical results as new
  passes.
- [ ] Commit: `git add docs/validation-network-skill-suite.md` and any justified fixes/tests, then `git commit -m
  "test: validate network skill suite"`. After all implementation, request the already selected Sol final review
  and address findings before declaring completion.

## Dependency and coverage check

| Requirement | Owner | Depends on |
| --- | --- | --- |
| Durable history, revisions and idempotency | Task 1 | None |
| Evidence provenance, run-scoped IDs and decisions | Task 2 | Task 1 |
| Budget, safe execution, cancellation and resume | Task 3 | Tasks 1–2 |
| Action, checks, stabilization and handoff | Task 4 | Tasks 1–3 |
| Five direct entry skills and independent fallback | Task 5 | Tasks 1–4 for incident interface |
| Deterministic release, inventory and standalone preservation | Task 6 | Tasks 1–5 |
| Real corpus, forward tests and truthful host limits | Task 7 | Tasks 1–6 |

Tasks 1–4 share CLI wiring, the case contract and tests, so execute sequentially; do not assign concurrent
implementers to those files. Test observable public CLI behavior rather than private helper wording. Task 5 may be drafted independently only after its interfaces are frozen and must not edit shared controller
files. The five review-focus cases each map to named tests above. Follow the already selected Terra/Luna method and
reserve Sol for the final whole-branch review.

**Handoff:** The implementation plan is ready for user review. Ask whether it captures the intended scope and wait
for that review before implementation; do not ask the user to choose the execution method again.
