# Local case contract, schema 1

Run `python scripts/case.py COMMAND --case DIR [--input FILE]`. Mutations read one JSON object and return a JSON snapshot. `get` reads the current snapshot. Event IDs are safe ASCII tokens; actor and UTC RFC 3339 `occurred_at` are required. Mutations after create also require `expected_revision`. Identical event retries return the original snapshot, even after later changes; conflicting IDs and stale new events fail.

`create` requires `case_id`, `symptom`, `business_impact`, `scope`, and `verification_plan`. Scope has `vantage`, `identity`, `operation`, `target`, `protocol`, `address_family`, `proxy`, `workload`, and `original_window`; each can initially be null. The verification plan has `criterion`, `unit`, `window_seconds`, `cadence_seconds`, `maximum_gap_seconds`, `freshness_seconds`, `minimum_checks`, `minimum_coverage`, `owner`, and `agreement_ref`; each can initially be null. Non-null timing durations must be between one microsecond and 100 years (3,153,600,000 seconds), inclusive; a window must also fit the clock range at its start. A criterion is `{"operator":"gte","value":1}` with operator `eq`, `gte`, or `lte`. `scope` accepts both complete objects and a `reason` and retains prior policy in history.

`create` and `scope` optionally accept a versioned `service_context` as described in [the carrier evidence contract](carrier-evidence-contract.md). Omitting it on `scope` preserves the current context; explicit null removes it. A change increments policy revision and invalidates earlier verification windows and decisions, including after removal. Legacy inputs without context retain their existing policy identity and snapshot shape. Context fields are local declarations, not proof of service identity. Carrier metadata is bounded to 1 MiB, depth 16, 2,048 characters per string, 256 objects, 512 links and 256 evidence records. CLI input is limited to 16 MiB.

The default budget is 3 rounds, 75 active seconds, 18 HTTP requests, and concurrency 1, reserving 1 round, 25 seconds, and 6 requests for verification. An optional `budget` must specify all seven fields shown in the snapshot.

A case directory is private local state, not a service. It contains SQLite state and restricted imports. The local filesystem must support SQLite locking and durable writes. Keep it in trusted storage and apply the operator's retention policy. Do not place credentials or raw captures in event input. POSIX creation uses mode 0700 for directories and 0600 for the database; other platforms may not provide the same permission guarantees.

`import-run` takes `run_dir`, `run_id`, and `expected_summary_hashes` for `manifest.json`, `evidence.jsonl`, `diagnosis.json`, and `report.md`. Supply SHA-256 hashes computed from the four completed source files. The run ID must match the manifest. Only these summaries are copied; referenced artifacts are checked but raw files and captures remain at their source. Imports have restricted access. A run evidence reference is `{"run_id":"run1","evidence_id":"E001"}`; IDs alone are ambiguous. Orphan import directories are not evidence unless an event committed them.

Optional `service_context` and `carrier_evidence` belong in the hashed manifest itself. The imported source context remains separate from the receiving case context; importing it neither asserts equivalence nor changes recovery policy. The manifest and its carrier metadata are retained with the import. No carrier metadata path is opened.

`decision` takes `observations`, `hypotheses` (at most two), `support`, `counterevidence`, `confidence`, `limitations`, `next_test`, `expected_support`, `expected_counterevidence`, and `changed_condition`. Support and counterevidence are arrays of qualified references. A repeated test requires a changed condition; record expected support and counterevidence for a next test. An absent next test records a stop reason.

`run` requires a trusted absolute `provider_cli` named `diagnose.py`, `purpose` (`investigation` or `verification`), `mode` (`live` or `offline_pcap`), a new absolute `out`, `authorization_ref`, `decision_event_id`, `actual_vantage`, and `vantage_source`. Live mode also takes `target` and `symptom`; target must be the HTTPS target in the decision's current scope. Offline mode takes an absolute `pcap`. The latest decision must specify a discriminating next test and the actual vantage must match scope. A decision authorizes one attempted run, including an interrupted reservation; a further attempt requires a new decision with a different test or a changed condition. Identical event retries remain idempotent. The controller reserves one round and 25 seconds before even querying the selected provider version; live mode additionally reserves six HTTP requests. Investigation cannot spend verification reserves. Reserved cost remains charged after interruption, missing output, or incompatible provider. Reported request cost is conservative; it does not represent a wire-byte cap.

`cancel` takes a reason and stops the owned process when its supervisor is active. It cannot stop unrelated processes or enforce standalone collector invocations; descendant cleanup is unverified. After a supervisor crash the operation remains in flight. Once the owner has confirmed the prior process ended, use `transition` with `reconcile_operation_id`, `confirmed_ended: true`, `owner`, `evidence`, and `reason` before another run. The controller never kills a stale PID. `reopen` takes a reason and starts a new episode without resetting budget. A `transition` may instead supply `budget_increase` with nonnegative integer `rounds`, `active_seconds`, and/or `http_requests`, a reason, and `authorization_ref`.

## Recovery records

Status changes use `transition` with `status` and `reason`. The allowed paths are intake → investigating; investigating → awaiting_action, verifying, or closed_unresolved; awaiting_action → verifying, action_outcome_unknown, or closed_unresolved; action_outcome_unknown → awaiting_action or verifying after authoritative reconciliation, or closed_unresolved; verifying → stabilizing, investigating, or closed_unresolved; stabilizing → closed_recovered, investigating, or closed_unresolved. `cancel` applies to nonterminal cases; `reopen` is the only route from a terminal case to intake. Returning from verification to investigation requires a new discriminating decision after the latest failure and unreserved budget.

`action` records an operator's work; it executes nothing. Supply `owner`, `intended_change`, `affected_scope` (the complete current scope object), `preconditions`, `authorization_ref`, `expected_check`, `rollback_trigger`, `rollback_owner`, unique `correlation_key`, UTC `action_time`, `outcome` (`proposed`, `completed`, `partial`, `unknown`, or `failed`), and `evidence` (qualified references). Complete original scope and plan are required. An unknown outcome blocks another action and verification. To reconcile, transition from `action_outcome_unknown` with a `reconciliation` object containing matching `correlation_key`, `owner`, `evidence`, `authorization_ref`, and an `outcome` of `completed`, `partial`, `failed`, or `not_performed`.

Start verification with `{"event_id":"start1","actor":"operator","occurred_at":"2026-01-01T00:00:00Z","expected_revision":3,"kind":"start","reason":"initial observation"}`. The snapshot's last `verification_windows` item contains the controller-assigned `window_id`, `episode_id`, `policy_revision`, `policy_hash`, `window_start`, and `window_end`; copy those six fields into each `kind: "check"` input. Do not supply a past window. A check also takes a unique `check_id`, the complete matching `scope`, UTC `observed_at` and `collected_at`, `source`, `source_actor`, numeric `value`, exact `unit`, computed `outcome` (`pass` or `fail`), `provenance`, `trust_grade` (`independent_observation` or `owner_claim`), `differences` (array), and `raw_reference`:

```json
{"root":"/absolute/local/directory","path":"check.json","sha256":"<sha256-of-check-json>"}
```

The reference must point to a bounded regular file under that directory without symlinks. The controller copies its checked bytes into restricted case storage and assigns `recorded_at`. It rejects mismatched units, values and outcomes, future or misordered timestamps, and stale episode/policy/window identities. Owner claims remain context; independent observations must cover the original operation. The check artifact and provenance are declarations, not authenticated ground truth.

`closed_recovered` requires the current complete policy, a finished window, enough fresh independent passing checks, the agreed cadence-derived coverage and maximum gap, and no in-window failure or later recurrence. Stored artifact hashes are rechecked. A scope or plan update invalidates previous eligibility and does not erase failures. After an action or its reconciliation, recovery requires a window started after that record and no earlier than the recorded action time, with qualifying observations in that window. Spontaneous recovery remains possible without an action. `export` prints a local Markdown handoff draft; it does not send a message or write a ticket.

For a live run, the decision must also carry `authorized_collection: {"target":"https://service.example.test","vantage":"branch","authorization_ref":"approval-id"}` matching the run request and current scope. The controller does not determine whether that authorization is valid. After reopening a case whose action outcome remains unknown, `transition` may record the same reconciliation object as `action_reconciliation` without changing status.

For example, an intake input can use explicit unknowns and the default budget:

```json
{
  "case_id": "incident1", "event_id": "create1", "actor": "operator",
  "occurred_at": "2026-01-01T00:00:00Z", "symptom": "order submission fails",
  "business_impact": "orders cannot be submitted",
  "scope": {"vantage": "branch", "identity": null, "operation": "submit order", "target": "https://service.example.test", "protocol": "HTTPS", "address_family": null, "proxy": null, "workload": null, "original_window": null},
  "verification_plan": {"criterion": null, "unit": null, "window_seconds": null, "cadence_seconds": null, "maximum_gap_seconds": null, "freshness_seconds": null, "minimum_checks": null, "minimum_coverage": null, "owner": null, "agreement_ref": null}
}
```

Complete all scope fields before an action or verification; use an explicit value such as `direct` when there is no proxy. To calculate the four import hashes from a completed run without changing it:

```python
from hashlib import sha256
from pathlib import Path
run = Path('/absolute/run-directory')
hashes = {name: sha256((run / name).read_bytes()).hexdigest() for name in
          ('manifest.json', 'evidence.jsonl', 'diagnosis.json', 'report.md')}
```

Use the resulting mapping as `expected_summary_hashes` and the manifest's actual `run_id`. Hashing is a consistency check; it does not authenticate the source.

Checked imports require operating-system support for no-symlink descriptor reads and atomic no-replace directory renames. The controller fails closed when these operations are unavailable; this has been exercised on the current Linux host and does not establish native Windows or network-filesystem support.
