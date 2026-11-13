# Incident service-review provider contract

This reference documents the optional, incident-owned service-acceptance analyzer. Discover it through the host's supported provider mechanism and invoke it only when present and explicitly selected:

```sh
python3 scripts/review_service.py --input REQUEST.json
```

The CLI reads a bounded strict UTF-8 JSON request and returns deterministic JSON on stdout. The result includes a bounded, fixed-structure Markdown `draft_report` string; the program does not create or send files. It does not contact a network, run probes, perform changes, dispatch tickets or messages, mutate a case, approve a plan, or change recovery eligibility. The existing incident controller remains authoritative. The offline manual workflow is usable without this provider.

The contract uses schema version 1 and M2 checked runs. Every request key shown below is required unless the contract explicitly allows a nullable reference or array. Unknown keys fail closed. A null or empty value records absent or unknown evidence; it is never a pass or waiver.

## Strict request, existing checked runs and bounds

Use the same strict UTF-8 JSON, M2 four-summary `runs`, M1 service context and source-qualified `bindings` as the access/transport providers. Add explicit service-delivery declarations below; all keys are required, unknown keys rejected, nullable refs/arrays mean unknown or absent, not a default or pass. `<sha256>` placeholders below are illustrative and must be replaced with hashes of actual source bytes.

```json
{
  "schema_version": 1,
  "reference_time": "2026-01-01T00:10:00Z",
  "window_start": "2026-01-01T00:00:00Z",
  "window_end": "2026-01-01T00:09:00Z",
  "max_age_seconds": 600,
  "service": {"topology_run_id": "topology-run", "object_id": "service-alias"},
  "runs": [{"run_id":"topology-run","run_dir":"/trusted/topology-run","expected_summary_hashes":{"manifest.json":"<sha256>","evidence.jsonl":"<sha256>","diagnosis.json":"<sha256>","report.md":"<sha256>"}}],
  "bindings": [{
    "record":{"run_id":"actual-run","evidence_id":"ev-000000000001"},
    "topology_evidence":{"run_id":"topology-run","evidence_id":"ev-000000000001"},
    "service_id":"service-alias","resource_id":"point-alias",
    "source":"source-token","source_native_id":"point-source-alias",
    "valid_from":"2026-01-01T00:00:00Z","valid_until":"2026-01-01T00:09:00Z","authority":"operator-map"
  }],
  "delivery_scope": {"circuit_id":"circuit-alias","endpoint_a_id":"site-a","endpoint_b_id":"site-b"},
  "static_authorities": [{
    "source":"order-source","source_native_id":"order-alias",
    "current_evidence":{"run_id":"order-run","evidence_id":"ev-000000000001"},
    "valid_from_evidence":null,"valid_until_evidence":null
  }],
  "field_inventory": {
    "run_id":"order-run","source":"order-source","source_native_id":"field-inventory-alias",
    "approval_evidence":{"run_id":"order-run","evidence_id":"ev-000000000003"},
    "count_evidence":{"run_id":"order-run","evidence_id":"ev-000000000004"},
    "entry_evidence":[{"run_id":"order-run","evidence_id":"ev-000000000005"}]
  },
  "fields": [{
    "field":"vlan","target":"endpoint_a",
    "required_evidence":{"run_id":"order-run","evidence_id":"ev-000000000005"},
    "applicability_evidence":null,"inapplicability_reason_evidence":null,
    "expected_evidence":{"run_id":"order-run","evidence_id":"ev-000000000002"},
    "actual_evidence":{"run_id":"actual-run","evidence_id":"ev-000000000002"},
    "actual_target_evidence":{"run_id":"actual-run","evidence_id":"ev-000000000009"},
    "equivalence_evidence":null
  }],
  "criterion_inventory": {
    "run_id":"sla-run","source":"sla-source","source_native_id":"inventory-alias",
    "approval_evidence":{"run_id":"sla-run","evidence_id":"ev-00000000000b"},
    "count_evidence":{"run_id":"sla-run","evidence_id":"ev-00000000000c"},
    "entry_evidence":[{"run_id":"sla-run","evidence_id":"ev-00000000000d"}]
  },
  "criteria": [{
    "criterion_id":"criterion-1","source":"sla-source","source_native_id":"criterion-alias",
    "capability_evidence":{"run_id":"sla-run","evidence_id":"ev-00000000000e"},
    "applicability_evidence":null,"inapplicability_reason_evidence":null,
    "metric_evidence":{"run_id":"sla-run","evidence_id":"ev-000000000001"},
    "aggregation_evidence":{"run_id":"sla-run","evidence_id":"ev-000000000002"},
    "comparator_evidence":{"run_id":"sla-run","evidence_id":"ev-000000000003"},
    "threshold_evidence":{"run_id":"sla-run","evidence_id":"ev-000000000004"},
    "method_evidence":{"run_id":"sla-run","evidence_id":"ev-000000000005"},
    "minimum_samples_evidence":{"run_id":"sla-run","evidence_id":"ev-000000000006"},
    "direction_evidence":{"run_id":"sla-run","evidence_id":"ev-000000000007"},
    "calibration_policy_evidence":{"run_id":"sla-run","evidence_id":"ev-000000000008"},
    "window_start_evidence":{"run_id":"sla-run","evidence_id":"ev-000000000009"},
    "window_end_evidence":{"run_id":"sla-run","evidence_id":"ev-00000000000a"}
  }],
  "direction_mappings": [{
    "point_id":"point-alias","site_id":"site-a","source":"source-token","source_native_id":"point-source-alias",
    "relative_direction":"egress","absolute_direction":"A_to_B",
    "mapping_evidence":{"run_id":"actual-run","evidence_id":"ev-000000000003"},
    "valid_from":"2026-01-01T00:00:00Z","valid_until":"2026-01-01T00:09:00Z","authority":"operator-direction-map"
  }],
  "test_results": [{
    "criterion_id":"criterion-1","measurement_evidence":{"run_id":"actual-run","evidence_id":"ev-000000000004"},
    "method_evidence":{"run_id":"actual-run","evidence_id":"ev-000000000005"},
    "aggregation_evidence":{"run_id":"actual-run","evidence_id":"ev-000000000006"},
    "window_start_evidence":{"run_id":"actual-run","evidence_id":"ev-000000000007"},
    "window_end_evidence":{"run_id":"actual-run","evidence_id":"ev-000000000008"},
    "instrument_evidence":null,"calibration_evidence":null,
    "calibration_start_evidence":null,"calibration_end_evidence":null
  }],
  "change_review": null
}
```

Every actual run used above must be supplied in `runs`; the compact example does not repeat all run hashes/bindings. Each field is a declaration of **references**, not a caller-supplied measurement, threshold, approval outcome, comparison or causal conclusion. M2 evidence IDs use the producer's 12-digit lowercase hexadecimal row number: row 10 is `ev-00000000000a`, row 11 is `ev-00000000000b`. Fixture materializers must read the produced IDs or use this pinned hexadecimal convention, never decimal-formatted indexes. Use M4's strict checked loader: UTF-8, no duplicate keys/nonfinite values/control characters, confined no-symlink regular files, exact source hashes and M1 envelope/visible observation consistency, bounded rows. At most eight runs, 512 evidence records, 512 bindings, 512 topology links, 256 field/test/direction/criterion declarations each, 1 MiB request/result, 2 MiB per run, 16 MiB aggregate, depth 16/20,000 nodes, fixed work limits and a five-second worker watchdog. Count before allocation; cache visible artifacts once. Unsupported input fails closed; timeout returns unverified with `analysis_timeout` and no stale decision. No request-controlled arbitrary code, dynamic file path inside evidence, or executable source text.

Topology declarations must explicitly cover `service_to_circuit`, `service_to_endpoint_a`, `service_to_endpoint_b`, and `site_to_point`; each relation is verified and explicit. The ordinary source-qualified service-to-resource binding is still required for every measurement. No relation is inferred from a shared label, endpoint order, registry order, or graph proximity.

M2 records are declarations, not authenticated business documents. All refs must exist in checked complete M2 runs. Every actual measurement, actual field, direction mapping, actual method/aggregation and postcheck must have its own usable M1 source-qualified binding into the selected service and correct object; event/collection times and uncertainty are required and evaluated at this request's reference time. Actual events must fall in the request test window and satisfy `max_age_seconds`; the M2 adapter's earlier quality is not current freshness proof. Window boundary values and source calibration validity are separate metadata, not fabricated observation events: an unknown original event date stays unknown and may be retained when independently valid scoped source authority and explicit business-date values establish applicability. No alias-only or hostname-based identity equivalence. A binding's actual `(source,source_native_id)` must match exactly, its declared interval must cover the event uncertainty range, and verified direct topology is an operator claim, not authentication.

Business dates are **values**, not an observation's event timestamp. Static validity endpoints, approved test windows, actual measurement windows, calibration validity and planned change dates use finite numeric M2 values with exact unit `unix_s`: seconds since the Unix epoch in UTC, including an explicitly supplied fractional part if present. Each role has the exact metric named below and a qualified ref; reject booleans, nonfinite/out-of-range values, reversed intervals and unit mismatches. The provider converts the declared numeric timestamp to a UTC instant only for comparison, without inferring a timezone or substituting another field. The M1 `event_time` remains the source's original observation or approval time and remains null if unknown; `collected_at` remains collection time. A valid-until or planned-end **value** may legitimately be later than collection time. Future business-date values must never be put into M1 `event_time` merely to represent a deadline. An approval's original event time must be explicitly present when its chronology is required.

`delivery_scope` names distinct **known** M1 `circuit` and two **known** `site` objects from the selected topology context. Require explicit fresh verified declared service-to-circuit, service-to-site-A and service-to-site-B links with source roles distinguishing A from B; no endpoint order inferred from registry position/name. For each measurement point require a known topology object and an explicit verified site-to-point relation in addition to the service-to-point binding. Mapping evidence must be a real checked, bound M2 `direction_mapping` row whose M1 relative direction and allowlisted value exactly match `relative_direction` and `absolute_direction`; its source/native identity and point match the declaration. `relative_direction` is `ingress` or `egress`, `absolute_direction` is `A_to_B` or `B_to_A`. A mapping applies only within its own declared interval and topology snapshot validity. **Do not infer** the reverse mapping from ingress/egress: B-to-A needs its own explicit source-backed mapping. Conflicting/missing site, mapping, topology, clock or service identity means unknown direction and blocks the relevant comparison.

## Static order and criterion validity is not measurement freshness

A static source record can be an order, design, SLA, approval or criterion. `static_authorities` explicitly identifies the `(source,source_native_id)` namespace of those records and a checked M2 `static_current` enum assertion with value `current` or `unknown`. The current assertion is an operator/source declaration, not authenticated truth. Do not automatically discard a static document merely because its historical `event_time` is old; conversely, do not call a document current solely because it was recently collected. The common M3/M4 actual-observation binding currently requires an event timestamp and max-age check: introduce a narrowly scoped **static** binding validation path rather than bypassing or weakening that actual-evidence policy. It checks the same checked source identity, explicit service/object topology, nonfuture collection, authorization and binding validity at the request reference instant, but does not assign a collection time as the static record's event time or discard it solely for age. An undated static field can be preserved as undated only when its own source namespace has independently established applicable current authority below; this never manufactures an approval date. For a **usable** static declaration either:

1. its authority has both `static_valid_from` and `static_valid_until` source evidence refs, whose checked `unix_s` **values** establish that the entire relevant request/test/change interval lies in that validity interval; or
2. `static_current=current` has an explicit source event time equal to `reference_time`, a synchronized clock and zero declared uncertainty, independently corroborating applicability at that instant. Nonzero or unknown uncertainty does not establish exact-instant currentness; use the sourced validity interval instead.

All business date values come from cited source rows, never from their observation or collection timestamps. Source records with null event time retain that unknown; a recently collected undated approval is not assigned a fabricated approval date. A static source must still have nonfuture checked collection time, valid identity/provenance, scoped selected service and a verified operator-declared topology binding; it is *not* subject to the active-observation `max_age_seconds` solely for being old. A null/missing validity ref can be retained for a draft but cannot satisfy the dated-interval route. Static conflicting records or an explicit superseded/revoked status block comparisons. All source claims and mappings remain unauthenticated declarations.

## Required expected/actual fields

`field_inventory` is required; null means no usable approved field requirements and blocks technical conformance. Its exact fields are shown in the request. It selects one checked M2 inventory snapshot and source-qualified namespace, with `field_inventory_approval=approved`, nonnegative integer `field_inventory_count`, and `required_field_target` enum entry records. Check approval/current authority, unique target values, exact count, and exact set equality between `entry_evidence` and **all** `required_field_target` rows for that source/native namespace in the selected checked run. Every inventory entry must have exactly one matching `fields` declaration and every declaration must be in the inventory; callers cannot make an endpoint optional by omitting it. Additional operator-required supported field/target combinations are included as declared; an unrecognized field/target is an explicit unsupported requirement and blocks conformance rather than being discarded. The field, criterion and change-check inventories use the same narrowly scoped internal count/set/provenance verifier with role-specific fixed metrics; this is not a generic controller or workflow framework. The inventory is a source assertion, not proof that an unseen real-world order has no other requirements.

Each `fields` entry has exactly `{field,target,required_evidence,applicability_evidence,inapplicability_reason_evidence,expected_evidence,actual_evidence,actual_target_evidence,equivalence_evidence}`. `target` is `service`, `endpoint_a`, or `endpoint_b`; each `(field,target)` must be unique. Expected/actual/actual-target/equivalence refs may be null for an incomplete draft. The two nullable applicability refs are present for an explicit source `field_applicability=not_applicable` and a source `field_inapplicability_reason` controlled token; they must be in the same currently authorized field-target namespace. No applicability ref means the approved inventory's requirement remains required; `not_applicable` plus reason is surfaced for human review and is not an automatic waiver. Each checked source `required_field_target` value is exactly `<field>_<target>` (for example `vlan_endpoint_a`), and must match the entry's `field`, `target` and `required_evidence`. A requested role alone never establishes applicability or completeness. `expected_<field>` must have the order source and the source-native field-target identity named by that approved inventory entry; an independently current static authority covers that identity. `actual_<field>` and `actual_field_target` must be fresh checked rows, source-qualified to the same actual point/resource and event window; `actual_field_target`'s allowlisted value must equal the approved field-target token. The `actual_<field>` and `actual_field_target` rows must also have equal direction metadata. Both may explicitly say `unknown` for a configuration fact; conflicting direction values yield `field_scope_mismatch`. The actual point must have the explicit selected endpoint's verified site-to-point/service topology mapping. Multiple possible target/value associations are ambiguous, not paired by order. For the service-level targets, the bound resource must be the selected service or its explicitly verified circuit object.

The minimum supported complete order has **service targets** `circuit`, `bandwidth`, and `sla_profile`; it also has separate **endpoint_a and endpoint_b targets** for `endpoint`, `vlan`, `vrf`, `ip_prefix`, `bandwidth`, `mtu`, `qos`, `routing`, and `security`. Each endpoint is compared to its own `expected_<field>` and `actual_<field>` under that endpoint role, not to the other endpoint's value. Different legitimate A/B VLAN/QinQ, VRF, addressing, MTU, QoS or policy labels are allowed when each agrees with its own explicitly sourced design and scope. Missing B-side evidence remains unverified. An inventory may explicitly mark a listed target not applicable only with a separate source-backed reason and human review; do not silently omit or automatically waive it. Unsupported/unknown applicability blocks automatic technical conformance. Required field names and value handling are:

| Field | Source value form and comparison |
| --- | --- |
| `circuit`, `endpoint` | Controlled aliases, mapped to the declared context circuit or the selected A/B site with explicit service relationships. |
| `vlan`, `vrf`, `ip_prefix` | Operator-controlled VLAN/QinQ, VRF and address/prefix **aliases**. No subnet containment, CIDR normalization, implicit QinQ translation or identity inferred from names. |
| `bandwidth`, `mtu` | Finite numeric values with exact raw units; MTU must explicitly be IP/L3 packet bytes, never a TCP/ICMP/application payload size. |
| `qos`, `routing`, `security` | Explicit controlled design/observed labels; matches establish only the supplied scoped configuration facts. |
| `sla_profile` | Controlled SLA profile identity/association, not proof that the SLA was met. A real criterion and test matrix are separately mandatory. |

Each checked row must have a nonnull value and positive sample count. Static expected rows must be within an accepted `static_authorities` namespace; actual rows use fresh actual-evidence validation. Compare within the **same approved target**. For controlled aliases in the same source-qualified namespace, compare exact values and types. Across distinct source-qualified namespaces, a same-looking label is not an identity link: require a valid, applicable five-row `equivalence_evidence` relation before deciding alias equality. `equivalence_evidence` is null or exactly `{relation,expected_run,expected_id,actual_run,actual_id}`, each a qualified reference. Those five checked, scoped source rows must have respectively metrics `field_equivalence`, `equivalence_expected_run`, `equivalence_expected_id`, `equivalence_actual_run`, and `equivalence_actual_id`; relation has value `declared_equal` or `declared_different`, and the other four controlled enum values exactly equal the corresponding expected/actual reference's `run_id` and `evidence_id`. They share a source-qualified mapping identity, operator authority, temporal validity and verified service binding. Thus the evidence names the precise expected/actual pair; a generic relation row or caller-supplied pair is insufficient. When applicable evidence says `declared_equal`, treat the aliases as matching even if their source spellings differ. When it says `declared_different`, report a sourced mismatch even if their literal spellings match. Missing, malformed, conflicting or inapplicable relation evidence leaves the comparison `unverified`; do not infer identity from names. These source assertions are operator declarations, not authenticated truth. Finite numeric quantities compare by exact value type and raw unit; an equivalence relation never converts, normalizes or overrides a numeric comparison. No inferred numeric threshold, unit conversion or arbitrary text comparison is allowed. A differing source/object scope still requires verified service binding.

## Source-backed criterion inventory, SLA and test matrix

`criterion_inventory` is required; it is null when no approved inventory was supplied, which blocks technical conformance. Its exact fields are shown above. `run_id` identifies one checked M2 source snapshot; `source`/`source_native_id` identify the single approved inventory namespace. `approval_evidence` must be a current, source-qualified `criterion_inventory_approval=approved` record with its original approval observation time (unknown is not backfilled). `count_evidence` must be a current `criterion_inventory_count` record containing a nonnegative integer. `entry_evidence` lists unique qualified refs to all `required_criterion` records in that same run and namespace; each has a controlled criterion-ID value. Inspect **every** matching `required_criterion` row in that checked snapshot, require exact set equality with `entry_evidence`, and require the sourced count to equal the number of distinct entries. A caller cannot omit a failed or inconvenient criterion from the request to make the remaining list pass. Duplicate IDs, a missing/extra referenced entry, inconsistent count, unknown approval or conflicting inventory records block conformance. The snapshot, count and approval are still supplied source assertions and do not authenticate or prove completeness of the real-world order beyond the supplied source.

Each inventory ID must match exactly one `criteria[].criterion_id`; every criterion in the request must appear exactly once in the approved inventory. For each entry, `criteria[].source` must equal the approved inventory source, and `criteria[].source_native_id` must equal that entry's `criterion_id`. This binds the criterion record to the selected inventory identity; an alternate native namespace cannot substitute. Each criterion additionally cites its own current `criterion_capability` enum source record (`throughput`, `delay`, `loss`, `jitter`, or `l3_mtu`) under that criterion identity. The nullable `applicability_evidence` and `inapplicability_reason_evidence` cite `criterion_applicability=not_applicable` and a controlled `criterion_inapplicability_reason` from that same current namespace; a null applicability ref retains the approved inventory requirement. For each of the five mandatory capability categories, the approved criteria and test matrix together must cover both absolute directions. Separate A-to-B and B-to-A criteria may jointly cover a category; a one-way-only matrix emits `criterion_inventory_incomplete` and remains unverified, not waived. The provider does not assume a single ping, configuration check or availability-only criterion covers these capabilities. A source may explicitly declare a capability `not_applicable` only with its own cited, source-scoped reason and human disposition; such a declaration is **not** an automatic waiver and keeps technical status unverified pending human review. No implicit optionality, synthetic pass or guessed waiver.

Each `criteria` entry cites a source-qualified static criterion namespace. All listed refs must point to that namespace, be current under `static_authorities`, and carry these exact M2 metric/value roles:

- `criterion_metric`: an explicitly allowlisted actual metric name (`measured_throughput`, `measured_loss`, `measured_latency`, `measured_jitter`, `measured_availability`, or `measured_ip_mtu`). Mandatory capability mapping is exact: `throughput` → `measured_throughput`, `delay` → `measured_latency`, `loss` → `measured_loss`, `jitter` → `measured_jitter`, and `l3_mtu` → `measured_ip_mtu` in explicit IP/L3 bytes. A differently named or availability-only observation cannot satisfy those categories by relabeling.
- `criterion_aggregation`: `mean`, `min`, `max`, `p95`, `p99`, or `single`. A `mean` never implies a percentile.
- `criterion_comparator`: `gte`, `lte`, or `eq`.
- `criterion_threshold`: finite number with the exact raw unit that the actual observation must supply; no hard-coded value or unit conversion. Throughput, delay, loss, and jitter thresholds must be nonnegative. An L3 MTU threshold must be a positive integer number of IP packet bytes.
- `criterion_method`: controlled, explicitly sourced method label; no implementation or compliance is inferred from a label.
- `criterion_min_samples`: positive integer. `criterion_direction`: `A_to_B`, `B_to_A`, or `both`; `both` requires a separate independently mapped row per absolute direction.
- `criterion_calibration_policy`: `required` or `not_required`; missing/unknown is unverified. A required policy needs a sourced instrument identity and source-provided calibration validity covering the test interval; missing calibration remains unknown, never assumed valid.
- `criterion_window_start`, `criterion_window_end`: checked `unix_s` **values** that bound the approved test interval. Their own source observation `event_time` remains separate and may be unknown; never substitute collection time for it.

Each `test_results` entry cites a checked measurement with the exact criterion metric name, a finite value, matching raw unit, positive count meeting the sourced minimum, explicit relative direction and an independently validated absolute mapping. Throughput, delay, loss, and jitter values must be nonnegative; L3 MTU must be a positive integer number of IP packet bytes. The actual `method`, `aggregation`, window-boundary, and required instrument/calibration evidence must support the same measured direction, service, object, point, and source-qualified operation as the measurement. Do not use a same-source/resource row from another direction to complete a test. If these role facts are absent or incompatible, leave the row unverified and use the applicable `missing_test_evidence`, `missing_direction_mapping`, `test_method_mismatch`, or `test_measurement_mismatch` gap.

Categorical roles are sourced string values with the role's controlled label or alias; do not coerce a numeric value into a method, aggregation, direction/mapping, or instrument identity. For change metadata, `change_scope`, `change_impact`, `change_approval_reference`, `rollback_trigger`, `rollback_owner`, and `residual_risk` are likewise sourced string labels/tokens, not numeric quantities. Numeric values in these roles are unusable and keep the affected review incomplete.

Actual `window_start`/`window_end` checked `unix_s` values must be explicit, ordered, inside the approved window, incident window and validity scope. The complete event-time uncertainty interval of each actual observation used for the test must fit inside its applicable actual window. This applies separately to the measurement and every actual supporting method, aggregation, window-boundary, direction-mapping, and instrument observation; a point estimate inside the window is insufficient when its uncertainty extends beyond it. Calibration authority and validity-date records are static source facts: evaluate their authority and interval coverage separately, and do not require their observation timestamps to fall inside the actual test window. The result and collection must be fresh. A window-boundary record's observation date remains separate from its boundary value. These records must be bound to the same measured point and source-qualified operation; a polling interval does not prove the coverage window or whether the sample is a mean or percentile. Match aggregation, direction, time and raw unit before applying the cited comparator; no result may inherit a different criterion's method, endpoint, scope or SLA. Keep actual observations out of timeless static-authority conflict checks: actual conflicts require compatible evidence roles and overlapping event-time uncertainty. Unrelated old or undated static rows must not create actual freshness gaps. The measurement observation and all relevant method/window/mapping/profile refs appear in its matrix row, including qualified counterevidence or explicit gaps.

`instrument_evidence`, `calibration_evidence`, `calibration_start_evidence`, `calibration_end_evidence` are nullable. A supplied `instrument_id` must be a nonempty controlled string pseudonym whether calibration is required or not; an invalid supplied identity makes the affected test unverified with `missing_test_evidence`, while an absent optional instrument remains absent. When calibration is required, require a bound fresh `instrument_id` observation plus current-authority `calibration_status=valid`, `calibration_start`, and `calibration_end` rows whose source-native ID equals that instrument alias and whose source/resource matches it. The explicit source-valued `unix_s` calibration interval must cover the actual test window. Never infer calibration from tool name or assume one timestamp validates an instrument. If calibration is explicitly not required, do not require `calibration_status=valid` or calibration-window coverage. Retain supplied calibration status/date facts only when each is independently checked, current and valid for its own role, and associated by source/native/resource with the valid supplied instrument; they do not imply that calibration is valid. Missing or unusable optional calibration refs remain null/omitted and do not by themselves add a required-calibration gap. Do not fabricate absent metadata. Thresholds/criteria/measurements have no implicit units or vendor defaults.

## Change-review request

When `change_review` is non-null, its exact object is:

```json
{
  "phase": "pre_change",
  "scope_evidence": {"run_id":"change-run","evidence_id":"ev-000000000001"},
  "impact_evidence": {"run_id":"change-run","evidence_id":"ev-000000000002"},
  "planned_start_evidence": {"run_id":"change-run","evidence_id":"ev-000000000003"},
  "planned_end_evidence": {"run_id":"change-run","evidence_id":"ev-000000000004"},
  "approval_evidence": {"run_id":"change-run","evidence_id":"ev-000000000005"},
  "approval_reference_evidence": {"run_id":"change-run","evidence_id":"ev-00000000000a"},
  "rollback_trigger_evidence": {"run_id":"change-run","evidence_id":"ev-000000000006"},
  "rollback_owner_evidence": {"run_id":"change-run","evidence_id":"ev-000000000007"},
  "residual_risk_evidence": [{"run_id":"change-run","evidence_id":"ev-000000000008"}],
  "check_inventory": {
    "run_id":"change-run","source":"change-source","source_native_id":"check-inventory-alias",
    "approval_evidence":{"run_id":"change-run","evidence_id":"ev-00000000000b"},
    "count_evidence":{"run_id":"change-run","evidence_id":"ev-00000000000c"},
    "entry_evidence":[{"run_id":"change-run","evidence_id":"ev-000000000009"}]
  },
  "checks": [{
    "check_id":"check-1",
    "required_evidence":{"run_id":"change-run","evidence_id":"ev-000000000009"},
    "precheck_evidence":null,
    "planned_metric_evidence":null,"planned_method_evidence":null,
    "planned_criterion_evidence":null,"planned_comparator_evidence":null,"planned_direction_evidence":null,
    "postcheck_evidence":null,"postcheck_method_evidence":null,"postcheck_direction_evidence":null,
    "postcheck_window_start_evidence":null,"postcheck_window_end_evidence":null
  }]
}
```

`phase` is exactly `pre_change` or `post_change`. All evidence refs may be null for an incomplete draft, and arrays may be empty; missing risk declaration is unknown, not 'no risk'. `scope_evidence`, `impact_evidence`, `rollback_trigger_evidence`, `rollback_owner_evidence` and risk refs are controlled M2 enum/alias facts (`change_scope`, `change_impact`, `rollback_trigger`, `rollback_owner`, `residual_risk`) from a current static authority. Planned dates, approval state/reference, rollback metadata, risks, and checks must be checked against the selected change's exact source/native identity and bound resource, established by its scoped change record. A same-looking change label or an approval from another change identity cannot supply the selected change's fact; preserve opposing actual refs and leave the review blocked with `change_review_incomplete`. Do not echo an invalid or unassociated metadata/approval ref in the result: leave its output field null or omit it even when the underlying row is checked. `planned_start_evidence`/`planned_end_evidence` use checked `change_window_start`/`change_window_end` **values** in `unix_s`; their original source observation/approval times remain separate. `approval_reference_evidence` is a controlled source-supplied `change_approval_reference` token, not proof of approval. `approval_evidence` must be a source `change_approval` observation with its original event time and current validity; merely providing a token, current collection time or configuration text does not constitute approval. Before a change, a sourced `pending` or `approved` state may accompany a complete draft for human review; the event time of a `pending` state is a status observation, not an approval date, and no approval date is inferred. It never grants permission to execute. In post-change review, require a sourced `approved` state with known original approval time no later than the planned start. Even approved evidence does not authorize this provider to execute a change.

`check_inventory` is null or has exactly the shown fields. Its checked `change_check_inventory_approval=approved`, nonnegative integer `change_check_inventory_count`, and all `required_change_check` rows form a single source-qualified inventory snapshot. Check exact count, unique IDs, completeness against *all* matching inventory entries in that checked run, and one-to-one coverage by `checks`, just as for `criterion_inventory`. A caller cannot remove an inconvenient check.

Each `checks` entry has a unique safe `check_id`, a source `required_change_check` enum value matching that ID, and source-backed `planned_postcheck_metric`, `planned_postcheck_method`, `planned_postcheck_criterion`, `planned_postcheck_comparator` (`eq`, `gte`, `lte`) and `planned_postcheck_direction` facts for that check. Validate all plan roles and their supported values in both `pre_change` and `post_change`; an unsupported comparator/direction, absent sourced metric or method, or unusable criterion makes the change review incomplete (`change_review_incomplete`). The criterion record contains the actual source-declared finite threshold or controlled expected enum and its raw unit; no request value is a criterion. For `eq`, the source criterion may be a controlled enum or finite number. `gte` and `lte` require a finite numeric criterion and explicit unit. Apply the nonnegative throughput, delay, loss, and jitter domains and positive integral IP-byte MTU domain when a planned metric maps to one of those supported capabilities. Each actual check must have explicit evidence that it refers to the same check ID and service/resource; a mere matching alias across sources is insufficient. Preserve owner/trigger/source refs. In `pre_change`, require complete prechecks and these explicit, usable postcheck plans/criteria, but do **not** require or invent future postcheck results. A complete pre-change draft can be `ready_for_human_review` with human signoff still pending. In `post_change`, require a fresh bound measurement of the exact planned metric, a matching actual method, explicit mapped direction and explicit checked `unix_s` window boundary values; actual method, direction, and window evidence must apply to that measured check. Require the complete event-time uncertainty interval of the postcheck measurement and every actual supporting method, direction-mapping, and window-boundary observation to fit inside its applicable postcheck window. Apply the source-declared comparator to compatible actual and criterion values rather than treating a naked `pass` token as proof. Prechecks must be before the planned window and actual postchecks after it with nonoverlapping clock uncertainty. Actual check `event_time`, not its collection time or planned-date value, determines ordering. Missing/failed/mismatched required checks, an undated or unapproved post-change action, incomplete rollback metadata or unresolved residual risk keep the review blocked or pending human review. Emit only validated applicable evidence refs; unavailable role refs are null/omitted, never echoed from the request. In particular, if the postcheck measurement is absent or invalid, do not emit its method, direction, or window refs as if they applied to that check. This review does not execute or approve a plan.

## Result and acceptance gates

```json
{
  "schema_version":1,
  "service":{"topology_run_id":"topology-run","object_id":"service-alias"},
  "technical_status":"unverified",
  "human_signoff":"pending",
  "acceptance_status":"blocked",
  "field_results":[],"test_matrix":[],
  "change_review":{"status":"not_requested","evidence_refs":{},"checks":[],"gaps":[]},
  "counterevidence":[],
  "missing_requirements":[],
  "gaps":["missing_field_inventory"],
  "draft_report":"# Service acceptance review\n\n## Review state\n\nTechnical status: unverified. Human signoff: pending. Acceptance status: blocked.\n\n## Findings\n\nNo field or test result is established.\n\n## Outstanding evidence\n\n- missing_field_inventory\n\n## Human review\n\nHuman signoff remains pending."
}
```

`technical_status` is `conformant`, `nonconformant`, or `unverified`; it describes only cited technical criteria, not service acceptance or recovery. A known, comparable mismatch or failed criterion may yield `nonconformant` even when other fields are missing; report all gaps. `conformant` requires exact coverage of the approved source-backed field and criterion inventories, all required **service and A/B endpoint targets** matched to their own design under the explicit equivalence/scope rules, all five capability categories, current approved SLA and complete source-backed criteria, a complete passing test matrix for every required absolute direction, required calibration and no conflicting/stale/wrong-object/partial evidence. A single ping, successful configuration check, authentication or favorable single measurement is never sufficient. Missing SLA, threshold, method, window, topology, direction, criterion provenance, required mapping or calibration yields unverified. `human_signoff` is always `pending`; `acceptance_status` is `awaiting_human_signoff` only when technical status is conformant, otherwise `blocked`. There is **no** automated `accepted` state, approval execution or recovery transition.

`field_results` entries have `{field,target,status,required_ref,expected_ref,actual_ref,actual_target_ref,equivalence_ref,topology_ref,counterevidence,gaps}`; `test_matrix` entries have `{criterion_id,absolute_direction,measurement_point,status,measurement_ref,criterion_refs,method_ref,window_refs,instrument_ref,calibration_refs,topology_ref,direction_mapping_ref,counterevidence,gaps}`. `measurement_point` is the validated operator-mapped point alias for the observation scope, or null; it is not a device-cause or fault-localization claim. `absolute_direction` is `A_to_B`, `B_to_A`, or null. For an incomplete required criterion, emit an explicit `unverified` matrix row using only independently checked, current, scoped, conflict-free criterion and direction evidence. If the applicable criterion direction proves both directions, emit one row for each; if it proves one, emit only that row. If direction is missing, unsupported, or conflicted, set it to null; never infer a direction. Validate each criterion fact under its existing role rules before including its ref, including on the incomplete-row path. A checked but role-invalid fact, such as a numeric method, is not a validated criterion ref and must be omitted; retain other independently valid criterion and direction refs. `window_refs` contains only validated applicable boundary refs; suppress refs for invalid timestamp-valued boundaries. When measurement, measurement point, or method evidence is unavailable, its matrix field is null and the row has `missing_criterion_evidence`; an invalid supplied instrument identity makes the affected test unverified with `missing_test_evidence`. Retain real opposing refs as counterevidence. Status is `match`/`mismatch`/`unverified` for fields and `pass`/`fail`/`unverified` for tests. Every pass/fail/match/mismatch cites actual run-qualified evidence, topology and mapping references, and any conflicting records as counterevidence; never manufacture an empty-counterevidence claim of health. A criteria/test without a resolvable selected service/object remains unverified. `missing_requirements` is always an array of `{kind,id,required_ref}` entries for requirements present in a checked approved inventory but omitted from the request; `kind` is `field`, `criterion`, or `change_check`, `id` is the controlled inventory ID, and `required_ref` points to the actual checked requirement. When an inventory is missing or unusable, do not invent entries; on timeout return `[]`. Top-level `counterevidence` retains contradictory source refs even when an inventory or criterion cannot be used.

Change-review status is `not_requested`, `blocked`, or `ready_for_human_review`. `change_review.evidence_refs` is `{scope_evidence,impact_evidence,planned_start_evidence,planned_end_evidence,approval_evidence,approval_reference_evidence,rollback_trigger_evidence,rollback_owner_evidence,residual_risk_evidence}`. The first eight values are nullable qualified refs and `residual_risk_evidence` is a qualified-ref array. When no change review is requested or analysis times out, this object is `{}`. Each output check has `{check_id,status,required_ref,precheck_ref,plan_refs,postcheck_ref,postcheck_method_ref,postcheck_direction_ref,postcheck_window_refs,gaps}`; `status` is `unverified` or `ready_for_human_review`. `plan_refs` contains non-null qualified refs in this order: planned metric, method, criterion, comparator, direction. `postcheck_window_refs` contains qualified boundary refs. Every check carries its real supporting refs and gaps.

`draft_report` is bounded Markdown inside the result JSON; the complete request/result, including the report, is limited to 1 MiB. It summarizes the selected service and endpoint scope, technical/change/human/acceptance states, field outcomes and their qualified refs, test outcomes and their qualified refs, `missing_requirements`, and—when requested—change scope, impact, planned window, approval and approval-reference, rollback trigger/owner, residual-risk refs, check results, and outstanding gaps. It ends with human signoff pending. Use controlled pseudonyms, fixed headings/prose, and run-qualified refs only. Do not include raw source text, source paths, commands, credentials, real addresses, or generated files. The report does not itself mark a service accepted or authorize a change.

When a change review was requested, `acceptance_status` additionally remains `blocked` while that review is blocked, even if the separate technical test/configuration assessment is conformant. Only technical conformance **and** a not-requested or ready-for-human-review change assessment can yield `awaiting_human_signoff`. Keep technical status independent so a partial change plan does not erase valid technical facts; add a public control where every technical criterion passes but a required post-change check is absent. No output path can imply that a blocked change was accepted.

### Stable gap vocabulary

The top-level, field, test, and change-review `gaps` arrays use these fixed codes where applicable:

- `invalid_delivery_scope`, `missing_field_inventory`, `field_inventory_incomplete`, `unsupported_or_missing_field_requirement`, `human_applicability_review`
- `missing_field_evidence`, `field_scope_mismatch`, `field_unit_mismatch`, `missing_field_equivalence`
- `missing_criterion_inventory`, `criterion_inventory_incomplete`, `missing_criterion_evidence`, `missing_test_evidence`, `ambiguous_test_evidence`
- `missing_direction_mapping`, `test_window_mismatch`, `test_method_mismatch`, `test_measurement_mismatch`, `missing_calibration`
- `conflicting_observations`, `change_review_incomplete`, `analysis_timeout`
- Shared checked-evidence/binding gaps: `missing_evidence`, `clock_uncertain`, `stale_or_outside_window`, and `unverified_or_mismatched_mapping`.

Emit the specific applicable gap while preserving all independent gaps and contradictory refs. Do not replace a missing or unusable source with a pass, inferred relationship, or guessed threshold.
