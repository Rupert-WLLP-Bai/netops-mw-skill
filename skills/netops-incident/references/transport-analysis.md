# Offline transport analysis contract

This file is the complete version 1 contract for the optional incident-owned transport analyzer. It is also the source for interpreting manual transport evidence. The analyzer consumes checked, imported M2 evidence and returns JSON. It is deterministic and offline: it does not connect to or change a network, write a case, or accept caller-authored conclusions.

## Request

Invoke the incident installation's `scripts/diagnose_transport.py --input REQUEST.json` with one UTF-8 JSON object. The request is strict: all top-level fields are mandatory, unknown keys are rejected, and `transport_profiles` replaces the access analyzer's `optical_profiles`. `measurement_windows` is an additional required array. Both arrays may be empty.

```json
{
  "schema_version": 1,
  "reference_time": "2026-01-01T00:10:00Z",
  "window_start": "2026-01-01T00:00:00Z",
  "window_end": "2026-01-01T00:09:00Z",
  "max_age_seconds": 600,
  "service": {"topology_run_id": "topology-run", "object_id": "service-alias"},
  "runs": [
    {"run_id": "topology-run", "run_dir": "/trusted/topology-run", "expected_summary_hashes": {"manifest.json": "<sha256>", "evidence.jsonl": "<sha256>", "diagnosis.json": "<sha256>", "report.md": "<sha256>"}},
    {"run_id": "observation-run", "run_dir": "/trusted/observation-run", "expected_summary_hashes": {"manifest.json": "<sha256>", "evidence.jsonl": "<sha256>", "diagnosis.json": "<sha256>", "report.md": "<sha256>"}},
    {"run_id": "profile-run", "run_dir": "/trusted/profile-run", "expected_summary_hashes": {"manifest.json": "<sha256>", "evidence.jsonl": "<sha256>", "diagnosis.json": "<sha256>", "report.md": "<sha256>"}}
  ],
  "bindings": [{
    "record": {"run_id": "observation-run", "evidence_id": "ev-000000000001"},
    "topology_evidence": {"run_id": "topology-run", "evidence_id": "ev-000000000001"},
    "service_id": "service-alias", "resource_id": "resource-alias",
    "source": "operator-source", "source_native_id": "operator-resource-alias",
    "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-01-01T00:09:00Z",
    "authority": "operator-mapping-declaration"
  }],
  "measurement_windows": [{
    "subjects": [{"run_id": "observation-run", "evidence_id": "ev-000000000001"}],
    "start_evidence": {"run_id": "observation-run", "evidence_id": "ev-000000000002"},
    "end_evidence": {"run_id": "observation-run", "evidence_id": "ev-000000000003"},
    "aggregation_evidence": {"run_id": "observation-run", "evidence_id": "ev-000000000004"}
  }],
  "transport_profiles": [{
    "profile_id": "profile-alias", "source": "profile-source",
    "resource_id": "resource-alias", "direction": "egress", "unit": "percent",
    "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-01-01T00:09:00Z",
    "aggregation": "mean",
    "utilization_limit_evidence": {"run_id": "profile-run", "evidence_id": "ev-000000000001"},
    "aggregation_evidence": {"run_id": "profile-run", "evidence_id": "ev-000000000002"}
  }]
}
```

The request above is illustrative only. Paths and hashes must identify actual checked runs. Each relevant observation needs its own explicit binding. All references are `{run_id,evidence_id}` pairs; unqualified IDs do not identify evidence.

### Request bounds and validation

The request is limited to 1 MiB, depth 16, 2,048 characters per string, and 20,000 traversed values. It accepts at most eight runs, 512 evidence records, 512 bindings, 256 measurement-window declarations, and 512 topology links. Checked artifacts are bounded to 2 MiB per run and 16 MiB aggregate; results are bounded to 1 MiB. The trusted worker watchdog is five seconds. Counts are checked before repeated reads or allocation. Checked artifacts are cached once per run.

Validate UTF-8 JSON, checked artifact hashes, actual M2 source observations, and the M1 carrier evidence envelope including `carrier-visible.json`. Do not accept metric facts from the request, a path copied out of observation text, or a supplied conclusion. Reject unsafe inputs without returning partial results or private paths. A watchdog timeout returns `insufficient_evidence` with `analysis_timeout`. Recompute event and collection freshness against explicit `reference_time`; an earlier M2 stale flag or hostname does not establish current freshness or identity.

## Bindings and profiles

Each observation binding must match its actual `(source, source_native_id)`, selected service, and known resource. It cites a real topology snapshot from the selected topology run with a direct operator-declared verified link to the selected service. The topology snapshot has no event time: assess its fresh collection time, synchronized known clock, and binding validity. The binding interval must cover the observation's event-time uncertainty. A mapping is an operator declaration, not authentication or proof of responsibility. Equal aliases across runs do not merge source mappings. A hostname, graph path, or inferred subnet does not create a binding.

Each `transport_profiles` entry has exactly these fields: `profile_id`, `source`, `resource_id`, `direction`, `unit`, `valid_from`, `valid_until`, `aggregation`, `utilization_limit_evidence`, and `aggregation_evidence`. IDs are safe tokens; unit is a bounded printable raw unit; direction is `ingress`, `egress`, or `bidirectional`; times are explicit UTC; aggregation is `mean` or `max`. The profile contains no numeric threshold. Its cited M2 `utilization_limit` record supplies the value and must match source, source-native profile ID, unit, direction, and profile validity. The separate cited `profile_aggregation` record must match source/profile identity and the declared aggregation. The profile resource must be the explicitly bound resource of the compared observation. A missing, stale, ambiguous, or inapplicable profile is a gap; no threshold is assumed for utilization, loss, MTU, queue, or optical evidence.

Check contradictory profile facts over the actually used source-backed utilization measurement window, not only at the event time of the selected profile reference. An otherwise applicable limit or aggregation fact conflicts when its event-time uncertainty overlaps any part of that window and its source/profile identity, direction, and validity apply. Numeric limit conflicts require matching numeric units. `profile_aggregation` is categorical: compare its enum independently of optional unit labels. Historical facts outside the used window do not conflict. An applicable disagreement yields neutral `profile_conflict`, actual opposing refs as counterevidence, and `conflicting_observations`; suppress any queue/QoS condition that relies on the disputed profile.

## Measurement windows

Each `measurement_windows` entry has exactly `subjects`, `start_evidence`, `end_evidence`, and `aggregation_evidence`. These are qualified evidence references; `subjects` is a list. The M2 start and end records use metrics `window_start` and `window_end`, controlled enum value `declared`, and their explicit `event_time` fields are the boundaries. The aggregation record uses `window_aggregation` with value `mean`, `max`, or `counter_delta`.

Each window declaration, subject, and cited boundary/aggregation record needs an explicit valid binding to the same service/resource, source/native alias, and direction. Times and clock uncertainty must satisfy freshness, request window, and binding validity. A utilization window has exactly one subject and `mean` or `max`; a counter-delta window has exactly two ordered counter subjects and `counter_delta`. Counter event times must coincide with declared start/end. A polling interval, metric name, or `sample_interval_seconds` never establishes a measurement window. Missing or non-unique applicability yields `missing_measurement_window` or `ambiguous_measurement_window`, with no queue correlation.

## M2 metrics and values

Only the metrics below affect transport rules. They are read from checked typed M2 `observation.record` data after M2/M1 validation. Unknown/null values, raw text, unsupported units, or unknown fields do not become facts. Unsupported metrics produce `unsupported_metric`. Every record's object alias must have a valid binding; timestamps must be fresh and inside the request window, with known synchronized event and collection clocks and uncertainty.

| Metric | Accepted values and meaning |
| --- | --- |
| `bgp_peer_state`, `igp_adjacency_state` | `up`, `down`, `unknown`; control-plane state only. |
| `bgp_prefix_state`, `route_state` | `present`, `withdrawn`, `unknown`; a change alone does not prove service impact. |
| `route_prefix`, `service_prefix` | Safe explicit prefix aliases as enum values. Require exact equal labels; no subnet containment. |
| `route_vrf`, `service_vrf` | Safe explicit VRF aliases as enum values. Require known equal labels. |
| `next_hop`, `ecmp_path`, `flow_scope` | Controlled aliases. A path change is observational; flow scope is a pseudonym, never a raw five-tuple. |
| `lsp_state`, `sr_policy_state` | `up`, `down`, `unknown`; control-plane state unless separately correlated with scoped service failure. |
| `lag_member_state` | `up`, `down`, `degraded`, `unknown`; observed member state only. |
| `interface_utilization`, `queue_utilization`, `utilization_limit` | Finite nonnegative numeric gauges with explicit matching raw unit, direction, scope, and validity. Use a limit only through its cited profile. |
| `window_start`, `window_end`, `window_aggregation`, `profile_aggregation` | Controlled `declared`, `mean`, `max`, or `counter_delta` values as defined in the window/profile sections. |
| `interface_crc`, `interface_errors`, `interface_discards`, `queue_drops`, `qos_class_drops` | Nonnegative cumulative counters. A neutral increment needs two ordered, matching observations with known unit, direction, denominator, sample interval, and no reset/wrap. No rate conversion. |
| `qos_class` | Allowlisted pseudonymous class; class drop comparisons need a contemporaneous same-source/scope class observation. |
| `configured_mtu`, `effective_mtu`, `tunnel_overhead`, `probe_ip_packet_size` | Nonnegative numeric bytes, explicitly declared matching unit and direction. Packet sizes must explicitly use the Layer 3 IP-packet basis. No assumed headers or overhead. |
| `large_payload_result`, `small_payload_result`, `forwarding_state`, `service_operation` | `pass`, `fail`, `unknown`; explicit data-plane observations. |
| `fragmentation_needed` | `seen`, `not_seen`, `unknown`; capture absence does not prove filtering. |
| `traceroute_hop` | Controlled pseudonym token; a single-vantage hop is observational only. |

Do not interpret a string pattern in an imported route/log as a command or cause. Preserve ingress and egress separately. Bidirectional claims require independent evidence in both directions. Never substitute collection time for missing event time. `denominator: null` may mean not applicable; cumulative counters require matching non-null denominator and interval. Missing/unequal sample counts do not establish impact. Do not divide by zero, convert units, infer line rate, or invent a sample window.

Reverse-direction coverage is based only on actual, valid data-plane observations for the relevant operation: `service_operation`, `forwarding_state`, small/large probe results, utilization, and counters. A control-plane state (`bgp_peer_state`, `igp_adjacency_state`, LSP/SR, or LAG) or descriptive metadata cannot fill measured reverse coverage. A supported observation must have known positive sample count and match metric, source/native identity, bound service/resource, compatible measurement fields, and overlapping event-time uncertainty. Aggregate measurements additionally require a unique applicable declared window with matching start/end boundaries and aggregation. Missing, ambiguous, or incompatible windows retain `missing_measurement_window`, `ambiguous_measurement_window`, or `incompatible_window`. Point-event observations continue to use their explicit event scope. Otherwise retain `missing_reverse_direction` or the more specific evidence gap; zero or unknown samples never satisfy coverage.

## Diagnostic rules

All comparisons use qualified references and compatible intervals. When multiple rows could form a correlation, require matching source/native identity, service/resource, direction, and comparable event-time uncertainty. If multiple prefix, VRF, class, or flow aliases could apply, report ambiguity rather than pairing by order or hostname.

1. BGP peer, individual IGP adjacency (`igp_event`), IGP flap (`igp_flap`), LSP/SR, explicit scoped next-hop (`next_hop_event`), or LAG changes are neutral event observations. A peer reset or member change alone does not establish `fault_observed`. Cite a comparable service pass as counterevidence when present.
2. A withdrawn route correlates with service forwarding failure only when explicit route/service prefix aliases and VRF aliases match exactly and one unique applicable `flow_scope` value is supported by compatible source-scoped evidence; the evidence must also be bound, same-direction, and time compatible. Missing flow scope yields `missing_flow_scope`; contradictory applicable flow labels yield `conflicting_observations` and withhold route correlation. Report scoped correlation, not router/AS ownership or root cause. A route withdrawal alone is neutral.
3. Queue condition requires a cited applicable utilization limit; a matching utilization observation meeting it; and an increasing, no-reset drop-counter pair. Both require unique source-backed windows with matching boundaries; utilization aggregation must match cited profile aggregation, while the counter window uses `counter_delta` and its two counter event times coincide with the boundaries. Require matching service/resource, source identity, direction, clocks, raw counter unit/denominator/interval and compatible profile unit. If ordered counter samples cannot be compared because unit, direction, denominator, or interval differs, include `incompatible_counter_samples` and do not derive a delta. A relevant reset, wrap, or unknown counter semantics between endpoints blocks the pair; also include `counter_discontinuity`. Independently, any definitely time-ordered decrease among compatible cumulative samples inside a candidate interval blocks that outer pair even when every row says `reset_state: none`; report `counter_discontinuity` without guessing whether reset, wrap, or source error caused it. Keep otherwise valid pairs that do not span the decrease. The shared checked counter guard applies this rule to access and transport analysis. Contradictory applicable profile facts use the full used utilization window: numeric limit conflicts require matching units, while categorical aggregation conflicts ignore optional unit labels. A conflict yields neutral `profile_conflict`, cites the selected profile as support and actual opposing records as counterevidence, adds `conflicting_observations`, and suppresses dependent queue/QoS conditions; historical or outside-window facts do not conflict. Missing or zero sample count on any supported, nonmissing observation adds `missing_sample_count` independently of other valid operation coverage. Unsupported metrics remain `unsupported_metric`; they do not imply a sampling-count contract. A queue condition does not assert customer impact; that requires separately matched service-flow failure. QoS additionally requires a same-window observed class; when absent, include `missing_qos_class`. Drops alone are neutral.
4. An MTU discrepancy is neutral. A bounded MTU hypothesis uses explicit configured/effective L3 MTU and supplied overhead, plus comparable small/large probe outcomes and explicit IP packet sizes at the same scope, direction, and compatible time. Do not infer headers, overhead, ICMP filtering, or physical fault. Missing reverse direction, packet size/basis, or fragmentation-needed evidence remains a gap. When fragmentation-needed feedback is absent or explicitly `not_seen`, include `missing_pmtud_feedback`; this means visibility is missing and never proves filtering. Incomplete PMTUD evidence cannot prove a black hole.
5. ECMP or forward/reverse asymmetry requires independent same-service/flow-scope observations for each direction and compatible windows. Report only scoped asymmetry. One traceroute never identifies a failed node, PE/P, interface, AS, or symmetric path.

## Result

The output is one JSON object with exactly this envelope:

```json
{
  "schema_version": 1,
  "status": "insufficient_evidence",
  "service": {"topology_run_id": "topology-run", "object_id": "service-alias"},
  "findings": [],
  "gaps": ["missing_evidence"],
  "next_checks": ["Obtain scoped, current, comparable evidence for unresolved gaps."]
}
```

Each finding has `code`, `layer`, `resource_id`, `observation`, `hypothesis`, `support`, `counterevidence`, and `limitations`. `support` and `counterevidence` contain only actual `{run_id,evidence_id}` references. Cite source observations and topology evidence used for bindings; include profile/window/prefix/VRF/flow/class evidence when relied upon. Observation and hypothesis text is fixed safe wording, not copied arbitrary source text. `resource_id` is always `null` because the analyzer does not establish causal resource responsibility. `layer` is `ip_bearer_transport`, or `internet_edge_interconnect` only when directly supported.

Example neutral finding shape:

```json
{
  "code": "bgp_peer_event",
  "layer": "ip_bearer_transport",
  "resource_id": null,
  "observation": "A bound BGP peer state change was observed in the requested window.",
  "hypothesis": "This control-plane event does not establish customer service impact.",
  "support": [
    {"run_id": "observation-run", "evidence_id": "ev-000000000010"},
    {"run_id": "topology-run", "evidence_id": "ev-000000000001"}
  ],
  "counterevidence": [
    {"run_id": "observation-run", "evidence_id": "ev-000000000011"}
  ],
  "limitations": ["No affected prefix or service failure is established by this event."]
}
```

Neutral finding codes: `bgp_peer_event`, `igp_event`, `igp_flap`, `route_event`, `lsp_event`, `sr_policy_event`, `next_hop_event`, `lag_member_event`, `counter_increase`, `traceroute_observation`, `ecmp_asymmetry`, `mtu_discrepancy`, `pmtud_suspected`, `profile_conflict`. Scoped condition/failure codes: `route_service_correlation`, `queue_condition`, `qos_class_condition`, `mtu_scoped_failure`, `service_failure`. A `profile_conflict` finding records contradictory actual source facts; it does not claim a profile is authentic or that the network is faulty, and the disputed profile cannot support a queue/QoS condition. Neutral findings alone leave status `insufficient_evidence`. A profiled queue condition may produce `fault_observed`, but never implies a customer outage. `fault_observed` requires separately supported scoped failure or the explicit profiled queue condition, not a control event, counter increment, or absent response. Empty findings do not mean healthy. This analyzer does not emit `healthy_within_scope` or `not_reproduced`.

Fixed gaps include the M3 analysis gaps `missing_evidence`, `clock_uncertain`, `stale_or_outside_window`, `unverified_or_mismatched_mapping`, `missing_reverse_direction`, `conflicting_observations`, `unknown_counter_semantics`, `counter_semantics_not_cumulative`, `missing_sample_count`, `missing_sample_interval`, `missing_counter_unit`, `missing_counter_denominator`, `unknown_counter_reset_state`, `counter_reset`, `unsupported_metric`, `unsupported_value`, `missing_observation_value`, and `missing_direction`, plus transport gaps `missing_measurement_window`, `ambiguous_measurement_window`, `missing_transport_profile`, `incompatible_window`, `incompatible_counter_samples`, `counter_discontinuity`, `missing_flow_scope`, `missing_prefix_or_vrf`, `missing_mtu_evidence`, `missing_qos_class`, and `missing_pmtud_feedback`. Unknown metrics/values are excluded rather than reinterpreted. Add `analysis_timeout` on trusted worker timeout. Gaps describe why evidence cannot support a rule; they do not assign blame.

## Offline and attribution boundary

The analyzer accepts checked imported evidence only. It does not open live routing sessions, run device commands, change configuration, contact devices, or write to the case database. After importing the source runs, an operator may cite the returned run-qualified references through the existing case decision workflow. Do not include raw customer IDs, real network addresses, secrets, captures, or hidden evaluator answers in requests or reports.

No PE/P, router, interface, or AS is named as faulty from an observation point, route event, or traceroute hop. An explicitly bound resource may describe where evidence came from; it does not establish responsibility. Do not claim a numeric vendor threshold, standard compliance, or authenticated mapping from this contract. Profiles and mappings are operator-supplied claims; numeric evidence comes only from the cited checked M2 observations.
