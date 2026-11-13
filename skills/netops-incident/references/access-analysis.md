# Offline access-analysis provider contract

This reference defines the optional incident-owned `scripts/diagnose_access.py` provider. It accepts checked local M2 run bundles and an operator-declared request; it does not import evidence, mutate a case, access a network or device, or decide recovery. Use the provider only when its Skill/package and Python runtime are available through explicit host discovery. Its implementation resides in the incident Skill; callers must not depend on a sibling installation path.

Run the provider with one UTF-8 JSON request file:

```text
python <discovered-netops-incident>/scripts/diagnose_access.py --input <absolute-request-file>
```

The process writes one deterministic JSON result to standard output. Invalid requests, invalid or unavailable evidence, hash/reference mismatches, and input errors return nonzero with a fixed error message and no partial result. A worker timeout returns a successful `insufficient_evidence` result with `service: null` and `analysis_timeout`.

## Request shape

The request is a strict UTF-8 JSON object. The reader decodes UTF-8 before JSON parsing; UTF-16 and UTF-32 encodings are rejected. All top-level keys and all nested fields shown here are required; additional or missing fields are invalid. Duplicate JSON keys, nonfinite values, symlinks, special files, traversal, and malformed timestamps are rejected. This strict behavior is limited to the new access-analysis path; existing readers keep their established defaults.

```json
{
  "schema_version": 1,
  "reference_time": "2026-11-13T00:10:00Z",
  "window_start": "2026-11-13T00:00:00Z",
  "window_end": "2026-11-13T00:09:00Z",
  "max_age_seconds": 600,
  "service": {"topology_run_id": "topology-run", "object_id": "service-alias"},
  "runs": [
    {
      "run_id": "topology-run",
      "run_dir": "/absolute/trusted/topology-run",
      "expected_summary_hashes": {
        "manifest.json": "<sha256>",
        "evidence.jsonl": "<sha256>",
        "diagnosis.json": "<sha256>",
        "report.md": "<sha256>"
      }
    }
  ],
  "bindings": [
    {
      "record": {"run_id": "observation-run", "evidence_id": "ev-000000000001"},
      "topology_evidence": {"run_id": "topology-run", "evidence_id": "ev-000000000001"},
      "service_id": "service-alias",
      "resource_id": "resource-alias",
      "source": "operator-controlled-source-token",
      "source_native_id": "source-qualified-alias",
      "valid_from": "2026-11-13T00:00:00Z",
      "valid_until": "2026-11-13T00:09:00Z",
      "authority": "operator-controlled-authority-token"
    }
  ],
  "optical_profiles": []
}
```

`reference_time`, `window_start`, `window_end`, and all evidence times use UTC RFC 3339. `window_start` must not exceed `window_end`, which must not be later than `reference_time`. `max_age_seconds` is finite and nonnegative. `service.topology_run_id` must name one declared run. Run IDs are unique; each run supplies an absolute `run_dir` and exactly four expected SHA-256 values for the named summary files. Binding and profile references use exactly `{run_id,evidence_id}`. Binding intervals are ordered. `source`, `source_native_id`, IDs, and `authority` are explicit operator declarations, not authentication.

The request's runs array in the example contains only the topology run for brevity. Every binding's observation run must also appear in the array. The executable request must supply actual absolute run paths and hashes; the placeholder strings above are explanatory and are not executable values.

An optional `optical_profiles` entry has exactly these fields:

```json
{
  "profile_id": "resource-alias",
  "device_model": "model-alias",
  "source": "operator-controlled-source-token",
  "valid_from": "2026-11-13T00:00:00Z",
  "valid_until": "2026-11-13T00:09:00Z",
  "direction": "ingress",
  "unit": "dBm",
  "limit_evidence": {"run_id": "profile-run", "evidence_id": "ev-000000000001"},
  "device_model_evidence": {"run_id": "observation-run", "evidence_id": "ev-000000000002"}
}
```

Profile direction is `ingress`, `egress`, or `bidirectional`; unit is a nonempty printable label up to 128 characters. The cited limit must be an imported, fresh `optical_rx_lower_limit` or `optical_tx_lower_limit` observation with a numeric value, matching direction and unit, and source/source-native identity matching `source`/`profile_id`. `device_model_evidence` must be a fresh, separately bound `device_model` enum whose value equals `device_model`; its mapped resource must match at least two comparable optical samples in the declared validity interval. The model binding establishes the mapped observation resource; the profile-limit reference is matched to the declared profile source identity. These are source declarations, not authenticated truth. The provider has no built-in optical threshold. An unknown, missing, or inapplicable profile leaves the profile-dependent inference unsupported.

## Run validation and source-qualified bindings

Each run is validated using the existing confined M2 summary reader and M1 contract validation. The four supplied summary hashes must match the actual bytes. The manifest run ID and artifact references must agree; its `carrier-visible.json`, evidence records, M1 `carrier_evidence` envelope, source hashes, and visible records must be mutually consistent. Only complete parsed M2 records are candidates for observations. A metric value is taken from the actual observation record; request fields cannot provide or override a metric value.

The selected topology run must contain a versioned `service_context` with the selected known service object. The topology evidence reference in each binding must refer to a real evidence record from that run whose observation has no metric row, as in the topology-only M2 snapshot. A bound resource must be known in that context and must be the service itself or have a direct verified relationship to it. The topology snapshot needs a fresh collection timestamp and a synchronized, known clock; it has no event time by design, and the provider does not invent one. Its declared links remain operator claims.

An observation binding is usable only when its record exists and is a complete carrier observation, its M1 source and source-native ID exactly equal the binding's source-qualified pair, and the source and topology runs validate. The bound service must equal the selected service. The observation's event-time uncertainty interval must fit the binding interval. Unknown/unverified/ambiguous topology, a wrong topology run or service, a missing identity, a source or alias mismatch, or an invalid time blocks attribution. A hostname, equal alias, or graph path does not create a binding.

Freshness is recalculated from the request's reference time, independently for collection and event times. Both must be present as applicable, ordered, within the declared maximum age and window, and have synchronized clock quality and known uncertainty. Uncertainty ranges must not overlap when a rule requires temporal order. Old M2 quality fields do not prove that evidence is fresh now.

## Observation vocabulary

Only these exact metric names are recognized; values come from M2's typed `observation.record` after bundle and carrier-contract validation:

| Metric | Recognized values and role |
| --- | --- |
| `optical_rx_power`, `optical_tx_power` | Finite numeric gauge observations; comparable only with a matching, cited profile. |
| `optical_rx_lower_limit`, `optical_tx_lower_limit` | Numeric profile limits; usable only through the matching `optical_profiles` citation. |
| `device_model` | A source-supplied enum matched to a cited model record and mapped resource. |
| `los_state`, `lof_state` | `active`, `clear`, `unknown`; source-reported state. |
| `pon_session_state` | `up`, `down`, `unknown`; a flap needs three comparable, strictly ordered alternating states in the same scope: up/down/up or down/up/down. |
| `fec_count`, `crc_count` | Numeric cumulative counters with known matching unit, direction, denominator, interval, clock and reset semantics. |
| `pppoe_auth`, `ipoe_auth`, `aaa_result` | `accept`, `reject`, `unknown`; authentication evidence only. |
| `dhcp_lease` | `assigned`, `failed`, `unknown`; address assignment evidence only. |
| `dhcp_pool` | `available`, `exhausted`, `unknown`; pool evidence only. |
| `service_vlan_expected`, `service_vlan_actual` | Explicit enum labels; a mismatch requires same scope and overlapping event-time uncertainty. |
| `forwarding_state`, `application_state`, `wifi_state` | `pass`, `fail`, `unknown`; each describes its own boundary. |

The implementation's fixed result gaps include `missing_evidence`, `clock_uncertain`, `stale_or_outside_window`, `unverified_or_mismatched_mapping`, `missing_reverse_direction`, `missing_comparable_optical_profile`, `conflicting_observations`, `unknown_counter_semantics`, `counter_semantics_not_cumulative`, `missing_sample_count`, `missing_sample_interval`, `missing_counter_unit`, `missing_counter_denominator`, `unknown_counter_reset_state`, `counter_reset`, `counter_discontinuity`, `unsupported_metric`, `unsupported_value`, `missing_observation_value`, and `missing_direction`. Unknown metric names are never reinterpreted. Unsupported enum or numeric values are excluded. A null, zero-count, or unsupported observation cannot satisfy direction coverage. Reverse-direction coverage is evaluated per supported metric/operation and request window. Opposite directions must have the same metric, source/native identity, mapped resource, overlapping event-time uncertainty, and compatible unit, denominator, interval, and counter fields; unrelated or unusable evidence does not fill the gap.

Comparisons require the same bound service/resource, source-qualified identity, compatible direction and unit, and matching denominator, sampling interval, and counter semantics where applicable. A denominator labeled literal `"0"` is unusable. For ordered trends, measurements need known uncertainty ranges with non-overlapping timestamp intervals. Counter reset or wrap prevents a delta. A relevant intermediate reset, wrap, or unknown counter state/semantics also blocks comparison across that discontinuity; do not skip it and compare outer samples. Emit `counter_discontinuity` alongside the applicable reset or unknown-semantics gap. This checked counter guard is shared by the access and transport providers. Optical readings conflict when both are fresh and have the same metric, bound resource, source/native alias, known unit and direction, matching denominator and sample interval, equal positive sample counts, known gauge semantics with no reset, overlapping event-time uncertainty, and unequal numeric values. No tolerance is inferred. Report neutral `optical_conflict` even without a profile: cite the conflicting observation as counterevidence, add `conflicting_observations`, and block degradation pairs using either conflicted sample. Conflicted samples also cannot support a normal-optics counterevidence claim. `optical_conflict` alone leaves status `insufficient_evidence`. Unknown counter meaning emits `unknown_counter_semantics`; a known gauge or delta used where a cumulative counter is required emits `counter_semantics_not_cumulative`. Missing or unusable sample counts, applicable intervals, units, denominators, and reset declarations produce their corresponding explicit gaps. Interval and denominator gaps apply when a counter-delta comparison needs those fields; gauge observations are not mislabeled as unknown counters. A positive comparable FEC/CRC increment is emitted only as neutral `counter_increase` evidence; it does not alone establish a fault, impact, optical cause, or a `fault_observed` status.

The supported findings are `optical_degradation`, neutral `optical_conflict`, `pon_flap`, `los_active`, `lof_active`, `auth_reject`, `dhcp_failure`, `dhcp_exhaustion`, `wifi_failure`, `forwarding_failure`, `application_failure`, `vlan_mismatch`, and neutral `counter_increase`. Optical degradation requires two comparable ordered readings that decline below the cited profile limit and have no unresolved contradictory optical evidence in the same scope and time. Normal profile-backed optics can be counterevidence to a Wi-Fi finding, but do not rule out failures outside their scope. A PON flap records either an observed up/down/up or down/up/down alternating session sequence; it does not establish physical fiber damage or an optical cause. Authentication acceptance can be counterevidence to DHCP failure, but does not establish forwarding or application health. VLAN mismatch is an observed mapping discrepancy, not a physical cause. Findings have `resource_id: null`; the provider does not infer a faulty device from a mapped observation.

## Result contract

The JSON result has exactly these top-level fields:

```json
{
  "schema_version": 1,
  "status": "insufficient_evidence",
  "service": {"topology_run_id": "topology-run", "object_id": "service-alias"},
  "findings": [],
  "gaps": ["missing_reverse_direction"],
  "next_checks": ["Obtain scoped, current and comparable evidence for unresolved gaps."]
}
```

Status is `fault_observed` when a supported fault observation exists and `insufficient_evidence` otherwise. A neutral `counter_increase` may be cited as a finding, but alone remains `insufficient_evidence`. Each finding contains `code`, `layer`, `resource_id`, `observation`, `hypothesis`, run-qualified `support`, run-qualified `counterevidence`, and `limitations`. A finding cites its source observation and the topology evidence used for the binding; profile-backed optical findings also cite their limit and model evidence. Counterevidence contains actual supplied evidence only. Layers are `access`, `aggregation_subscriber_edge`, `endpoint_lan`, or `destination_application` as applicable. Findings do not declare service recovery or prove that unobserved layers are healthy. Empty findings mean no supported rule fired; they do not establish a healthy service.

This request contract does not emit `healthy_within_scope` or `not_reproduced`. Those existing case diagnosis states remain governed by their own contracts and verification workflow; this analyzer cannot establish a complete service baseline or incident reproduction history.

## Resource bounds

The request is limited to 1 MiB, nesting depth 16, 2,048 characters per string, 20,000 traversed values, eight runs, 512 bindings, and 256 profiles. Run validation allows up to 2 MiB per run, 16 MiB aggregate checked bytes, 512 evidence records, and 512 topology links. The result is limited to 1 MiB. A trusted worker bounds whole-analysis time to five seconds; optical comparison work is limited to 4,096 pairs, findings to 512, and support and counterevidence to 32 references per finding. Limits are enforced fail-closed; they do not make an invalid or incomplete evidence set meaningful.
