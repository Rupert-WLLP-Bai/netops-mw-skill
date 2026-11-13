# Carrier service context and evidence contract

This contract extends the incident workflow with optional carrier context and evidence. It is vendor-neutral and describes operator-supplied identifiers and observations; it does not establish that an identifier, mapping, measurement, or source claim is true. The canonical object vocabulary is defined in the root `GLOSSARY.md`.

## Compatibility and ownership

Existing Internet evidence records, diagnosis records, and the four diagnosis states remain valid as they are. Carrier fields are additive and versioned. A missing `service_context` or `carrier_evidence` means that carrier context was not supplied; it does not make an old record invalid or imply that an affected service is unknown in reality.

The incident case owns its optional `service_context`. A case created without it retains legacy behavior and policy identity. A scope update that omits the field preserves the current context; an explicit `null` removes it. Adding, changing, or removing context changes the case policy identity, so verification and decision eligibility tied to the previous policy cannot be reused. Old records remain in the event history.

Imported run context is source context, not an assertion that it identifies the case's service. `service_context` and `carrier_evidence` supplied in `manifest.json` are covered by that file's existing hash. Carrier records point to existing evidence IDs; their referenced objects must be declared in that manifest's service context. The incident importer continues to retain the checked Agent-visible summaries in restricted case storage and references source artifacts by hash; it does not copy raw artifacts into the case.

## Service context

`service_context` has `schema_version: 1`, a nullable `service_ref`, an `objects` registry, and `topology` links. `service_ref` must identify a registry object of type `service`; `null` means the affected service reference is unknown. Object IDs are unique only within their context and are not globally identifying.

The registry accepts the 15 canonical object types: `service`, `customer_pseudonym`, `site`, `circuit`, `access_line`, `device`, `interface`, `vlan`, `vrf`, `session`, `path`, `alarm`, `measurement`, `sla`, and `acceptance_criterion`. Each object records its type, optional layer, identity state, source, source-native ID, and reason. Identity state is `known`, `unknown`, or `ambiguous`; unknown or ambiguous identity requires a reason. A source-native ID is kept distinct from the context-local object ID, must be present as a field, and may be null when unavailable. It must be controlled or pseudonymous when exposed in Agent-visible context. Do not use a device name, address, circuit label, or other source-native value as proof that two records refer to the same object.

The six layer values are `endpoint_lan`, `access`, `aggregation_subscriber_edge`, `ip_bearer_transport`, `internet_edge_interconnect`, and `destination_application`. A null layer means no layer assignment was supplied. The glossary describes their boundaries.

Each topology link names `from_id`, `to_id`, an operator-declared `relation`, a state, confidence, and reason. Link state is `verified`, `unverified`, or `ambiguous`; confidence (`low`, `medium`, `high`, or null) is separate from state. Unverified or ambiguous links require a reason. A verified link requires both endpoint identities to be `known`. “Verified” records an operator declaration in the supplied context; it is not an authenticated network fact. Never infer a link from matching text or registry order.

All schema fields are present; fields that can be unknown use null or an `unknown`/`ambiguous` enum as defined by the schema, with a reason where the contract requires one. The measurement object itself may be null. Do not replace missing identifiers, topology, clock quality, measurements, or semantics with a likely value.

## Carrier evidence envelope

`carrier_evidence` has `schema_version: 1` and a list of records. Each record references one existing `evidence_id` and zero or more context-local `object_refs`, and carries source and device-role provenance, event and collection timestamps, timezone, clock quality and uncertainty, artifact hash, redaction relationship, topology-mapping confidence, and an optional measurement. Evidence IDs are qualified by their run; repeated IDs in separate runs or sources do not identify the same observation or object.

`event_time` describes when the source says the event or measurement occurred. `collected_at` describes when the evidence was collected. They remain separate; neither is silently substituted for the other. `timezone` records the supplied time-zone context. `clock_quality` is `synchronized`, `skewed`, or `unknown`; `clock_uncertainty_seconds` is a non-negative estimate or null. A synchronized event time later than collection time is invalid. Unknown or skewed clock quality limits time correlation.

The redaction record contains `status` (`redacted`, `not_redacted`, or `unknown`), `raw_sha256`, `visible_sha256`, and optional `policy_ref`. When both `artifact_sha256` and `visible_sha256` are present, they must match; a declared artifact or visible hash must also match a hash declared by the referenced evidence record. These hashes establish byte consistency only; they do not authenticate the source or prove that redaction was sufficient. Restricted raw source artifacts and Agent-visible summaries are different artifacts with a declared relationship. Do not place secrets or unredacted customer identifiers in Agent-visible metadata.

A measurement is either null or a raw observation with `value`, `unit`, `direction`, `denominator`, `sample_interval_seconds`, `sample_count`, `missing_reason`, `counter_semantics`, and `reset_state`. Direction is `ingress`, `egress`, `bidirectional`, or `unknown`; counter semantics are `gauge`, `delta`, `cumulative`, or `unknown`; reset state is `none`, `reset`, `wrap`, or `unknown`. A null value requires a reason. Reset or wrap is valid only for cumulative or unknown counter semantics. M1 preserves the supplied value and unit: it does not normalize units, infer a denominator, derive a rate, or assign vendor-specific counter meaning. A reset, wrap, unknown unit, missing sample interval, or unknown direction remains an evidence limitation.

## Cross-record use

Treat each record as an observation from its stated source and scope. A source-native identifier, device role, or timestamp is not a topology mapping. The comparison helper requires equal, non-null `source` and `source_native_id` values, and requires every referenced object to be the declared service or have a direct verified link to that service. Referenced objects must have known identities, and both records need mapping confidence of `medium` or `high`. The helper does not infer a path through multiple links; a declared graph association is not proof of a physical forwarding path. Unrelated links do not affect the comparison.

The helper reports gaps named `value`, `unit`, `direction`, `denominator`, `sample_interval_seconds`, `sample_count`, `counter_reset`, `clock`, `sample_window`, `object_scope`, and `topology`. Both sample counts must be positive but need not be equal. Unit, direction, denominator, and sample interval must be known and equal; the literal denominator string `"0"` is also a gap. Counter semantics must be known and equal, and reset state must be `none`. Both records need synchronized clocks, known uncertainty, and event and collection times, and their event times must match. Missing or incompatible properties are gaps, not permission to guess or discard an observation.

The helper performs no unit conversion, diagnosis, threshold evaluation, or root-cause attribution. An empty gap list means only that the supplied records meet these contract compatibility checks. It does not prove that they describe the same real-world service, establish health or causality, authenticate the source, or prove mapping correctness.

Carrier metadata is limited to 1 MiB, nesting depth 16, and 2,048 characters per string. A service context permits up to 256 objects and 512 links; an evidence envelope permits up to 256 records. It is descriptive offline evidence only: this contract adds no vendor commands, device access, polling, thresholds, probes, configuration changes, or automatic repair.
