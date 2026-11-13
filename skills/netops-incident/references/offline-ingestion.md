# Offline carrier evidence ingestion

This reference describes the local, bounded import adapter in `scripts/ingest.py`. It imports explicitly selected, operator-supplied files; it does not connect to a device, execute transcript contents, perform a probe, or change a network. Existing PCAP analysis remains a separate workflow. Carrier imports use the versioned service and evidence contracts in [the carrier evidence contract](carrier-evidence-contract.md).

Run the incident-bundled adapter with a relative source path confined to a trusted source directory, a private configuration file, and two new output directories:

```bash
python scripts/ingest.py \
  --source-root /absolute/trusted/input \
  --source sanitized-export.json \
  --config /absolute/private/adapter-config.json \
  --out /absolute/new/visible-run \
  --private-out /absolute/new/restricted-import
```

The source must be a bounded regular file reached by a relative path under the trusted source root. The configuration must be a private regular file, and `--out` and `--private-out` must be new directories. The adapter reads the source as data only. On parser timeout it publishes a safe empty-result bundle with `parse_timeout` and exits successfully if publication completes; unsafe inputs, invalid configuration or destinations, and output failures return a nonzero result without publishing a partial bundle.

## Supported input formats

The caller selects one exact `format` in the private adapter configuration. A parser accepts only the declared generic form below. A vendor-specific export is supported only if it conforms to one of these forms; a similar-looking command output is not enough to claim compatibility.

| Format | Input form | Accepted content | Deliberately withheld or unsupported |
| --- | --- | --- | --- |
| `telemetry-json-v1` | UTF-8 JSON object with `format: "telemetry-json-v1"`, `version: 1`, and `records` | Typed metric observations using the field list below | Unknown properties, free-form text, undeclared metrics, units, and enum values |
| `telemetry-csv-v1` | UTF-8 CSV with the exact ordered header below; the configuration selects the format version | The same typed metric observations as JSON | Extra, reordered, duplicate, or missing columns; unlisted fields |
| `optical-json-v1` | UTF-8 JSON object with `format: "optical-json-v1"`, `version: 1`, and `records` | Generic typed optical measurements using the same record structure | Optical thresholds, binary OTDR/SOR files, proprietary sections, or inferred trace interpretation |
| `topology-json-v1` | UTF-8 JSON object with `format: "topology-json-v1"`, `version: 1`, `service_id`, `objects`, and `links` | Explicitly declared objects and relationships | Discovered or inferred links, undeclared object identities, and vendor-specific inventory syntax |
| `cli-keyvalue-v1` | UTF-8 text beginning with `# carrier-cli-keyvalue-v1`; subsequent lines are `metric=value` | Numeric values or configured enum values for allowlisted metrics | Opaque command output, unrecognized lines, commands, prompts, terminal control effects, and vendor-specific interpretation |
| `syslog-rfc5424-v1` | One RFC 5424 syslog message per UTF-8 line | Validates the standard priority, version, and timestamp; emits priority and event time | Hostname, application/process/message identifiers, structured data, and the `MSG` payload; no vendor payload is interpreted |

The syslog format is a local line-delimited file representation. [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424.html) defines a message format, not a file-storage format. This adapter reads only the listed header metadata; it does not implement a general syslog collector or transport. Its timestamp subset accepts UTC `Z` or `NILVALUE`; other valid RFC 5424 offsets are outside this adapter subset and produce `parse_error`.

Optical metrics can use `telemetry-csv-v1` when their rows conform to its generic typed schema. M2 does not parse binary OTDR/SOR files or claim compatibility with any manufacturer's report.

### Typed metric record

JSON telemetry and optical records require exactly these fields:

| Field | Accepted value | Handling |
| --- | --- | --- |
| `metric` | String in `metric_allowlist` | Unknown metric is rejected as a parse error. |
| `value` | Finite number, null, or a string explicitly allowed for that metric | Null remains missing; a missing reason is recorded. Enum values are categorical observations, not numeric measurements. |
| `unit` | Null or a string in `unit_allowlist` | Preserved as supplied; no conversion or normalization. |
| `direction` | `ingress`, `egress`, `bidirectional`, or `unknown` | Preserved; unknown direction limits comparison. |
| `denominator` | Null or an allowlisted unit token | Preserved; no inferred denominator. |
| `sample_interval_seconds` | Null or a positive finite number | Preserved; no rate is derived. |
| `sample_count` | Null or a non-negative integer | Preserved; no samples are fabricated. |
| `counter_semantics` | `gauge`, `delta`, `cumulative`, or `unknown` | Preserved. |
| `reset_state` | `none`, `reset`, `wrap`, or `unknown` | Reset or wrap is accepted only with cumulative or unknown counter semantics. |
| `event_time` | Null or UTC RFC 3339 timestamp | Kept separate from collection time. |
| `object_id` | Null or source-native ID present in the private pseudonym map | Never emitted as a raw ID. A mapped ID becomes a source-qualified pseudonymous declaration, not a cross-run identity or verified topology link. An unmapped ID is withheld. Telemetry, optical, and CLI formats do not include topology, so they report `incomplete_topology` even when an alias is supplied. A null event time adds `clock_uncertain`; collection time is not substituted for event time. |

CSV uses this exact header and field order; nullable cells are empty strings:

```text
metric,value,unit,direction,denominator,sample_interval_seconds,sample_count,counter_semantics,reset_state,event_time,object_id
```

The `topology-json-v1` object entries contain exactly `id`, `type`, and `layer`. The service reference is null or matches one declared input object. Link entries contain exactly `from_id`, `to_id`, `relation`, `state`, and `confidence`; relation values must be in `relation_allowlist`. IDs are translated through the private pseudonym map. Without a mapping, the adapter emits a deterministic context-local unknown ID based on that object's one-based input position, marks its identity unknown with a reason, and reports `incomplete_topology`. A verified link with an unknown endpoint is downgraded to unverified. Missing endpoints and duplicate raw IDs are parse errors; no relationship is inferred. Context objects and links appear in the manifest's `service_context`; the visible evidence records may be empty for a topology-only input.

### Adapter configuration

Configuration is a single private JSON object. Every key below is required; the pseudonym map may be empty. Identity, source, actor, authorization, metric, enum, and relation labels are operator-controlled safe tokens rather than raw customer or device identifiers. Unit labels are bounded printable strings and may contain punctuation (for example, `Mbit/s`, `bytes/s`, or `%`); timezone labels may be IANA names or numeric offsets.

| Key | Meaning |
| --- | --- |
| `format` | One of the six exact format selectors above. |
| `run_id` | Caller-supplied safe run identifier. |
| `source`, `actor`, `authorization_ref` | Operator-declared source, collecting actor, and authorization reference. These are provenance declarations, not authentication. |
| `collected_at`, `reference_time` | Explicit UTC RFC 3339 timestamps used for collection provenance and age evaluation. No wall-clock timestamp is substituted; a reference time earlier than collection time adds `clock_uncertain`. |
| `max_age_seconds` | Non-negative maximum age relative to `reference_time`. |
| `timezone` | Operator-declared IANA-style time-zone name or numeric UTC offset, such as `Asia/Shanghai` or `+08:00`; syntax is checked, but the host's timezone database is not consulted. |
| `clock_quality`, `clock_uncertainty_seconds` | Operator-declared clock state and non-negative uncertainty, or null uncertainty. |
| `metric_allowlist`, `unit_allowlist` | Exact allowed metric names and printable unit labels. |
| `value_allowlists` | Per-metric enum strings that may be accepted as categorical values; use controlled safe labels. |
| `relation_allowlist` | Exact topology relation labels allowed in output; use controlled safe labels. |
| `pseudonyms` | Private map from source-native IDs to unique safe aliases. Aliases must not equal any raw map key; the map is never copied to Agent-visible output. |

## Privacy boundary and output

The adapter snapshots the bounded source file into restricted local storage and keeps any reversible pseudonym map separately in private storage. Raw input text, raw identifiers, the map, and filesystem paths do not appear in Agent-visible output. Only allowlisted typed fields, safe aliases, fixed warning codes, and the provenance needed by the M1 contracts may appear in the visible derivative. Pattern-based scrubbing alone is not treated as proof that arbitrary text is safe; opaque values are withheld.

The visible run bundle contains `manifest.json`, `evidence.jsonl`, `diagnosis.json`, `report.md`, and `carrier-visible.json`. The manifest records a `carrier_adapter` object with format/version, parse status, quality codes, fixed warnings, source, actor, authorization reference, explicit collection/reference times, and timezone. Its `artifact_hashes` cover the visible bundle, including `carrier-visible.json`; evidence sources reference the visible artifact hash, and the M1 carrier redaction record links raw and visible hashes. These hashes check consistency, not source authenticity or redaction adequacy. `carrier-visible.json` has `schema_version: 1`, `parse_status`, `quality`, and typed `records`. Evidence IDs are deterministic sequential IDs in input order. Metric records populate M1 `carrier_evidence` with the event time from the row and collection/clock fields from configuration; a configured pseudonym is used only as `source_native_id`, while `object_refs` stays empty and `topology_mapping_confidence` stays unknown. Only `topology-json-v1` creates a `service_context`; it does not claim that this source context is the incident case's service. Parse error, unsupported format, or timeout yields no visible carrier records and one safe evidence record with a fixed observation status; `diagnosis.json` remains `insufficient_evidence`. The existing incident `import-run` flow remains the path for importing the completed four summary files; it validates and retains the manifest containing the carrier metadata.

The adapter stores the bounded raw snapshot as `raw.bin` and the reversible alias map as `pseudonyms.json` in a separate private directory created with mode 0700; each file uses mode 0600 where supported. Neither private file nor the adapter configuration is included in the Agent-visible run bundle. A topology-only import carries its `service_context` in the manifest; raw source IDs and the reversible map stay private.

Terminal control bytes make a text source malformed and produce `parse_error`; prompt-like content is always untrusted data, never an instruction. `cli-keyvalue-v1` accepts only its marker and allowlisted `metric=value` lines, and does not execute values or commands. Unknown CLI lines are omitted with the fixed warning `withheld_unrecognized_line`. `syslog-rfc5424-v1` discards fields that could contain identifiers or arbitrary message text and records the fixed warning `withheld_syslog_content`. It emits parsed priority and a UTC-Z timestamp or a null timestamp; the RFC version field is validated but not echoed. Other RFC-valid timestamp offsets are outside the supported subset and produce `parse_error`.

## Status, quality, and limits

`parse_status` is one of `complete`, `parse_error`, `unsupported_vendor_format`, or `parse_timeout`. It describes adapter handling, not network health. Independent quality codes can coexist with any successful parse:

- `stale`: an event timestamp is older than `max_age_seconds` relative to the supplied `reference_time`;
- `clock_uncertain`: an event time is absent, the supplied clock quality is not synchronized, uncertainty is missing, or the configured reference time precedes collection time;
- `unknown_counter_semantics`: a counter meaning is not established;
- `incomplete_topology`: a source object lacks a pseudonym, or the source-qualified alias has no supplied verified topology association. A matching alias across runs does not prove a shared object. Telemetry, optical, and CLI inputs always carry this quality flag because they do not define a topology context; topology-only data can carry it when identities or links are unknown or unverified.

Quality codes and warning codes are emitted as sorted lists and can coexist. Missing/unknown values, stale data, uncertain clocks, counter resets, and incomplete topology remain evidence gaps. The adapter does not set optical thresholds, infer units, convert values, claim a fault, or assign a root cause. A successful parse means only that the selected generic format was read within its declared limits.

Each input is limited to 1 MiB; configuration to 1 MiB; visible output to 2 MiB; input to 1,024 lines and 8,192 bytes per line; records to 256; fields to 2,048 characters; nesting depth to 16; and parser wall time to five seconds. Exceeding an input or output bound fails closed. No network access, shell execution, credential use, device command, active scan, upload, or automatic repair occurs.

## Synthetic golden fixtures and provenance

The repository's M2 golden inputs are self-authored synthetic examples. They contain no real subscriber, site, circuit, device, vendor transcript, alarm, or OTDR data. The fixture provenance manifest records each input path, format/version, synthetic origin, and license. Test fixtures and any private alias maps are development inputs; they are not included in the distributable Skill package.
