# M2: bounded offline carrier evidence ingestion

Implement [issue #6](https://github.com/Rupert-WLLP-Bai/netops-mw-skill/issues/6) from merged M1 at
`b2e7ee524d83ebb9dee3e51dd471c053c48b6974`, on `feat/carrier-m2-offline-adapters`. The active user
goal now authorizes completing all milestones and merging their separate reviewed PRs; this supersedes
the earlier instruction to stop for approval after M1. Implementation, final validation and final Sol
review remain separate phases. No tests run while implementation or corrections are in progress.

## Interface and responsibility

- Add a self-contained offline ingestion CLI and private implementation within `netops-incident`.
  Reuse M1 carrier context/evidence contracts and the existing four-summary run import interface.
  Do not add another incident controller or change the standalone collector or PCAP workflow.
- Require an explicit source directory and confined relative input, versioned configuration, a new
  private raw destination and a separate new visible run destination. Configuration supplies source
  identity, actor/authorization references, collection/reference times, clock declarations, freshness
  policy, explicit identifier aliases, and metric/unit/value allowlists.
- Support six named versioned generic formats: telemetry JSON, telemetry CSV, topology JSON, optical
  JSON, a declared CLI key/value export, and a documented safe RFC 5424 syslog-header subset. Optical
  CSV can use the generic telemetry CSV contract. Undeclared vendor output, opaque text and binary
  OTDR/SOR are not interpreted as supported vendor formats.
- Numeric measurements retain their supplied unit, direction, count, sampling interval and counter
  semantics. Controlled enum facts may be retained only through an explicit value allowlist; no
  arbitrary source prose becomes a normalized operational fact.
- Produce `manifest.json`, `evidence.jsonl`, `diagnosis.json`, `report.md` and a sanitized derivative
  referenced as a confined run artifact. The result can be imported by the existing case controller.
  Successful parsing is not a fault, root cause, topology verification or business-health conclusion.

## Data protection and bounds

Keep the exact checked raw snapshot and reversible alias configuration in the separate private
destination with restrictive permissions. The visible derivative contains only declared safe fields
and pseudonyms, raw/visible hash relationships and provenance. Do not expose original source paths,
unknown identifiers, private mappings, credentials, opaque transcript lines or syslog message bodies.
Treat command-looking and instruction-looking source text as untrusted data; never execute it.

Validate the explicit format/version and strict record shape. Reject malformed CSV/JSON, duplicate
keys, nonfinite values, unsafe paths, symlinks, special files, terminal controls and oversized input
without partial publication. Bound source/config bytes, lines, records, fields, nesting, traversal
work and visible output. Enforce parsing time with a trusted standard-library worker and a parent
watchdog, including termination and reaping; loop clock checks alone do not bound a slow parser.
Operate on the immutable source snapshot so the retained raw hash cannot diverge from parsed bytes.

Keep parse failure, unsupported format, parse timeout, stale data, clock uncertainty, unknown counter
semantics and incomplete topology distinct. Quality limitations may coexist. Deterministic IDs and
hashes use the same input/configuration and explicit reference times, not ambient wall clock or
destination paths. Publish new private/visible destinations without overwriting existing files and
clean newly staged data if publication fails.

## Deliverables and ownership

Terra owns runtime, CLI, tests and suite allowlist updates. Luna owns the bundled ingestion reference,
synthetic golden inputs and source/license manifest. The parent owns README links, validation and
review records, package checks, PR and integration. All project content is English. Synthetic fixtures
are labeled as such and excluded from product archives; no actual vendor interoperability is claimed.

After all code, tests, fixtures and contract documentation are frozen, run full regression, format and
privacy/hostile-input tests, deterministic double builds, clean extraction and managed case import.
Recheck the unchanged standalone collector and affected PCAP behavior. Only then request Sol's final
standards/specification reviews. Finish any required correction before rerunning final checks and
re-review. Open an independent M2 PR and merge only its reviewed, verified head before starting M3.
