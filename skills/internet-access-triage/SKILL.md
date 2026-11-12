---
name: internet-access-triage
description: Diagnose a specific internet access symptom from bounded local HTTP, DNS, ping, and existing PCAP evidence. Use when a user requests evidence-based triage for one URL or an existing packet capture.
metadata:
  version: 0.1.0
---

# Internet access triage

Collect bounded evidence for the exact target and time window the user named. Run `scripts/diagnose.py --help` for the supported commands.

Use live mode for a URL and symptom. HTTPS is the default. Plain HTTP requires `--allow-http` and is intended for an explicitly approved diagnostic or test target. Pass a configured comparison URL only with `--control-url`; the skill has no built-in public or control target.

Use offline mode when the user supplies an existing PCAP or PCAPNG. It runs separately from live checks and does not start capture, install tools, change network settings, upload evidence, or collect TLS secrets.

The command creates a new output directory containing `evidence.jsonl`, `diagnosis.json`, `report.md`, and `manifest.json`. Treat `raw/` as local sensitive evidence. Review it before sharing. URLs in reports omit query strings and fragments; proxy credentials and raw tool errors are not included in Agent-visible summaries.

Interpret only observed facts. The four diagnosis states are `fault_observed`, `healthy_within_scope`, `not_reproduced`, and `insufficient_evidence`. Name at most two candidate domains, cite evidence IDs, include counterevidence and limits, and keep target, protocol, address family, and time scope explicit. A user-supplied cause is context, not proof. Three samples support a median and range; a latency fault requires a configured baseline or a valid same-IP comparison. Extraction success, a quiet PCAP, or ping alone cannot establish business health.

The runtime uses Python's standard library and optional external `curl`, `dnslookup`, `ping`, and `tshark` commands. Missing tools reduce coverage. The implementation is defensive across platforms, but the v0.1 project validation scope is Linux/WSL; native Windows behavior has not been validated.

See [the evidence contract](references/evidence-contract.md) and [collection limits](references/collection-limits.md) for output and interpretation details.
