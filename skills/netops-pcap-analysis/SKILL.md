---
name: netops-pcap-analysis
description: Interpret an existing PCAP or PCAPNG for a scoped question about recorded traffic. Use for offline capture analysis; do not initiate capture or live probes.
metadata:
  version: 0.1.0
---

# Offline packet capture analysis

Identify the capture, the user's question, known capture point and time window, and what visibility is missing. Analyze only supplied files. Keep capture timestamps separate from analysis time; a recorded packet does not establish current service health or responsibility. Cite concrete evidence such as frame numbers, timestamps, run-qualified evidence IDs, and file hashes where available, along with relevant capture and encryption limits.

If the host can discover a compatible installed `internet-access-triage` provider, use its documented offline CLI; otherwise use an actually available, permitted offline parser. If neither is available, state the missing capability and what remains unknown. Do not install tools, contact a target, or start a live capture. Ask only for missing information needed to answer the scoped question.

Read [offline analysis](references/offline-analysis.md) for provider invocation, parser checks, and interpretation limits.
