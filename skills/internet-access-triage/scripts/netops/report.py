"""English, evidence-referenced report rendering."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _display(value: Any) -> str:
    if value is None:
        return "unknown"
    return str(value).replace("\n", " ")


def render_report(diagnosis: dict[str, Any], evidence: list[dict[str, Any]],
                  manifest: dict[str, Any]) -> str:
    by_id = {item["id"]: item for item in evidence}
    scope = diagnosis.get("scope", {})
    lines = [
        "# Internet access triage report",
        "",
        f"**Status:** `{_display(diagnosis.get('status'))}`",
        "",
        "## Scope",
        "",
        f"- Mode: `{_display(scope.get('mode'))}`",
        f"- Target: `{_display(scope.get('target'))}`",
        f"- Protocol: `{_display(scope.get('protocol'))}`",
        f"- Address family: `{_display(scope.get('address_family'))}`",
        f"- Collection window start: `{_display(scope.get('time_window'))}`",
        f"- Control URL configured: `{bool(scope.get('control_target_configured'))}`",
        "",
        "The user-provided symptom was treated as context. It did not select a cause.",
        "",
        "## Evidence",
        "",
    ]
    if not evidence:
        lines.append("No evidence records were produced.")
    for record in evidence:
        lines.append(f"### `{record['id']}` — {_display(record.get('kind'))}")
        lines.append("")
        lines.append(f"- Collection status: `{_display(record.get('status'))}`")
        lines.append(f"- Tool: `{_display(record.get('tool', {}).get('name'))}` ({_display(record.get('tool', {}).get('version'))})")
        target = record.get("scope", {}).get("target")
        if target:
            lines.append(f"- Target: `{_display(target)}`")
        observation = record.get("observation", {})
        if record.get("kind") == "http_probe":
            lines.append(f"- Outcome: `{_display(observation.get('outcome'))}`; HTTP status: `{_display(observation.get('http_status'))}`")
            if observation.get("address_family"):
                lines.append(f"- Connected address family: `{_display(observation.get('address_family'))}`")
            if observation.get("proxy_configured"):
                lines.append("- A proxy is configured; direct target-path attribution is unavailable.")
        elif record.get("kind") == "dns_query":
            lines.append(f"- Query type: `{_display(observation.get('rrtype'))}`; resolver: `{_display(observation.get('resolver'))}`; transport: `{_display(observation.get('transport'))}`")
            lines.append(f"- RCODE: `{_display(observation.get('rcode'))}`; answer count: `{len(observation.get('answers', []))}`")
        elif record.get("kind") == "ping":
            lines.append(f"- Target address: `{_display(record.get('scope', {}).get('target'))}`; requested samples: `{_display(observation.get('requested_samples'))}`; sent: `{_display(observation.get('sent'))}`; received: `{_display(observation.get('received'))}`")
        elif record.get("kind") == "pcap_analysis":
            summary = observation.get("summary", {})
            lines.append(f"- Capture SHA-256: `{_display(observation.get('capture_sha256'))}`")
            lines.append(f"- Parsed frames: `{_display(summary.get('frames'))}`; TCP retransmission indicator frames: `{_display(summary.get('tcp_retransmission_frames'))}`")
            lines.append(f"- HTTP paired final responses: `{_display(summary.get('http_paired_final_responses'))}`")
        for item in record.get("measurements", []):
            value = item.get("value")
            rendered = _display(value) if value is not None else f"missing ({_display(item.get('missing_reason'))})"
            lines.append(f"- `{item.get('name')}`: {rendered} {_display(item.get('unit'))}; samples: `{_display(item.get('sample_count'))}`")
        for source in record.get("sources", []):
            if source.get("kind") == "run_artifact":
                lines.append(f"- Local source: `{source.get('path')}` (SHA-256 `{source.get('sha256')}`)")
            elif source.get("kind") == "external_input":
                lines.append(f"- Local input: `{source.get('name')}` (SHA-256 `{source.get('sha256')}`)")
        if record.get("failure"):
            lines.append(f"- Collection failure: `{_display(record['failure'].get('kind'))}` — {_display(record['failure'].get('reason'))}")
        lines.append("")

    lines.extend(["## Candidate domains", ""])
    if not diagnosis.get("candidates"):
        lines.append("No evidence-supported candidate domain was selected.")
    for candidate in diagnosis.get("candidates", []):
        lines.extend([
            f"### {_display(candidate.get('domain'))}",
            "",
            _display(candidate.get("basis")),
            "",
            "Supporting evidence: " + (", ".join(f"`{item}`" for item in candidate.get("evidence_ids", [])) or "none"),
            "",
            "Counterevidence: " + (", ".join(f"`{item}`" for item in candidate.get("counterevidence_ids", [])) or "none recorded"),
            "",
            "Falsifying next step: " + _display(candidate.get("next_step")),
            "",
        ])

    lines.extend(["## Counterevidence", ""])
    if not diagnosis.get("counterevidence"):
        lines.append("No counterevidence was available in the collected scope.")
    for item in diagnosis.get("counterevidence", []):
        lines.append(f"- `{item['evidence_id']}`: {item['meaning']}")
    lines.extend(["", "## Limitations", ""])
    for item in diagnosis.get("limitations", []):
        lines.append(f"- {item}")
    if not diagnosis.get("limitations"):
        lines.append("- No additional limitation was recorded.")
    lines.extend(["", "## Next steps", ""])
    for item in diagnosis.get("next_steps", []):
        lines.append(f"- {item}")
    if not diagnosis.get("next_steps"):
        lines.append("- No additional step was identified from the collected evidence.")
    lines.extend([
        "",
        "## Collection summary",
        "",
        f"- Run ID: `{_display(manifest.get('run_id'))}`",
        f"- Skill version: `{_display(manifest.get('skill_version'))}`",
        f"- Subprocess calls: `{_display(manifest.get('call_counts', {}).get('subprocesses'))}`",
        f"- Raw evidence remains under: `{Path('raw').as_posix()}`",
        "",
    ])
    return "\n".join(lines)


def write_report(path: Path, diagnosis: dict[str, Any], evidence: list[dict[str, Any]],
                 manifest: dict[str, Any]) -> None:
    path.write_text(render_report(diagnosis, evidence, manifest), encoding="utf-8")
