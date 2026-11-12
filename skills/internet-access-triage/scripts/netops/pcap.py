"""Bounded, offline-only TShark extraction for existing PCAP or PCAPNG files."""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from .contract import make_evidence, measurement, relative_artifact, sha256_file, utc_now
from .live import ToolBox
from .runner import Deadline


INPUT_LIMIT = 64 * 1024 * 1024
FRAME_LIMIT = 100000
EVENT_LIMIT = 8 * 1024 * 1024
STDERR_LIMIT = 64 * 1024
FIELD_PROBE_LIMIT = 64 * 1024 * 1024
FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "frame.protocols",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.stream", "tcp.srcport", "tcp.dstport",
    "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.reset", "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission", "tcp.analysis.spurious_retransmission",
    "tcp.analysis.lost_segment", "tcp.analysis.out_of_order", "tcp.analysis.zero_window",
    "udp.stream", "udp.srcport", "udp.dstport", "dns.id", "dns.flags.response", "dns.flags.rcode",
    "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa", "dns.cname", "dns.resp.ttl", "dns.time",
    "tls.record.content_type", "tls.handshake.type", "tls.handshake.extensions_server_name",
    "tls.alert_message.desc", "http.request.method", "http.request.full_uri", "http.response.code",
    "http.location", "http.request_in", "http.response_in", "http.time",
)
REQUIRED_FIELDS = {"frame.number", "frame.time_epoch"}


def _field_key(field: str) -> str:
    return field.replace(".", "_")


def _values(layers: dict[str, Any], field: str) -> list[Any]:
    value = layers.get(_field_key(field), [])
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _first(layers: dict[str, Any], field: str) -> Any:
    values = _values(layers, field)
    return values[0] if values else None


def _int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _flag(layers: dict[str, Any], field: str) -> bool:
    return any(str(value).lower() in ("1", "true") for value in _values(layers, field))


def _field_set(stdout: bytes) -> set[str]:
    found: set[str] = set()
    for raw_line in stdout.decode("utf-8", "replace").splitlines():
        fields = raw_line.split("\t")
        for field in FIELDS:
            if field in fields:
                found.add(field)
    return found


def _capture_scope(path: Path, file_hash: str, stat_before: os.stat_result) -> dict[str, Any]:
    return {
        "target": None,
        "hostname": None,
        "address_family": None,
        "protocol": "PCAP/PCAPNG selected packet metadata",
        "window": None,
        "capture_name": path.name[:160],
        "capture_bytes": stat_before.st_size,
        "capture_sha256": file_hash,
    }


def _summarize_events(raw: bytes, valid_fields: set[str]) -> tuple[dict[str, Any], str | None, int]:
    counts: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    tcp_streams: set[int] = set()
    udp_streams: set[int] = set()
    requests: dict[int, int | None] = {}
    responses: list[tuple[int, int | None, int | None, int]] = []
    ambiguous_frames: list[int] = []
    first_epoch: Decimal | None = None
    last_epoch: Decimal | None = None
    complete_lines = 0
    parse_error: str | None = None
    for line_number, raw_line in enumerate(raw.splitlines(keepends=True), 1):
        if not raw_line.strip():
            continue
        try:
            document = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            if line_number == len(raw.splitlines()):
                parse_error = "The final retained TShark record is incomplete."
                break
            parse_error = f"TShark output record {line_number} is invalid JSON."
            break
        layers = document.get("layers") if isinstance(document, dict) else None
        if not isinstance(layers, dict):
            continue  # TShark EK index record.
        complete_lines += 1
        frame = _int(_first(layers, "frame.number"))
        if frame is None:
            parse_error = f"TShark packet record {line_number} has no frame number."
            break
        counts["frames"] += 1
        wire = _int(_first(layers, "frame.len"))
        captured = _int(_first(layers, "frame.cap_len"))
        if wire is not None:
            counts["wire_bytes"] += wire
        if wire is not None and captured is not None and captured < wire:
            counts["truncated_frames"] += 1
        epoch_raw = _first(layers, "frame.time_epoch")
        if epoch_raw is not None:
            try:
                epoch = Decimal(str(epoch_raw))
                if not epoch.is_finite():
                    raise InvalidOperation
                first_epoch = epoch if first_epoch is None else min(first_epoch, epoch)
                last_epoch = epoch if last_epoch is None else max(last_epoch, epoch)
            except InvalidOperation:
                pass
        protocols_in_frame = str(_first(layers, "frame.protocols") or "").split(":")
        for protocol in set(protocols_in_frame) - {""}:
            protocols[protocol] += 1
        for field, label in (("tcp.flags.syn", "tcp_syn_frames"),
                             ("tcp.flags.fin", "tcp_fin_frames"),
                             ("tcp.flags.reset", "tcp_reset_frames"),
                             ("tcp.analysis.retransmission", "tcp_retransmission_frames"),
                             ("tcp.analysis.fast_retransmission", "tcp_fast_retransmission_frames"),
                             ("tcp.analysis.spurious_retransmission", "tcp_spurious_retransmission_frames"),
                             ("tcp.analysis.lost_segment", "tcp_lost_segment_indicators"),
                             ("tcp.analysis.out_of_order", "tcp_out_of_order_frames"),
                             ("tcp.analysis.zero_window", "tcp_zero_window_frames")):
            if field in valid_fields and _flag(layers, field):
                counts[label] += 1
        tcp_stream = _int(_first(layers, "tcp.stream")) if "tcp.stream" in valid_fields else None
        udp_stream = _int(_first(layers, "udp.stream")) if "udp.stream" in valid_fields else None
        if tcp_stream is not None:
            tcp_streams.add(tcp_stream)
        if udp_stream is not None:
            udp_streams.add(udp_stream)
        if "dns.id" in valid_fields and _values(layers, "dns.id"):
            counts["dns_frames"] += 1
            if _first(layers, "dns.flags.response") in ("1", 1, True):
                counts["dns_responses"] += 1
            else:
                counts["dns_queries"] += 1
            for code in _values(layers, "dns.flags.rcode"):
                counts[f"dns_rcode_{code}"] += 1
        if ("tls.record.content_type" in valid_fields and _values(layers, "tls.record.content_type")) or (
                "tls.handshake.type" in valid_fields and _values(layers, "tls.handshake.type")):
            counts["tls_frames"] += 1
        methods = _values(layers, "http.request.method") if "http.request.method" in valid_fields else []
        statuses = _values(layers, "http.response.code") if "http.response.code" in valid_fields else []
        counts["http_request_messages"] += len(methods)
        counts["http_response_messages"] += len(statuses)
        ambiguous = len(methods) > 1 or len(statuses) > 1 or bool(methods and statuses)
        if ambiguous:
            ambiguous_frames.append(frame)
            continue
        if methods:
            requests[frame] = tcp_stream
        if statuses:
            for status in statuses:
                responses.append((frame, tcp_stream,
                                  _int(_first(layers, "http.request_in")), _int(status) or 0))
    for _, stream, request_frame, code in responses:
        if request_frame in requests and requests[request_frame] == stream and code >= 200:
            counts["http_paired_final_responses"] += 1
        else:
            counts["http_unpaired_responses"] += 1
    if counts["http_request_messages"]:
        counts["http_unpaired_requests"] = max(0, counts["http_request_messages"] - counts["http_paired_final_responses"])
    field_requirements = {
        "wire_bytes": {"frame.len"},
        "truncated_frames": {"frame.len", "frame.cap_len"},
        "tcp_streams": {"tcp.stream"},
        "udp_streams": {"udp.stream"},
        "protocol_frame_counts": {"frame.protocols"},
        "tcp_syn_frames": {"tcp.flags.syn"},
        "tcp_fin_frames": {"tcp.flags.fin"},
        "tcp_reset_frames": {"tcp.flags.reset"},
        "tcp_retransmission_frames": {"tcp.analysis.retransmission"},
        "tcp_fast_retransmission_frames": {"tcp.analysis.fast_retransmission"},
        "tcp_spurious_retransmission_frames": {"tcp.analysis.spurious_retransmission"},
        "tcp_lost_segment_indicators": {"tcp.analysis.lost_segment"},
        "tcp_out_of_order_frames": {"tcp.analysis.out_of_order"},
        "tcp_zero_window_frames": {"tcp.analysis.zero_window"},
        "dns_frames": {"dns.id"},
        "dns_queries": {"dns.id", "dns.flags.response"},
        "dns_responses": {"dns.id", "dns.flags.response"},
        "dns_response_code_frame_counts": {"dns.id", "dns.flags.rcode"},
        "tls_frames": {"tls.record.content_type", "tls.handshake.type"},
        "http_request_messages": {"http.request.method"},
        "http_response_messages": {"http.response.code"},
        "http_paired_final_responses": {"http.request.method", "http.response.code", "http.request_in", "tcp.stream"},
        "http_unpaired_responses": {"http.request.method", "http.response.code", "http.request_in", "tcp.stream"},
        "http_unpaired_requests": {"http.request.method", "http.response.code", "http.request_in", "tcp.stream"},
    }

    def available(name: str) -> bool:
        required = field_requirements.get(name, set())
        if name == "tls_frames":
            return bool(required & valid_fields)
        return required <= valid_fields

    def observed_count(name: str) -> int | None:
        return counts[name] if available(name) else None

    summary = {
        "frames": counts["frames"],
        "wire_bytes": counts["wire_bytes"] if available("wire_bytes") else None,
        "truncated_frames": counts["truncated_frames"] if available("truncated_frames") else None,
        "tcp_streams": len(tcp_streams) if available("tcp_streams") else None,
        "udp_streams": len(udp_streams) if available("udp_streams") else None,
        "protocol_frame_counts": dict(protocols.most_common()) if available("protocol_frame_counts") else None,
        "tcp_syn_frames": observed_count("tcp_syn_frames"),
        "tcp_fin_frames": observed_count("tcp_fin_frames"),
        "tcp_reset_frames": observed_count("tcp_reset_frames"),
        "tcp_retransmission_frames": observed_count("tcp_retransmission_frames"),
        "tcp_fast_retransmission_frames": observed_count("tcp_fast_retransmission_frames"),
        "tcp_spurious_retransmission_frames": observed_count("tcp_spurious_retransmission_frames"),
        "tcp_lost_segment_indicators": observed_count("tcp_lost_segment_indicators"),
        "tcp_out_of_order_frames": observed_count("tcp_out_of_order_frames"),
        "tcp_zero_window_frames": observed_count("tcp_zero_window_frames"),
        "dns_frames": observed_count("dns_frames"),
        "dns_queries": observed_count("dns_queries"),
        "dns_responses": observed_count("dns_responses"),
        "dns_response_code_frame_counts": ({key.removeprefix("dns_rcode_"): value
                                             for key, value in counts.items() if key.startswith("dns_rcode_")}
                                            if available("dns_response_code_frame_counts") else None),
        "tls_frames": observed_count("tls_frames"),
        "http_request_messages": observed_count("http_request_messages"),
        "http_response_messages": observed_count("http_response_messages"),
        "http_paired_final_responses": observed_count("http_paired_final_responses"),
        "http_unpaired_responses": observed_count("http_unpaired_responses"),
        "http_unpaired_requests": observed_count("http_unpaired_requests"),
        "http_ambiguous_frames": (ambiguous_frames if available("http_paired_final_responses") else None),
        "capture_first_epoch": str(first_epoch) if first_epoch is not None else None,
        "capture_last_epoch": str(last_epoch) if last_epoch is not None else None,
        "events_parsed": complete_lines,
    }
    return summary, parse_error, complete_lines


def _event_time(epoch: str | None) -> str | None:
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return None


def collect_offline(capture: Path, output: Path, deadline: Deadline,
                    tshark_name: str = "tshark", display_filter: str | None = None) -> dict[str, Any]:
    """Parse an existing local file only. No command in this module starts capture."""
    evidence: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    box = ToolBox(deadline)
    box.executables["tshark"] = shutil.which(tshark_name)
    box.discovery["tshark"] = {"available": box.executables["tshark"] is not None, "version_status": "not_queried"}
    box.discover_versions(live=False)
    started, mono = utc_now(), time.monotonic()
    capture = capture.resolve(strict=True)
    if not capture.is_file():
        raise ValueError("PCAP input must be a regular file")
    stat_before = capture.stat()
    if stat_before.st_size > INPUT_LIMIT:
        scope = {"target": None, "hostname": None, "address_family": None,
                 "protocol": "PCAP/PCAPNG", "window": None, "capture_name": capture.name[:160],
                 "capture_bytes": stat_before.st_size}
        reason = "PCAP input exceeds the 64 MiB limit; no input bytes were parsed or hashed."
        evidence.append(make_evidence(
            "pcap_analysis", "tshark", None, "partial", scope,
            {"parsed": False, "capture_name": capture.name[:160], "capture_bytes": stat_before.st_size,
             "capture_sha256": None, "analysis_started_at_utc": started,
             "input_status": "input_limit", "parse_error": reason},
            started, int((time.monotonic() - mono) * 1e9),
            [measurement("frame_count", None, "frames", 0, missing_reason=reason)],
            [{"kind": "inline"}], {"kind": "input_limit", "reason": reason}))
        failures.append({"kind": "input_limit", "target": capture.name[:160], "status": "partial", "reason": reason})
        return {"evidence": evidence, "failures": failures, "capabilities": box.discovery,
                "tool_versions": box.versions, "calls": box.calls,
                "call_counts": {"subprocesses": len(box.calls), "pcap_parsers": 0},
                "scope": {"mode": "offline_pcap", "target": None, "protocol": "PCAP/PCAPNG",
                          "address_family": None, "time_window": None}}
    file_hash = sha256_file(capture)
    scope = _capture_scope(capture, file_hash, stat_before)
    executable = box.executables["tshark"]
    if executable is None:
        _record = make_evidence("pcap_analysis", "tshark", None, "unsupported", scope,
                                {"parsed": False, "capture_sha256": file_hash, "reason": "TShark is unavailable"},
                                started, int((time.monotonic() - mono) * 1e9),
                                [measurement("frame_count", None, "frames", 0, missing_reason="TShark executable is unavailable")],
                                [{"kind": "external_input", "name": capture.name, "sha256": file_hash}],
                                {"kind": "tool_missing", "reason": "TShark executable is unavailable"})
        evidence.append(_record)
        failures.append({"kind": "tool_missing", "target": None, "status": "unsupported", "reason": "TShark executable is unavailable"})
        return {"evidence": evidence, "failures": failures, "capabilities": box.discovery,
                "tool_versions": box.versions, "calls": box.calls,
                "call_counts": {"subprocesses": len(box.calls), "pcap_parsers": 0},
                "scope": {"mode": "offline_pcap", "target": None, "protocol": "PCAP/PCAPNG", "address_family": None,
                          "time_window": None, "capture_sha256": file_hash}}
    field_probe = box.run("tshark", [executable, "-G", "fields"], "TShark field registration",
                          FIELD_PROBE_LIMIT, STDERR_LIMIT, timeout_seconds=deadline.remaining(),
                          safe_command=[Path(executable).name, "-G", "fields"])
    field_stderr = output / "raw" / "tshark-fields.stderr.txt"
    field_stderr.write_bytes(field_probe.stderr)
    fields = _field_set(field_probe.stdout)
    missing_required = sorted(REQUIRED_FIELDS - fields)
    if field_probe.status not in ("complete",) or field_probe.returncode != 0 or missing_required:
        status = field_probe.status if field_probe.status != "complete" else "unsupported"
        reason = ("field registration probe did not complete" if status != "unsupported"
                  else "required frame fields are unavailable: " + ", ".join(missing_required))
        evidence.append(make_evidence("pcap_analysis", "tshark", box.versions.get("tshark"), status, scope,
                                      {"parsed": False, "capture_sha256": file_hash,
                                       "field_probe_status": field_probe.status,
                                       "supported_fields": sorted(fields), "missing_required_fields": missing_required},
                                      started, int((time.monotonic() - mono) * 1e9),
                                      [measurement("frame_count", None, "frames", 0, missing_reason=reason)],
                                      [{"kind": "external_input", "name": capture.name, "sha256": file_hash},
                                       relative_artifact(output, field_stderr)],
                                      {"kind": status, "reason": reason}))
        failures.append({"kind": "field_probe", "target": capture.name, "status": status, "reason": reason})
        return {"evidence": evidence, "failures": failures, "capabilities": box.discovery,
                "tool_versions": box.versions, "calls": box.calls,
                "call_counts": {"subprocesses": len(box.calls), "pcap_parsers": 0},
                "scope": {"mode": "offline_pcap", "target": None, "protocol": "PCAP/PCAPNG", "address_family": None,
                          "time_window": None, "capture_sha256": file_hash}}
    selected_fields = [field for field in FIELDS if field in fields]
    command = [executable, "-2", "-n", "-o", "http.desegment_body:FALSE", "-r", str(capture),
               "-c", str(FRAME_LIMIT)]
    if display_filter:
        command.extend(["-Y", display_filter])
    command.append("-T")
    command.append("ek")
    for field in selected_fields:
        command.extend(["-e", field])
    safe_command = [Path(executable).name, "-2", "-n", "-o", "http.desegment_body:FALSE",
                    "-r", "<pcap-input>", "-c", str(FRAME_LIMIT)]
    if display_filter:
        safe_command.extend(["-Y", display_filter])
    safe_command.extend(["-T", "ek", "-e", "<registered-field-list>"])
    result = box.run("tshark", command, "offline PCAP parse", EVENT_LIMIT, STDERR_LIMIT,
                     timeout_seconds=deadline.remaining(), safe_command=safe_command)
    events_path = output / "raw" / "tshark-events.ndjson"
    events_path.write_bytes(result.stdout)
    stderr_path = output / "raw" / "tshark-parse.stderr.txt"
    stderr_path.write_bytes(result.stderr)
    summary, parse_error, parsed = _summarize_events(result.stdout, set(selected_fields))
    try:
        after = capture.stat()
        changed = any(getattr(after, name) != getattr(stat_before, name)
                      for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns"))
    except OSError:
        changed = True
    if changed:
        result.status = "parse_error"
        parse_error = "The capture changed while it was being analyzed."
    status = result.status
    if status == "complete" and result.returncode != 0:
        status = "tool_error"
    if status == "complete" and parse_error:
        status = "parse_error"
    if status == "complete" and summary["frames"] == FRAME_LIMIT:
        status = "partial"
    if status == "complete" and display_filter:
        status = "partial"
        parse_error = parse_error or "Filtered analysis is scoped to the first at most 100000 input frames."
    if status == "complete" and summary["frames"] == 0:
        # Empty or filtered input is valid extraction, but it does not establish health.
        status = "complete"
    if status not in ("complete", "partial") and parse_error is None:
        parse_error = result.error_kind or status
    observations = {
        "parsed": status in ("complete", "partial"),
        "capture_sha256": file_hash,
        "capture_name": capture.name[:160],
        "capture_bytes": stat_before.st_size,
        "capture_first_utc": _event_time(summary.get("capture_first_epoch")),
        "capture_last_utc": _event_time(summary.get("capture_last_epoch")),
        "analysis_started_at_utc": started,
        "display_filter": display_filter,
        "filter_scope": ("display-filter selected packets from the first at most 100000 input frames"
                         if display_filter else "all packets from the first at most 100000 input frames"),
        "input_scan_may_be_partial": bool(display_filter) or summary["frames"] == FRAME_LIMIT,
        "input_scan_limit_note": ("The display filter is evaluated while scanning at most the first 100000 input frames; later capture frames may not have been examined."
                                  if display_filter else "Parsing stops after the first 100000 input frames."),
        "parser_frame_limit": FRAME_LIMIT,
        "event_limit_bytes": EVENT_LIMIT,
        "output_truncated": result.stdout_truncated,
        "stderr_truncated": result.stderr_truncated,
        "supported_fields": selected_fields,
        "unsupported_optional_fields": sorted(set(FIELDS) - fields),
        "summary": summary,
        "parse_error": parse_error,
        "limitations": [
            "Counts describe selected captured packets, not every action on the network.",
            "TShark TCP flags are dissector indications and do not prove end-to-end loss.",
            "HTTP pairing is limited to decoded HTTP/1.x headers and may be incomplete.",
            "Capture timestamps and analysis timestamps are separate scopes.",
            "No live capture, TLS key collection, or network request was started by offline mode.",
        ],
    }
    sources = [
        {"kind": "external_input", "name": capture.name[:160], "sha256": file_hash},
        relative_artifact(output, events_path),
        relative_artifact(output, stderr_path),
        relative_artifact(output, field_stderr),
    ]
    failures_for_evidence = None
    if status not in ("complete", "partial"):
        failures_for_evidence = {"kind": status, "reason": parse_error or status}
        failures.append({"kind": "pcap_parse", "target": capture.name[:160], "status": status,
                         "reason": parse_error or status})
    if status == "partial":
        failures.append({"kind": "pcap_limit", "target": capture.name[:160], "status": "partial",
                         "reason": parse_error or "A parser output, frame, or time bound was reached."})
    measurements = [measurement("selected_frame_count", summary["frames"], "frames", summary["frames"])]
    for name, field, source_fields, unit, sample_count in (
        ("tcp_retransmission_indicator_frames", "tcp_retransmission_frames", {"tcp.analysis.retransmission"}, "frames", summary["frames"]),
        ("tcp_lost_segment_indicator_frames", "tcp_lost_segment_indicators", {"tcp.analysis.lost_segment"}, "frames", summary["frames"]),
        ("http_paired_final_responses", "http_paired_final_responses",
         {"http.request.method", "http.response.code", "http.request_in", "tcp.stream"},
         "transactions", summary["http_response_messages"] or 0),
    ):
        value = summary.get(field)
        fields_available = source_fields <= set(selected_fields)
        reason = None if fields_available and value is not None else "required TShark fields were unavailable"
        measurements.append(measurement(name, value if fields_available else None, unit,
                                        sample_count if fields_available else 0, missing_reason=reason))
    evidence.append(make_evidence("pcap_analysis", "tshark", box.versions.get("tshark"), status, scope,
                                  observations, started, int((time.monotonic() - mono) * 1e9),
                                  measurements, sources, failures_for_evidence))
    scope["window"] = (f"capture:{observations['capture_first_utc']}..{observations['capture_last_utc']}"
                       if observations["capture_first_utc"] and observations["capture_last_utc"] else
                       "capture window unavailable")
    evidence[-1]["scope"]["window"] = scope["window"]
    return {
        "evidence": evidence,
        "failures": failures,
        "capabilities": box.discovery,
        "tool_versions": box.versions,
        "calls": box.calls,
        "call_counts": {"subprocesses": len(box.calls), "pcap_parsers": 1,
                        "selected_frames": summary["frames"], "event_bytes_retained": len(result.stdout)},
        "scope": {"mode": "offline_pcap", "target": None, "protocol": "PCAP/PCAPNG",
                  "address_family": None, "time_window": summary.get("capture_first_epoch") + ".." + summary.get("capture_last_epoch")
                  if summary.get("capture_first_epoch") and summary.get("capture_last_epoch") else None,
                  "capture_sha256": file_hash, "filter_scope": observations["filter_scope"]},
    }
