#!/usr/bin/env python3
"""Collect bounded internet-access evidence or analyze an existing packet capture."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from netops import VERSION
from netops.contract import (make_evidence, relative_artifact, sha256_file, utc_now,
                             validate_evidence, write_evidence, write_json)
from netops.diagnosis import diagnose, validate_diagnosis
from netops.live import collect_live
from netops.pcap import collect_offline
from netops.report import write_report
from netops.runner import Deadline
from netops.urls import parse_target, validate_dns_endpoint


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect bounded live evidence for one URL, or analyze one existing local PCAP/PCAPNG file.",
        epilog=(
            "Examples:\n"
            "  python scripts/diagnose.py --url https://service.example/status --symptom 'intermittent timeout' --out runs/run-001\n"
            "  python scripts/diagnose.py --url https://service.example/status --control-url https://control.example/health --symptom 'slow response' --out runs/run-002\n"
            "  python scripts/diagnose.py --url http://127.0.0.1:8080/health --allow-http --symptom 'local test' --out runs/local-test\n"
            "  python scripts/diagnose.py --pcap ./capture.pcapng --out runs/capture-001"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--url", help="HTTPS URL to probe; plain HTTP requires --allow-http")
    mode.add_argument("--pcap", type=Path, help="Existing local PCAP or PCAPNG file for offline analysis")
    parser.add_argument("--symptom", help="Short symptom description for context; it is not copied into output")
    parser.add_argument("--control-url", help="Configured comparison URL; no public target is chosen automatically")
    parser.add_argument("--allow-http", action="store_true",
                        help="Allow an explicitly approved plain HTTP diagnostic or test target")
    parser.add_argument("--out", required=True, type=Path, help="New output directory; existing paths are refused")
    parser.add_argument("--tshark", default="tshark", help="TShark executable name or full path for offline mode")
    parser.add_argument("--display-filter", help="Optional TShark display filter; reported results are filter-scoped")
    parser.add_argument("--dns-server", help="Optional explicit DNS resolver hostname/IP or secure resolver URL")
    parser.add_argument("--dns-transport", choices=("udp", "tcp", "tls", "https", "quic"), default="udp",
                        help="Transport for --dns-server; ignored only for the system-default resolver")
    parser.add_argument("--max-response-wait-ms", type=float,
                        help="Explicit configured response-wait limit; evaluated only with at least three comparable samples")
    parser.add_argument("--max-dns-ms", type=float,
                        help="Explicit configured DNS timing limit; evaluated only with at least three structured samples")
    parser.add_argument("--version", action="version", version=f"internet-access-triage {VERSION}")
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> tuple[str, list[dict[str, Any]], str | None]:
    if args.pcap:
        if args.symptom or args.control_url or args.allow_http or args.dns_server or args.dns_transport != "udp":
            parser.error("Offline PCAP mode does not accept live URL, symptom, HTTP, or DNS resolver options")
        if args.display_filter and any(ord(char) < 32 or ord(char) == 127 for char in args.display_filter):
            parser.error("Display filter cannot contain control characters")
        return "offline_pcap", [], None
    if not args.symptom or not args.symptom.strip():
        parser.error("Live mode requires --symptom")
    if len(args.symptom) > 2000:
        parser.error("Symptom text must be at most 2000 characters")
    if args.display_filter:
        parser.error("--display-filter is available only with --pcap")
    if args.max_response_wait_ms is not None and (not math.isfinite(args.max_response_wait_ms) or args.max_response_wait_ms < 0):
        parser.error("--max-response-wait-ms must be a finite, non-negative number")
    if args.max_dns_ms is not None and (not math.isfinite(args.max_dns_ms) or args.max_dns_ms < 0):
        parser.error("--max-dns-ms must be a finite, non-negative number")
    if args.dns_server:
        try:
            dns_server = validate_dns_endpoint(args.dns_server, args.dns_transport)
        except ValueError as error:
            parser.error(str(error))
    else:
        dns_server = None
        if args.dns_transport != "udp":
            parser.error("--dns-transport requires an explicit --dns-server")
    try:
        targets = [parse_target(args.url, args.allow_http)]
        if args.control_url:
            targets.append(parse_target(args.control_url, args.allow_http))
    except ValueError as error:
        parser.error(str(error))
    if len(targets) > 2:
        parser.error("At most one configured control URL is supported")
    return "live", targets, dns_server


def _create_output(path: Path) -> Path:
    raw = path.expanduser()
    if raw.name in ("", ".", ".."):
        raise ValueError("Output must name a new directory")
    raw.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = raw.parent.resolve(strict=True)
    output = parent / raw.name
    if output.exists() or output.is_symlink():
        raise FileExistsError("Output directory already exists; choose a new path")
    output.mkdir(mode=0o700, exist_ok=False)
    (output / "raw").mkdir(mode=0o700)
    return output


def _runtime_sources() -> dict[str, str]:
    skill_root = Path(__file__).resolve().parents[1]
    candidates = [skill_root / "SKILL.md", skill_root / "LICENSE"]
    for relative in ("config", "schemas", "references", "scripts"):
        directory = skill_root / relative
        if directory.exists():
            candidates.extend(path for path in directory.rglob("*")
                              if path.is_file() and path.suffix in (".json", ".md", ".py"))
    hashes: dict[str, str] = {}
    for path in sorted(set(candidates)):
        if path.is_symlink() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        hashes[path.relative_to(skill_root).as_posix()] = sha256_file(path)
    return hashes


def _evidence_windows(records: list[dict[str, Any]]) -> None:
    for record in records:
        started = record.get("started_at_utc")
        duration_ns = record.get("duration_ns")
        if not isinstance(started, str) or not isinstance(duration_ns, int):
            continue
        try:
            start = datetime.fromisoformat(started.replace("Z", "+00:00"))
            end = start + timedelta(microseconds=duration_ns / 1000)
        except ValueError:
            continue
        record.setdefault("scope", {})["window"] = (
            start.isoformat(timespec="milliseconds").replace("+00:00", "Z") + ".." +
            end.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        )


def _fatal_evidence(mode: str, error: Exception, output: Path) -> dict[str, Any]:
    return make_evidence(
        "run_failure", "python-standard-library", sys.version.split()[0], "tool_error",
        {"target": None, "hostname": None, "address_family": None,
         "protocol": "HTTPS" if mode == "live" else "PCAP/PCAPNG", "window": None},
        {"error_kind": type(error).__name__, "message": "Collection stopped before completion."},
        utc_now(), 0, [], [{"kind": "inline"}],
        {"kind": "run_error", "reason": type(error).__name__},
    )


def _hash_artifacts(output: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "manifest.json" and not path.is_symlink():
            result[path.relative_to(output).as_posix()] = sha256_file(path)
    return result


def _main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    mode, targets, dns_server = _validate_args(parser, args)
    if mode == "offline_pcap" and args.max_response_wait_ms is not None:
        parser.error("--max-response-wait-ms is available only in live mode")
    if mode == "offline_pcap" and args.max_dns_ms is not None:
        parser.error("--max-dns-ms is available only in live mode")
    try:
        output = _create_output(args.out)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    run_id = uuid.uuid4().hex
    started_at_utc = utc_now()
    wall_start = time.monotonic()
    evidence: list[dict[str, Any]] = []
    collection: dict[str, Any] = {}
    execution_error: Exception | None = None
    try:
        if mode == "live":
            deadline = Deadline(23.0)
            collection = collect_live(targets, output, deadline, args.allow_http,
                                      dns_server=dns_server, dns_transport=args.dns_transport)
            run_scope = collection["scope"]
        else:
            deadline = Deadline(25.0)
            collection = collect_offline(args.pcap, output, deadline, args.tshark, args.display_filter)
            run_scope = collection["scope"]
        evidence = collection.get("evidence", [])
    except Exception as error:
        execution_error = error
        evidence = [_fatal_evidence(mode, error, output)]
        collection = {
            "failures": [{"kind": "run_error", "target": None, "status": "tool_error",
                          "reason": type(error).__name__}],
            "capabilities": {}, "tool_versions": {}, "calls": [],
            "call_counts": {"subprocesses": 0},
            "scope": {"mode": mode, "target": None, "protocol": "HTTPS" if mode == "live" else "PCAP/PCAPNG",
                      "address_family": None, "time_window": None, "targets": []},
        }
        run_scope = collection["scope"]

    _evidence_windows(evidence)
    run_ended_at_utc = utc_now()
    run_scope["comparison_window_id"] = run_id
    run_scope["window_started_at_utc"] = started_at_utc
    run_scope["window_ended_at_utc"] = run_ended_at_utc
    run_scope["run_window_started_at_utc"] = started_at_utc
    run_scope["run_window_ended_at_utc"] = run_ended_at_utc
    for record in evidence:
        record.setdefault("scope", {})["comparison_window_id"] = run_id
        record["scope"]["run_window_started_at_utc"] = started_at_utc
        record["scope"]["run_window_ended_at_utc"] = run_ended_at_utc
    run_scope.setdefault("window_started_at_utc", started_at_utc)
    run_scope.setdefault("window_ended_at_utc", run_ended_at_utc)
    validation_errors = validate_evidence(evidence, output)
    diagnosis_input = evidence if not validation_errors else []
    try:
        diagnosis = diagnose(diagnosis_input, run_scope, mode,
                             max_response_wait_ms=args.max_response_wait_ms,
                             max_dns_ms=args.max_dns_ms)
    except Exception as error:
        execution_error = execution_error or error
        diagnosis = {
            "schema_version": "0.1.0", "status": "insufficient_evidence",
            "scope": {"mode": mode, "target": None, "protocol": "unknown", "address_family": None, "time_window": None},
            "evidence_ids": [], "candidates": [], "counterevidence": [],
            "limitations": ["Diagnosis could not consume the collected evidence safely."],
            "next_steps": ["Inspect the recorded validation and collection failures."],
            "origin": mode,
        }
    diagnosis_errors = validate_diagnosis(diagnosis, evidence)
    if validation_errors:
        diagnosis["status"] = "insufficient_evidence"
        diagnosis["limitations"].append("Evidence validation failed; no diagnosis was derived from invalid records.")
    if diagnosis_errors:
        diagnosis["status"] = "insufficient_evidence"
        diagnosis["candidates"] = []
        diagnosis["evidence_ids"] = []
        diagnosis["limitations"].append("Diagnosis reference validation failed; candidate attribution was removed.")
    write_evidence(output / "evidence.jsonl", evidence)
    write_json(output / "diagnosis.json", diagnosis)

    failures = list(collection.get("failures", []))
    for record in evidence:
        if record.get("status") not in ("complete", "partial"):
            failures.append({"kind": record.get("kind"), "evidence_id": record.get("id"),
                             "status": record.get("status"), "reason": (record.get("failure") or {}).get("reason")})
    if validation_errors:
        failures.append({"kind": "evidence_validation", "status": "parse_error", "reason": validation_errors})
    if diagnosis_errors:
        failures.append({"kind": "diagnosis_validation", "status": "parse_error", "reason": diagnosis_errors})
    if execution_error:
        failures.append({"kind": "run_error", "status": "tool_error", "reason": type(execution_error).__name__})
    completed_at_utc = utc_now()
    manifest: dict[str, Any] = {
        "schema_version": "0.1.0",
        "run_id": run_id,
        "skill_version": VERSION,
        "mode": mode,
        "started_at_utc": started_at_utc,
        "completed_at_utc": completed_at_utc,
        "comparison_window_id": run_id,
        "run_window": {"started_at_utc": started_at_utc, "ended_at_utc": run_ended_at_utc},
        "duration_ns": int((time.monotonic() - wall_start) * 1_000_000_000),
        "status": diagnosis.get("status"),
        "scope": run_scope,
        "symptom_provided": bool(args.symptom) if mode == "live" else False,
        "configured_thresholds": {"max_response_wait_ms": args.max_response_wait_ms if mode == "live" else None,
                                   "max_dns_ms": args.max_dns_ms if mode == "live" else None},
        "plain_http_allowed": bool(args.allow_http) if mode == "live" else False,
        "capabilities": collection.get("capabilities", {}),
        "tool_versions": collection.get("tool_versions", {}),
        "call_counts": collection.get("call_counts", {}),
        "subprocess_calls": collection.get("calls", []),
        "failures": failures,
        "validation_errors": {"evidence": validation_errors, "diagnosis": diagnosis_errors},
        "source_hashes": _runtime_sources(),
        "external_input_hashes": {source.get("name", "input"): source["sha256"]
                                   for record in evidence for source in record.get("sources", [])
                                   if source.get("kind") == "external_input" and source.get("sha256")},
        "privacy": {"raw_evidence_local": True, "url_queries_and_fragments_redacted": True,
                    "proxy_credentials_recorded": False, "symptom_text_recorded": False},
        "artifact_hashes": {},
    }
    write_report(output / "report.md", diagnosis, evidence, manifest)
    manifest["artifact_hashes"] = _hash_artifacts(output)
    write_json(output / "manifest.json", manifest)
    result = {"run_directory": str(output), "run_id": run_id, "mode": mode,
              "status": diagnosis.get("status"), "evidence_count": len(evidence),
              "candidate_count": len(diagnosis.get("candidates", [])),
              "validation_error_count": len(validation_errors) + len(diagnosis_errors)}
    sys.stdout.write(json.dumps(result, ensure_ascii=True) + "\n")
    return 1 if execution_error else 0


if __name__ == "__main__":
    raise SystemExit(_main())
