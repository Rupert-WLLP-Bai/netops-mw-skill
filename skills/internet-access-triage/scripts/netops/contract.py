"""Evidence contracts, hashing, safe paths, and structural validation."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATUSES = {
    "complete", "partial", "timeout", "permission_denied", "unsupported",
    "not_executed", "budget_exhausted", "parse_error", "tool_error",
}
DIAGNOSIS_STATUSES = {
    "fault_observed", "healthy_within_scope", "not_reproduced", "insufficient_evidence",
}
EVIDENCE_ID = re.compile(r"^ev-[0-9a-f]{12}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MEASUREMENT_UNITS = {"ms", "s", "ns", "bytes", "bytes/s", "frames", "packets", "probes", "transactions", "count"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256_file(path: Path, block_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            block = source.read(block_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def relative_artifact(run_root: Path, path: Path) -> dict[str, str]:
    root = run_root.resolve(strict=True)
    artifact = path.resolve(strict=True)
    if not artifact.is_file() or not artifact.is_relative_to(root):
        raise ValueError("Artifact paths must resolve to regular files inside this run directory")
    relative = artifact.relative_to(root).as_posix()
    return {"kind": "run_artifact", "path": relative, "sha256": sha256_file(artifact)}


def measurement(name: str, value: float | int | None, unit: str, sample_count: int,
                raw_values: list[float | int | None] | None = None,
                missing_reason: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": name, "value": value, "unit": unit, "sample_count": sample_count,
        "missing_reason": missing_reason,
    }
    if raw_values is not None:
        result["raw_values"] = raw_values
    return result


def make_evidence(kind: str, tool: str, version: str | None, status: str,
                  scope: dict[str, Any], observation: dict[str, Any],
                  started_at_utc: str, duration_ns: int,
                  measurements: list[dict[str, Any]] | None = None,
                  sources: list[dict[str, Any]] | None = None,
                  failure: dict[str, Any] | None = None) -> dict[str, Any]:
    import uuid

    return {
        "id": "ev-" + uuid.uuid4().hex[:12],
        "kind": kind,
        "tool": {"name": tool, "version": version},
        "status": status,
        "scope": scope,
        "started_at_utc": started_at_utc,
        "duration_ns": max(0, int(duration_ns)),
        "measurements": measurements or [],
        "observation": observation,
        "sources": sources or [],
        "failure": failure,
    }


def validate_evidence(records: list[dict[str, Any]], run_root: Path) -> list[str]:
    errors: list[str] = []
    if not isinstance(records, list):
        return ["evidence stream must be an array"]
    seen: set[str] = set()
    root = run_root.resolve(strict=True)
    for index, record in enumerate(records):
        prefix = f"evidence[{index}]"
        if not isinstance(record, dict):
            errors.append(f"{prefix} must be an object")
            continue
        evidence_id = record.get("id")
        if not isinstance(evidence_id, str) or not EVIDENCE_ID.fullmatch(evidence_id):
            errors.append(f"{prefix}.id has invalid form")
        elif evidence_id in seen:
            errors.append(f"{prefix}.id is duplicated")
        else:
            seen.add(evidence_id)
        if not isinstance(record.get("status"), str) or record.get("status") not in STATUSES:
            errors.append(f"{prefix}.status is unsupported")
        if not isinstance(record.get("kind"), str) or not record.get("kind"):
            errors.append(f"{prefix}.kind is missing")
        tool = record.get("tool")
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool.get("name"):
            errors.append(f"{prefix}.tool is invalid")
        elif "version" not in tool or (tool["version"] is not None and not isinstance(tool["version"], str)):
            errors.append(f"{prefix}.tool.version must be a string or null")
        if not isinstance(record.get("scope"), dict) or not isinstance(record.get("observation"), dict):
            errors.append(f"{prefix} scope or observation is invalid")
        duration = record.get("duration_ns")
        if not isinstance(duration, int) or isinstance(duration, bool) or duration < 0:
            errors.append(f"{prefix}.duration_ns is invalid")
        stamp = record.get("started_at_utc")
        try:
            if not isinstance(stamp, str) or not stamp.endswith("Z"):
                raise ValueError
            datetime.fromisoformat(stamp[:-1] + "+00:00")
        except ValueError:
            errors.append(f"{prefix}.started_at_utc must be a UTC ISO timestamp")
        measurements = record.get("measurements")
        if not isinstance(measurements, list):
            errors.append(f"{prefix}.measurements must be an array")
            measurements = []
        for item_index, item in enumerate(measurements):
            label = f"{prefix}.measurements[{item_index}]"
            if not isinstance(item, dict):
                errors.append(f"{label} is invalid")
                continue
            unit = item.get("unit")
            if not isinstance(item.get("name"), str) or not item.get("name") or not isinstance(unit, str) or unit not in MEASUREMENT_UNITS:
                errors.append(f"{label} name or unit is invalid")
            value = item.get("value")
            if value is not None and not _finite_number(value):
                errors.append(f"{label}.value must be numeric or null")
            if value is None and not (isinstance(item.get("missing_reason"), str) and item["missing_reason"]):
                errors.append(f"{label}.missing_reason is required for missing values")
            sample_count = item.get("sample_count")
            if not isinstance(sample_count, int) or isinstance(sample_count, bool) or sample_count < 0:
                errors.append(f"{label}.sample_count is invalid")
            raw_values = item.get("raw_values", [])
            if not isinstance(raw_values, list) or any(
                    value is not None and not _finite_number(value)
                    for value in raw_values):
                errors.append(f"{label}.raw_values must contain finite numbers or null")
        sources = record.get("sources")
        if not isinstance(sources, list):
            errors.append(f"{prefix}.sources must be an array")
            sources = []
        for source_index, source in enumerate(sources):
            label = f"{prefix}.sources[{source_index}]"
            if not isinstance(source, dict):
                errors.append(f"{label} is invalid")
                continue
            allowed_source_keys = {"kind", "path", "sha256", "pointer", "frame_numbers", "name"}
            if set(source) - allowed_source_keys:
                errors.append(f"{label} contains unsupported fields")
            if "pointer" in source and source["pointer"] is not None and not isinstance(source["pointer"], str):
                errors.append(f"{label}.pointer must be a string or null")
            frame_numbers = source.get("frame_numbers", [])
            if not isinstance(frame_numbers, list) or any(
                    not isinstance(frame, int) or isinstance(frame, bool) or frame < 1
                    for frame in frame_numbers):
                errors.append(f"{label}.frame_numbers must contain positive integers")
            if "name" in source and not isinstance(source["name"], str):
                errors.append(f"{label}.name must be a string")
            if source.get("kind") == "run_artifact":
                artifact_path = source.get("path")
                artifact_hash = source.get("sha256")
                if not isinstance(artifact_path, str) or not isinstance(artifact_hash, str) or not SHA256.fullmatch(artifact_hash):
                    errors.append(f"{label} requires a relative path and SHA-256")
                    continue
                candidate = Path(artifact_path)
                if candidate.is_absolute() or ".." in candidate.parts:
                    errors.append(f"{label}.path escapes the run directory")
                    continue
                resolved = (root / candidate).resolve(strict=False)
                if not resolved.is_relative_to(root) or not resolved.is_file():
                    errors.append(f"{label}.path is outside the run or missing")
                    continue
                if sha256_file(resolved) != artifact_hash:
                    errors.append(f"{label}.sha256 does not match")
            elif source.get("kind") == "external_input":
                if not isinstance(source.get("sha256"), str) or not SHA256.fullmatch(source["sha256"]):
                    errors.append(f"{label}.sha256 is invalid")
                if not isinstance(source.get("name"), str) or not source.get("name"):
                    errors.append(f"{label}.name is required for external input")
            elif source.get("kind") != "inline":
                errors.append(f"{label}.kind is unsupported")
        failure = record.get("failure")
        if failure is not None and not isinstance(failure, dict):
            errors.append(f"{prefix}.failure must be an object or null")
    return errors


def _finite_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        return False


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def write_evidence(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False))
            stream.write("\n")


def read_evidence(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"Evidence line {line_number} is not valid JSON") from error
            if not isinstance(value, dict):
                raise ValueError(f"Evidence line {line_number} must be an object")
            records.append(value)
    return records
