"""Bounded materialization for the developer-only M6 carrier corpus.

This module reads only self-authored parent fixtures and their separate
developer oracles. It does not infer expected outcomes from provider output.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


FIXTURE_REL = Path("tests/fixtures/carrier-m6")
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_FILES = 512
MAX_DEPTH = 8
IMPORT_TIMEOUT_SECONDS = 20
SUMMARY_FILES = ("manifest.json", "evidence.jsonl", "diagnosis.json", "report.md")
BUNDLE_FILES = (*SUMMARY_FILES, "carrier-visible.json")
IDENTIFIER_VALUE_METRICS = {
    "device_model", "service_vlan_expected", "service_vlan_actual",
    "route_prefix", "service_prefix", "route_vrf", "service_vrf", "flow_scope",
    "ecmp_path", "next_hop", "traceroute_hop", "lag_member_id", "qos_class",
    "instrument_id", "equivalence_expected_id", "equivalence_actual_id",
    "equivalence_expected_run", "equivalence_actual_run", "change_scope",
    "change_approval_reference", "rollback_owner",
    "actual_circuit", "actual_endpoint", "actual_ip_prefix", "actual_qos",
    "actual_routing", "actual_security", "actual_sla_profile", "actual_vlan", "actual_vrf",
    "expected_circuit", "expected_endpoint", "expected_ip_prefix", "expected_qos",
    "expected_routing", "expected_security", "expected_sla_profile", "expected_vlan", "expected_vrf",
    "current_circuit", "current_endpoint", "current_ip_prefix", "current_qos",
    "current_routing", "current_security", "current_sla_profile", "current_vlan", "current_vrf",
}
SOURCE_ROOTS = {
    "m3": Path("tests/fixtures/carrier-m3"),
    "m4": Path("tests/fixtures/carrier-m4"),
    "m5": Path("tests/fixtures/carrier-m5"),
}
INGEST = Path("skills/netops-incident/scripts/ingest.py")


class CorpusError(ValueError):
    """Raised when a corpus record or source fixture is unsafe or malformed."""


def _confined_regular(path: Path, root: Path) -> Path:
    """Resolve a path only after rejecting symlinks in every component."""
    root = root.resolve(strict=True)
    candidate = root / path if not path.is_absolute() else path
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise CorpusError("fixture path escapes its root") from exc
    current = root
    try:
        for part in relative.parts:
            current = current / part
            mode = current.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise CorpusError("fixture path contains a symlink")
        resolved = current.resolve(strict=True)
        resolved.relative_to(root)
    except OSError as exc:
        raise CorpusError("fixture path is missing") from exc
    return resolved


def _json_regular(path: Path, root: Path, *, limit: int = MAX_FILE_BYTES) -> Any:
    """Read a bounded regular file after proving it stays under root."""
    root = root.resolve(strict=True)
    try:
        resolved = _confined_regular(path, root)
        info = resolved.lstat()
    except (OSError, ValueError) as exc:
        raise CorpusError("fixture path is missing or escapes its root") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise CorpusError("fixture file is not a bounded regular file")
    try:
        return json.loads(resolved.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CorpusError("fixture JSON is malformed") from exc


def _walk_regular(root: Path) -> None:
    """Bound fixture tree traversal and reject symlinks and special files."""
    count = 0
    total = 0
    root = root.resolve(strict=True)
    for directory, names, files in os.walk(root, followlinks=False):
        current = Path(directory)
        if len(current.relative_to(root).parts) > MAX_DEPTH:
            raise CorpusError("fixture tree is too deep")
        for name in names:
            path = current / name
            mode = path.lstat().st_mode
            if not stat.S_ISDIR(mode):
                raise CorpusError("fixture tree contains a non-directory entry")
        for name in files:
            path = current / name
            info = path.lstat()
            count += 1
            total += info.st_size
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                raise CorpusError("fixture tree contains a non-regular or oversized file")
            if count > MAX_FILES or total > MAX_TOTAL_BYTES:
                raise CorpusError("fixture tree exceeds corpus bounds")


def load_catalog(repo_root: str | Path) -> dict[str, Any]:
    """Load and validate the opaque 36-case catalog."""
    repo = Path(repo_root).resolve(strict=True)
    fixture_root = repo / FIXTURE_REL
    _walk_regular(fixture_root)
    catalog = _json_regular(Path("catalog.json"), fixture_root)
    if not isinstance(catalog, dict) or catalog.get("schema_version") != 1:
        raise CorpusError("unsupported catalog schema")
    cases = catalog.get("cases")
    if not isinstance(cases, list) or len(cases) != 36:
        raise CorpusError("catalog must declare 36 cases")
    expected_groups = {
        "true_fault": 6,
        "healthy_misleading": 6,
        "unreliable_ticket": 4,
        "insufficient_evidence": 4,
        "service_acceptance": 8,
        "multi_layer_compound": 8,
    }
    counts = {name: 0 for name in expected_groups}
    seen: set[str] = set()
    for index, case in enumerate(cases, 1):
        if not isinstance(case, dict) or case.get("case_id") != f"case-{index:03d}":
            raise CorpusError("case IDs must be unique and sequential opaque IDs")
        if case["case_id"] in seen:
            raise CorpusError("duplicate case ID")
        seen.add(case["case_id"])
        group = case.get("primary_group")
        if group not in counts:
            raise CorpusError("unknown exclusive primary group")
        counts[group] += 1
        jobs = case.get("jobs")
        if not isinstance(jobs, list) or not jobs:
            raise CorpusError("each case must declare at least one job")
        if group == "multi_layer_compound" and len(jobs) < 2:
            raise CorpusError("compound cases need at least two domain jobs")
        for job_index, job in enumerate(jobs, 1):
            if not isinstance(job, dict) or job.get("job_id") != f"job-{job_index:02d}":
                raise CorpusError("job IDs must be opaque and sequential within a task")
            if job.get("provider") not in {"access", "transport", "service_review"}:
                raise CorpusError("unknown provider kind")
            if job.get("parent") not in SOURCE_ROOTS or not re.fullmatch(r"case-\d{3}", str(job.get("parent_case"))):
                raise CorpusError("invalid parent fixture reference")
            if not isinstance(job.get("ticket"), str) or not job["ticket"].strip():
                raise CorpusError("ticket text must be non-empty")
    if counts != expected_groups:
        raise CorpusError("catalog group counts do not match the M6 contract")
    return catalog


def _safe_copy_file(source: Path, destination: Path, source_root: Path) -> None:
    source_root = source_root.resolve(strict=True)
    try:
        resolved = _confined_regular(source, source_root)
        info = resolved.lstat()
    except (OSError, ValueError) as exc:
        raise CorpusError("source fixture path is missing or escapes its root") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
        raise CorpusError("source fixture is not a bounded regular file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(resolved.read_bytes())


def _remap(value: Any, identifiers: dict[str, str], run_ids: dict[str, str], *, key: str = "",
           opaque_prefix: str = "q00") -> Any:
    """Remap identifier-bearing fields while preserving evidence semantics."""
    if isinstance(value, dict):
        if "metric" in value and "value" in value and value.get("metric") in IDENTIFIER_VALUE_METRICS:
            result = {name: _remap(child, identifiers, run_ids, key=name, opaque_prefix=opaque_prefix)
                      for name, child in value.items() if name != "value"}
            result["value"] = _remap_identifier(value["value"], identifiers, opaque_prefix)
            return result
        if key == "value_allowlists":
            return {metric: [_remap_identifier(item, identifiers, opaque_prefix) for item in values]
                    if metric in IDENTIFIER_VALUE_METRICS else
                    [_remap(child, identifiers, run_ids, key=metric, opaque_prefix=opaque_prefix) for child in values]
                    for metric, values in value.items()}
        if key == "pseudonyms":
            return {identifiers.setdefault(name, f"{opaque_prefix}{len(identifiers) + 1:03d}"):
                    _remap(child, identifiers, run_ids, key="source_native_id", opaque_prefix=opaque_prefix)
                    for name, child in value.items()}
        return {name: _remap(child, identifiers, run_ids, key=name, opaque_prefix=opaque_prefix) for name, child in value.items()}
    if isinstance(value, list):
        return [_remap(child, identifiers, run_ids, key=key, opaque_prefix=opaque_prefix) for child in value]
    if isinstance(value, str):
        if value.startswith("$ID:") or value.startswith("$RUN_ID:") or value.startswith("$row"):
            return value
        if key == "run_id" or key == "topology_run_id" or key.endswith("_run_id"):
            return run_ids.get(value, value)
        if key == "authority":
            return "operator-map"
        if key.endswith("_evidence_id"):
            return value
        identifier_key = (
            key in {"object_id", "service_id", "resource_id", "source_native_id", "profile_id", "device_model",
                    "from_id", "to_id", "service", "source", "circuit", "site", "endpoint", "measurement_point",
                    "alias", "pseudonym", "id"}
            or (key.endswith("_id") and key != "evidence_id" and not key.endswith("_evidence_id") and not key.endswith("_run_id"))
        )
        if identifier_key and value not in {"", "null"}:
            return identifiers.setdefault(value, f"{opaque_prefix}{len(identifiers) + 1:03d}")
        return value
    return value


def _remap_identifier(value: Any, identifiers: dict[str, str], opaque_prefix: str) -> Any:
    if (not isinstance(value, str) or value in {"", "null"} or value.startswith("$")
            or value.startswith("ev-") or re.fullmatch(r"r\d{4}", value)):
        return value
    return identifiers.setdefault(value, f"{opaque_prefix}{len(identifiers) + 1:03d}")


def _resolve_tokens(value: Any, row_ids: dict[str, dict[str, str]], run_ids: dict[str, str]) -> Any:
    if isinstance(value, dict):
        if set(value) == {"$row"}:
            marker = value["$row"]
            if not isinstance(marker, str) or marker.count("/") != 1:
                raise CorpusError("malformed logical row reference")
            run_key, row_key = marker.split("/", 1)
            try:
                return row_ids[run_key][row_key]
            except KeyError as exc:
                raise CorpusError("logical row reference has no emitted evidence record") from exc
        return {key: _resolve_tokens(item, row_ids, run_ids) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_tokens(item, row_ids, run_ids) for item in value]
    if isinstance(value, str):
        if value.startswith("$ID:"):
            marker = value[4:]
            if marker.count("/") != 1:
                raise CorpusError("malformed staged evidence reference")
            run_key, row_key = marker.split("/", 1)
            try:
                return row_ids[run_key][row_key]
            except KeyError as exc:
                raise CorpusError("staged evidence reference has no emitted record") from exc
        if value.startswith("$RUN_ID:"):
            try:
                return run_ids[value[8:]]
            except KeyError as exc:
                raise CorpusError("staged run reference has no emitted run") from exc
    return copy.deepcopy(value)


def _resolve_static_evidence_refs(value: Any, row_ids: dict[str, dict[str, str]],
                                 run_ids: dict[str, str]) -> Any:
    """Translate parent fixture ev-* selectors by observed emitted order."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key == "evidence_id" and isinstance(item, str) and item.startswith("ev-"):
                old_run = value.get("run_id")
                run_key = run_ids.get(old_run)
                if run_key is None:
                    raise CorpusError("evidence reference does not identify a declared source run")
                try:
                    emitted = list(row_ids[run_key].values())
                    ordinal = int(item[-12:], 16) if item.startswith("ev-") else 0
                    result[key] = emitted[ordinal - 1]
                except (KeyError, ValueError, IndexError) as exc:
                    raise CorpusError("evidence reference is outside actual M2 output") from exc
            else:
                result[key] = _resolve_static_evidence_refs(item, row_ids, run_ids)
        return result
    if isinstance(value, list):
        return [_resolve_static_evidence_refs(item, row_ids, run_ids) for item in value]
    return value


def _source_rows(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            item = json.loads(line)
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise CorpusError("M2 emitted malformed evidence JSONL")
            rows.append(item)
    return rows


def _import_source(repo: Path, parent_root: Path, source: dict[str, Any], source_config: dict[str, Any],
                   input_data: Any, attempt: Path, source_index: int) -> tuple[Path, dict[str, str], str]:
    run_key = source["run_key"]
    stem = f"s{source_index:02d}"
    source_dir = attempt / f"{stem}-input"
    source_dir.mkdir(parents=True)
    suffix = Path(source["input_path"]).suffix or ".json"
    input_name = "input" + suffix
    input_path = source_dir / input_name
    input_path.write_text(_serialize_source(input_data), encoding="utf-8")
    config_path = attempt / f"{stem}-config.json"
    config_path.write_text(json.dumps(source_config, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    out_dir = attempt / f"{stem}-bundle"
    private_dir = attempt / f"{stem}-private"
    command = [sys.executable, "-B", str(repo / INGEST), "--source-root", str(source_dir), "--source", input_name,
               "--config", str(config_path), "--out", str(out_dir), "--private-out", str(private_dir)]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=IMPORT_TIMEOUT_SECONDS,
                                   check=False, cwd=repo)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CorpusError("bounded M2 import could not complete") from exc
    if completed.returncode != 0:
        raise CorpusError("M2 import rejected a corpus source")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CorpusError("M2 importer returned malformed status") from exc
    if result.get("parse_status") != "complete":
        raise CorpusError("M2 importer did not produce a complete source bundle")
    evidence = _source_rows(out_dir / "evidence.jsonl")
    row_keys = source.get("row_keys", [])
    if row_keys and len(row_keys) != len(evidence):
        raise CorpusError("logical row keys do not match emitted M2 evidence count")
    keys = row_keys or [f"#{index}" for index in range(1, len(evidence) + 1)]
    ids = {key: row["id"] for key, row in zip(keys, evidence)}
    return out_dir, ids, source_config["run_id"]


def _serialize_source(input_data: Any) -> str:
    """Write each telemetry record on its own line to honor M2's line cap."""
    if isinstance(input_data, dict) and isinstance(input_data.get("records"), list):
        header = {key: value for key, value in input_data.items() if key != "records"}
        encoded_header = json.dumps(header, ensure_ascii=False, separators=(",", ":"))
        if not encoded_header.endswith("}"):
            raise CorpusError("malformed telemetry source header")
        encoded_records = ",\n".join(
            json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            for record in input_data["records"]
        )
        return encoded_header[:-1] + ',"records":[\n' + encoded_records + "\n]}"
    return json.dumps(input_data, ensure_ascii=False, separators=(",", ":"))


def _materialize_job(repo: Path, job: dict[str, Any], task_dir: Path, job_number: int,
                     enrichment: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    parent = job["parent"]
    parent_root = (repo / SOURCE_ROOTS[parent]).resolve(strict=True)
    scenario = _json_regular(Path("cases") / job["parent_case"] / "scenario.json", parent_root)
    sources = scenario.get("sources")
    request = scenario.get("request")
    if not isinstance(sources, list) or not isinstance(request, dict):
        raise CorpusError("parent fixture scenario is malformed")
    if not sources or len(sources) > 64:
        raise CorpusError("parent fixture source count is outside limits")
    for source in sources:
        if not isinstance(source, dict):
            raise CorpusError("parent fixture source entry is malformed")
        for path_key in ("config_path", "input_path"):
            raw_path = source.get(path_key)
            if not isinstance(raw_path, str):
                raise CorpusError("parent fixture source path is malformed")
            relative = Path(raw_path)
            if relative.is_absolute() or ".." in relative.parts or len(relative.parts) > MAX_DEPTH:
                raise CorpusError("parent fixture source path exceeds limits")
        if len(source.get("row_keys", [])) > 4096:
            raise CorpusError("parent fixture logical row count exceeds limits")
    request_run_names = {item["run_id"] for item in request.get("runs", [])}
    needed_sources = [source for source in sources if source.get("run_key") in {name.removeprefix(f"{parent}-") for name in request_run_names}]
    # Fixtures whose source run key differs from the request's run ID (M5) retain declared order.
    if parent == "m5":
        needed_sources = sources
    if not needed_sources:
        needed_sources = sources

    run_ids = {source["run_key"]: f"r{job_number:02d}{index:02d}" for index, source in enumerate(needed_sources, 1)}
    old_to_new = {}
    for source in needed_sources:
        source_config = _json_regular(Path(source["config_path"]), parent_root)
        old_to_new[source_config["run_id"]] = run_ids[source["run_key"]]
    # Staged M5 templates are imported in declared order, resolving IDs only after actual M2 output.
    identifiers: dict[str, str] = {}
    row_ids: dict[str, dict[str, str]] = {}
    imported: dict[str, tuple[Path, str]] = {}
    attempt = task_dir / f"private-{job_number:02d}"
    attempt.mkdir(parents=True)
    for source_index, source in enumerate(needed_sources, 1):
        config = _json_regular(Path(source["config_path"]), parent_root)
        input_data = _json_regular(Path(source["input_path"]), parent_root)
        config = _resolve_tokens(config, row_ids, run_ids)
        input_data = _resolve_tokens(input_data, row_ids, run_ids)
        opaque_prefix = f"q{job_number:02d}"
        config = _remap(config, identifiers, old_to_new, opaque_prefix=opaque_prefix)
        input_data = _remap(input_data, identifiers, old_to_new, opaque_prefix=opaque_prefix)
        config["run_id"] = run_ids[source["run_key"]]
        config["actor"] = "operator"
        config["authorization_ref"] = "operator-supplied"
        out_dir, rows, emitted_run_id = _import_source(repo, parent_root, source, config, input_data, attempt, source_index)
        row_ids[source["run_key"]] = rows
        imported[source["run_key"]] = (out_dir, emitted_run_id)

    request = _resolve_tokens(request, row_ids, run_ids)
    source_run_keys = {source_config["run_id"]: source["run_key"]
                       for source in needed_sources
                       for source_config in [_json_regular(Path(source["config_path"]), parent_root)]}
    if parent != "m5":
        request = _resolve_static_evidence_refs(request, row_ids, source_run_keys)
    request = _remap(request, identifiers, old_to_new, opaque_prefix=f"q{job_number:02d}")
    # Keep source associations opaque and deterministic; no authoring path enters the task.
    runs = []
    visible_job_root = task_dir / "visible" / f"j{job_number:02d}"
    visible_job_root.mkdir(parents=True, exist_ok=True)
    for index, source in enumerate(needed_sources, 1):
        source_key = source["run_key"]
        private_bundle, emitted_run_id = imported[source_key]
        visible_bundle = visible_job_root / "runs" / f"r{index:02d}"
        visible_bundle.mkdir(parents=True, exist_ok=True)
        for name in BUNDLE_FILES:
            _safe_copy_file(private_bundle / name, visible_bundle / name, private_bundle)
        hashes = {name: hashlib.sha256((visible_bundle / name).read_bytes()).hexdigest() for name in SUMMARY_FILES}
        runs.append({"run_id": emitted_run_id, "run_dir": str(visible_bundle), "expected_summary_hashes": hashes})
    runs_by_id = {run["run_id"]: run for run in runs}
    declared_runs = request.get("runs", [])
    request["runs"] = [runs_by_id.get(item.get("run_id"), item) for item in declared_runs]
    if parent == "m3":
        request["service"]["topology_run_id"] = run_ids.get("topology", request["service"].get("topology_run_id"))
    request["schema_version"] = 1
    ticket = job["ticket"]
    provider_request = request
    task_job = {"job_id": job["job_id"], "provider": job["provider"], "ticket": ticket, "request": provider_request}
    parent_oracle_root = (parent_root / "oracle" / "expected.json")
    parent_oracle = _json_regular(parent_oracle_root, parent_root)
    parent_case_id = job["parent_case"]
    base_oracle = next((item for item in parent_oracle.get("cases", []) if item.get("case_id") == parent_case_id), None)
    if base_oracle is None:
        raise CorpusError("parent fixture oracle has no matching case")
    oracle_job = _adapt_oracle({**job, "_job_number": job_number, "oracle": enrichment}, base_oracle, row_ids, run_ids)
    visible_refs = []
    for run_key, evidence_map in row_ids.items():
        for evidence_id in evidence_map.values():
            visible_refs.append({"run_id": run_ids[run_key], "evidence_id": evidence_id})
    return task_job, oracle_job, {"request": request, "row_ids": row_ids, "run_ids": run_ids,
                                  "visible_refs": visible_refs}


def _adapt_oracle(job: dict[str, Any], source: dict[str, Any], row_ids: dict[str, dict[str, str]],
                  run_ids: dict[str, str]) -> dict[str, Any]:
    """Adapt independently authored expectations plus explicit M6 claim enrichments."""
    enrich = job.get("oracle", {})
    provider = job["provider"]
    if provider == "service_review":
        claims = []
        for item in source.get("required_field_results", []):
            claims.append({"kind": "field_result", "code": None, "status": item["status"],
                           "scope": {"field": item["field"], "target": item["target"]}, "layer": None,
                           "fault_class": False, "support_sets": _m5_support_sets(item, job, row_ids),
                           "counter_refs": []})
        for item in source.get("required_test_results", []):
            claims.append({"kind": "test_result", "code": None, "status": item["status"],
                           "scope": {"criterion_id": item["criterion_id"], "absolute_direction": item["absolute_direction"]},
                           "layer": None, "fault_class": False, "support_sets": _m5_support_sets(item, job, row_ids),
                           "counter_refs": []})
        service_states = {"technical": source.get("technical_status"), "acceptance": source.get("acceptance_status"),
                          "change": source.get("change_status")}
        return {"job_id": job["job_id"], "expected_state": None,
                "service_states": service_states, "required_gaps": source.get("required_gaps", []),
                "claims": claims, "prohibited_codes": [], "forbid_causal_links": True}
    claims = []
    for claim in enrich.get("claims", []):
        support_sets = [[_qualified_ref(ref, row_ids, run_ids) for ref in refs] for refs in claim.get("support_sets", [])]
        counter_refs = [_qualified_ref(ref, row_ids, run_ids) for ref in claim.get("counter_refs", [])]
        claims.append({"kind": "finding", "code": claim["code"], "status": claim.get("status"),
                       "scope": claim.get("scope", {}), "layer": claim.get("layer"),
                       "fault_class": bool(claim.get("fault_class", False)), "support_sets": support_sets,
                       "counter_refs": counter_refs})
    return {"job_id": job["job_id"], "expected_state": enrich.get("expected_state") or source.get("status"),
            "service_states": {"technical": None, "acceptance": None, "change": None},
            "required_gaps": enrich.get("required_gaps", []), "claims": claims,
            "prohibited_codes": enrich.get("prohibited_codes", source.get("prohibited_codes", [])),
            "forbid_causal_links": True}


def _m5_support_sets(item: dict[str, Any], job: dict[str, Any], row_ids: dict[str, dict[str, str]]) -> list[list[dict[str, str]]]:
    """Use claim-specific source roles; never copy the parent oracle's union bag."""
    if item.get("status") not in {"match", "mismatch", "pass", "fail"}:
        return []
    field = item.get("field")
    target = item.get("target")
    if field:
        keys = [
            f"design/required_{field}_{target}", f"design/expected_{field}_{target}",
            f"actual-fields/actual_{field}_{target}", f"actual-fields/target_{field}_{target}",
            "topology/topology-envelope",
        ]
        equality_key = f"equivalence/equal_{field}_{target}"
        if row_ids.get("equivalence", {}).get(f"equal_{field}_{target}"):
            # A cross-source comparison is grounded by the scoped mapping record.
            keys.append(equality_key)
    else:
        criterion = str(item.get("criterion_id", "")).removeprefix("criterion-")
        direction = item.get("absolute_direction")
        suffix = "a_to_b" if direction == "A_to_B" else "b_to_a"
        role_keys = (
            "capability", "metric", "aggregation", "comparator", "threshold", "method",
            "min_samples", "direction", "calibration_policy", "window_start", "window_end",
        )
        keys = [f"criteria/{role}_{criterion}" for role in role_keys]
        keys.extend([
            f"actual-tests/measure_{criterion}_{suffix}", f"actual-tests/method_{criterion}_{suffix}",
            f"actual-tests/aggregation_{criterion}_{suffix}", f"actual-tests/start_{criterion}_{suffix}",
            f"actual-tests/end_{criterion}_{suffix}", f"actual-tests/mapping_{criterion}_{suffix}",
            f"actual-tests/instrument_{criterion}_{suffix}", "topology/topology-envelope",
        ])
        calibration = row_ids.get("calibration", {})
        for row_key in ("status", "calibration_start", "calibration_end"):
            if row_key in calibration:
                keys.append(f"calibration/{row_key}")
    refs = []
    prefix = f"r{job.get('_job_number', 1):02d}"
    for value in keys:
        if "/" not in value:
            continue
        run_key, row_key = value.split("/", 1)
        evidence_id = row_ids.get(run_key, {}).get(row_key)
        if evidence_id:
            # Opaque run IDs are assigned by source order for this job.
            run_index = list(row_ids).index(run_key) + 1
            refs.append({"run_id": f"{prefix}{run_index:02d}", "evidence_id": evidence_id})
    return [refs] if refs and len(refs) == len(keys) else []


def _qualified_ref(ref: str, row_ids: dict[str, dict[str, str]], run_ids: dict[str, str]) -> dict[str, str]:
    """Resolve ``run_key:row`` or ``run_key:index`` from emitted importer records."""
    if not isinstance(ref, str) or ":" not in ref:
        raise CorpusError("malformed M6 logical evidence reference")
    run_key, selector = ref.split(":", 1)
    if selector.isdigit():
        row_key = f"#{int(selector)}"
        # M3/M4 sources have no explicit logical row names; use emitted order.
        source_rows = row_ids.get(run_key, {})
        try:
            evidence_id = list(source_rows.values())[int(selector) - 1]
        except IndexError as exc:
            raise CorpusError("source evidence index is outside emitted rows") from exc
    else:
        try:
            evidence_id = row_ids[run_key][selector]
        except KeyError as exc:
            raise CorpusError("unknown logical evidence row") from exc
    return {"run_id": run_ids[run_key], "evidence_id": evidence_id}


def materialize_case(repo_root: str | Path, case_id: str, work_root: str | Path) -> dict[str, Any]:
    """Materialize one opaque visible task and its parent-only oracle."""
    repo = Path(repo_root).resolve(strict=True)
    catalog = load_catalog(repo)
    case = next((item for item in catalog["cases"] if item["case_id"] == case_id), None)
    if case is None:
        raise CorpusError("unknown case ID")
    fixture_root = repo / FIXTURE_REL
    oracle_catalog = _json_regular(Path("oracle-enrichment.json"), fixture_root)
    oracle_cases = oracle_catalog.get("cases") if isinstance(oracle_catalog, dict) else None
    if not isinstance(oracle_catalog, dict) or oracle_catalog.get("schema_version") != 1 or not isinstance(oracle_cases, list) or len(oracle_cases) != 36:
        raise CorpusError("hidden oracle catalog schema is invalid")
    oracle_ids = [item.get("case_id") for item in oracle_cases if isinstance(item, dict)]
    if len(oracle_ids) != 36 or len(set(oracle_ids)) != 36 or set(oracle_ids) != {
            f"case-{index:03d}" for index in range(1, 37)}:
        raise CorpusError("hidden oracle case IDs are missing or duplicated")
    case_enrichment = next((item for item in oracle_catalog.get("cases", []) if item.get("case_id") == case_id), None)
    if not isinstance(case_enrichment, dict) or len(case_enrichment.get("jobs", [])) != len(case["jobs"]):
        raise CorpusError("hidden oracle enrichment is missing or does not match the catalog")
    if not all(isinstance(item, dict) for item in case_enrichment["jobs"]):
        raise CorpusError("hidden oracle job enrichment is malformed")
    work = Path(work_root).absolute()
    if any(parent.is_symlink() for parent in (work, *work.parents) if parent.exists()):
        raise CorpusError("work root path may not contain symlinks")
    if work == repo or repo in work.parents or work in repo.parents:
        raise CorpusError("work root must be separate from the repository")
    if work.exists() and not work.is_dir():
        raise CorpusError("work root must be a regular directory")
    work.mkdir(parents=True, exist_ok=True)
    opaque_case = hashlib.sha256(case_id.encode("ascii")).hexdigest()[:12]
    case_dir = work / f"trial-{opaque_case}"
    if case_dir.exists():
        raise CorpusError("case work directory already exists")
    case_dir.mkdir(mode=0o700)
    visible_root = case_dir / "visible"
    visible_root.mkdir(mode=0o700)
    task_jobs = []
    oracle_jobs = []
    visible_refs_by_job = {}
    for job_number, (job, enrichment) in enumerate(zip(case["jobs"], case_enrichment["jobs"]), 1):
        materialized_task, oracle_job, private = _materialize_job(repo, job, case_dir, job_number, enrichment)
        task_jobs.append(materialized_task)
        oracle_jobs.append(oracle_job)
        visible_refs_by_job[job["job_id"]] = private["visible_refs"]
    task_id = f"task-{opaque_case}"
    task = {"schema_version": 1, "task_id": task_id,
            "prompt": case["prompt"], "jobs": task_jobs}
    task_path = visible_root / "task.json"
    task_path.write_text(json.dumps(task, ensure_ascii=False, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    # Bundle folders already live under visible_root; enumerate only regular files.
    _walk_regular(visible_root)
    oracle = {"schema_version": 1, "task_id": task_id, "jobs": oracle_jobs,
              "required_bindings": case.get("required_bindings", [])}
    return {"task_path": task_path, "oracle": oracle, "visible_root": visible_root,
            "case_id": case_id, "primary_group": case["primary_group"],
            "visible_refs_by_job": visible_refs_by_job}
