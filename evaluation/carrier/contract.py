"""Bounded JSON contracts and mechanical provider-result normalization."""

from __future__ import annotations

import json
import math
from typing import Any

MAX_JSON_BYTES = 2_097_152
MAX_DEPTH = 32
MAX_NODES = 50_000
MAX_STRING = 262_144
PROVIDERS = {"access", "transport", "service_review"}
COMPLETIONS = {"complete", "process_error", "timeout", "invalid_output", "not_started"}


class ContractError(ValueError):
    """Raised when a task or answer is outside the bounded JSON contract."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON object key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ContractError("non-finite JSON number")


def _bounded(value: Any, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if depth > MAX_DEPTH or count[0] > MAX_NODES:
        raise ContractError("JSON structure exceeds limits")
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise ContractError("JSON string exceeds limit")
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise ContractError("JSON string contains an invalid Unicode scalar") from exc
    elif isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > MAX_STRING:
                raise ContractError("invalid JSON object key")
            _bounded(child, depth + 1, count)
    elif isinstance(value, list):
        for child in value:
            _bounded(child, depth + 1, count)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ContractError("non-finite JSON number")
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise ContractError("unsupported JSON value")


def loads_bounded(data: str | bytes) -> Any:
    """Parse UTF-8 JSON with duplicate-key, size, depth, and node limits."""
    if isinstance(data, bytes):
        if len(data) > MAX_JSON_BYTES:
            raise ContractError("JSON input exceeds byte limit")
        try:
            data = data.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ContractError("JSON must be UTF-8") from exc
    elif not isinstance(data, str) or len(data.encode("utf-8")) > MAX_JSON_BYTES:
        raise ContractError("JSON input exceeds byte limit or has invalid type")
    try:
        value = json.loads(data, object_pairs_hook=_pairs, parse_constant=_constant)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ContractError("invalid JSON") from exc
    _bounded(value)
    return value


def dumps_bounded(value: Any) -> str:
    _bounded(value)
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(rendered.encode("utf-8")) > MAX_JSON_BYTES:
        raise ContractError("JSON output exceeds byte limit")
    return rendered


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{name} must be an object")
    return value


def _text(value: Any, name: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, str) or not value or len(value) > MAX_STRING:
        raise ContractError(f"{name} must be a bounded non-empty string")


def validate_task(task: Any) -> dict[str, Any]:
    task = _object(task, "task")
    if set(task) != {"schema_version", "task_id", "prompt", "jobs"}:
        raise ContractError("unexpected task fields")
    if task.get("schema_version") != 1 or isinstance(task.get("schema_version"), bool):
        raise ContractError("unsupported task schema")
    _text(task.get("task_id"), "task_id")
    _text(task.get("prompt"), "prompt")
    jobs = task.get("jobs")
    if not isinstance(jobs, list) or not jobs or len(jobs) > 64:
        raise ContractError("jobs must be a non-empty bounded list")
    ids: set[str] = set()
    for job in jobs:
        job = _object(job, "job")
        if set(job) != {"job_id", "provider", "ticket", "request"}:
            raise ContractError("unexpected job fields")
        _text(job.get("job_id"), "job_id")
        _text(job.get("ticket"), "ticket")
        if job["job_id"] in ids:
            raise ContractError("duplicate job_id")
        ids.add(job["job_id"])
        if job.get("provider") not in PROVIDERS:
            raise ContractError("unknown provider")
        _object(job.get("request"), "request")
    return task


def validate_answer(answer: Any, task: dict[str, Any] | None = None) -> dict[str, Any]:
    answer = _object(answer, "answer")
    if set(answer) != {"schema_version", "task_id", "completion", "jobs"}:
        raise ContractError("unexpected answer fields")
    if answer.get("schema_version") != 1 or isinstance(answer.get("schema_version"), bool):
        raise ContractError("unsupported answer schema")
    _text(answer.get("task_id"), "task_id")
    if answer.get("completion") not in COMPLETIONS - {"not_started"}:
        raise ContractError("invalid task completion")
    jobs = answer.get("jobs")
    if not isinstance(jobs, list) or len(jobs) > 64:
        raise ContractError("answer jobs must be a bounded list")
    seen: set[str] = set()
    for job in jobs:
        job = _object(job, "answer job")
        if set(job) != {"job_id", "completion", "raw_result", "normalized_claims", "provider_metrics"}:
            raise ContractError("unexpected answer job fields")
        _text(job.get("job_id"), "job_id")
        if job["job_id"] in seen:
            raise ContractError("duplicate answer job_id")
        seen.add(job["job_id"])
        if job.get("completion") not in COMPLETIONS:
            raise ContractError("invalid job completion")
        raw = job.get("raw_result")
        if raw is not None:
            _object(raw, "raw_result")
        claims = job.get("normalized_claims")
        if not isinstance(claims, list) or len(claims) > 4096:
            raise ContractError("normalized_claims must be a bounded list")
        for claim in claims:
            _object(claim, "claim")
        if job["completion"] == "complete" and raw is None:
            raise ContractError("complete job must contain a provider result")
        if job["completion"] != "complete" and claims:
            raise ContractError("incomplete job cannot contain normalized claims")
        metrics = _object(job.get("provider_metrics"), "provider_metrics")
        if set(metrics) != {"tokens", "cost"}:
            raise ContractError("unexpected provider metrics")
        for key in ("tokens", "cost"):
            metric = metrics.get(key)
            if metric is not None and (isinstance(metric, bool) or not isinstance(metric, (int, float)) or not math.isfinite(metric) or metric < 0):
                raise ContractError(f"invalid provider metric: {key}")
    if task is not None:
        validate_task(task)
        if answer["task_id"] != task["task_id"]:
            raise ContractError("task_id mismatch")
        task_by_id = {item["job_id"]: item for item in task["jobs"]}
        expected = set(task_by_id)
        if seen - expected:
            raise ContractError("answer contains unknown job")
        if answer["completion"] == "complete" and seen != expected:
            raise ContractError("complete answer must account for every job")
        if answer["completion"] == "complete" and any(job.get("completion") != "complete" for job in jobs):
            raise ContractError("complete answer cannot contain incomplete jobs")
        for job in jobs:
            if job["completion"] == "complete":
                expected_claims = normalize_result(task_by_id[job["job_id"]]["provider"], job["raw_result"])
                if job["normalized_claims"] != expected_claims:
                    raise ContractError("normalized claims do not match raw provider result")
    return answer


def validate_oracle(oracle: Any, task: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate the parent-only expected-result record before scoring."""
    oracle = _object(oracle, "oracle")
    if set(oracle) != {"schema_version", "task_id", "jobs", "required_bindings"}:
        raise ContractError("unexpected oracle fields")
    if oracle.get("schema_version") != 1 or isinstance(oracle.get("schema_version"), bool):
        raise ContractError("unsupported oracle schema")
    _text(oracle.get("task_id"), "oracle task_id")
    jobs = oracle.get("jobs")
    bindings = oracle.get("required_bindings")
    if not isinstance(jobs, list) or not isinstance(bindings, list) or len(jobs) > 64 or len(bindings) > 256:
        raise ContractError("oracle collections exceed limits")
    seen: set[str] = set()
    for job in jobs:
        job = _object(job, "oracle job")
        required = {"job_id", "expected_state", "service_states", "required_gaps", "claims", "prohibited_codes", "forbid_causal_links"}
        if set(job) != required:
            raise ContractError("unexpected oracle job fields")
        _text(job.get("job_id"), "oracle job_id")
        if job["job_id"] in seen:
            raise ContractError("duplicate oracle job_id")
        seen.add(job["job_id"])
        _text(job.get("expected_state"), "expected_state", nullable=True)
        states = _object(job.get("service_states"), "service_states")
        if set(states) != {"technical", "acceptance", "change"}:
            raise ContractError("invalid service state dimensions")
        for value in states.values():
            _text(value, "service state", nullable=True)
        for key in ("required_gaps", "prohibited_codes"):
            values = job.get(key)
            if not isinstance(values, list) or len(values) > 4096:
                raise ContractError(f"{key} must be a bounded list")
            for value in values:
                _text(value, key)
        if not isinstance(job.get("forbid_causal_links"), bool):
            raise ContractError("forbid_causal_links must be boolean")
        claims = job.get("claims")
        if not isinstance(claims, list) or len(claims) > 4096:
            raise ContractError("oracle claims exceed limits")
        claim_keys: set[tuple[Any, ...]] = set()
        for claim in claims:
            claim = _object(claim, "oracle claim")
            if set(claim) != {"kind", "code", "status", "scope", "layer", "fault_class", "support_sets", "counter_refs"}:
                raise ContractError("unexpected oracle claim fields")
            if claim.get("kind") not in {"finding", "field_result", "test_result"}:
                raise ContractError("invalid oracle claim kind")
            for key in ("code", "status", "layer"):
                _text(claim.get(key), key, nullable=True)
            scope = _object(claim.get("scope"), "claim scope")
            if any(not isinstance(key, str) or not isinstance(value, str) for key, value in scope.items()):
                raise ContractError("claim scope values must be strings")
            claim_key = (claim["kind"], claim.get("code"), claim.get("status"), claim.get("layer"), tuple(sorted(scope.items())))
            if claim_key in claim_keys:
                raise ContractError("duplicate oracle claim identity")
            claim_keys.add(claim_key)
            if not isinstance(claim.get("fault_class"), bool):
                raise ContractError("fault_class must be boolean")
            support_sets = claim.get("support_sets")
            counters = claim.get("counter_refs")
            if not isinstance(support_sets, list) or not isinstance(counters, list) or len(support_sets) > 64:
                raise ContractError("invalid oracle support references")
            for refs in support_sets:
                if not isinstance(refs, list) or not refs or len(refs) > 128:
                    raise ContractError("support sets must contain bounded complete references")
                for ref in refs:
                    _object(ref, "qualified reference")
                    if set(ref) != {"run_id", "evidence_id"}:
                        raise ContractError("invalid qualified reference fields")
                    _text(ref.get("run_id"), "run_id")
                    _text(ref.get("evidence_id"), "evidence_id")
            for refs in (counters,):
                if not isinstance(refs, list) or len(refs) > 128:
                    raise ContractError("invalid oracle reference set")
                for ref in refs:
                    _object(ref, "qualified reference")
                    if set(ref) != {"run_id", "evidence_id"}:
                        raise ContractError("invalid qualified reference fields")
                    _text(ref.get("run_id"), "run_id")
                    _text(ref.get("evidence_id"), "evidence_id")
    for binding in bindings:
        _object(binding, "required binding")
    if task is not None:
        validate_task(task)
        if oracle["task_id"] != task["task_id"]:
            raise ContractError("oracle task_id mismatch")
        expected = {job["job_id"] for job in task["jobs"]}
        if seen != expected:
            raise ContractError("oracle jobs do not match task jobs")
    return oracle


def _refs(value: Any) -> list[dict[str, str]]:
    """Project only provider-returned qualified references."""
    if not isinstance(value, list):
        return []
    refs = []
    for ref in value:
        if not isinstance(ref, dict):
            continue
        run_id = ref.get("run_id")
        evidence_id = ref.get("evidence_id")
        if isinstance(run_id, str) and isinstance(evidence_id, str):
            refs.append({"run_id": run_id, "evidence_id": evidence_id})
    return refs


def _optional_text(item: dict[str, Any], key: str) -> str | None:
    value = item.get(key)
    if value is not None and not isinstance(value, str):
        raise ContractError(f"provider result field {key} must be string or null")
    return value


def _gap_codes(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ContractError("provider gaps must be a list of strings")
    return list(value)


def normalize_result(provider: str, raw_result: Any) -> list[dict[str, Any]]:
    """Mechanically project claims from an actual provider result, without truth filling."""
    if provider not in PROVIDERS or not isinstance(raw_result, dict):
        return []
    claims: list[dict[str, Any]] = []
    if provider in {"access", "transport"}:
        findings = raw_result.get("findings")
        if not isinstance(raw_result.get("status"), str) or not isinstance(findings, list):
            raise ContractError("provider result is missing status or findings")
        _gap_codes(raw_result.get("gaps"))
        for item in findings:
            if not isinstance(item, dict):
                raise ContractError("provider finding must be an object")
            claims.append({
                    "kind": "finding",
                    "code": _optional_text(item, "code"),
                    "status": _optional_text(item, "status"),
                    "layer": _optional_text(item, "layer"),
                    "resource_id": _optional_text(item, "resource_id"),
                    "measurement_point": _optional_text(item, "measurement_point"),
                    "scope": {},
                    "support": _refs(item.get("support")),
                    "counterevidence": _refs(item.get("counterevidence")),
                    "gaps": _gap_codes(item.get("gaps")),
                })
    else:
        fields = raw_result.get("field_results")
        tests = raw_result.get("test_matrix")
        change = raw_result.get("change_review")
        if (not isinstance(raw_result.get("technical_status"), str)
                or not isinstance(raw_result.get("acceptance_status"), str)
                or not isinstance(change, dict) or not isinstance(change.get("status"), str)
                or not isinstance(fields, list) or not isinstance(tests, list)):
            raise ContractError("service result is missing required status or matrix fields")
        _gap_codes(raw_result.get("gaps"))
        for item in fields:
            if not isinstance(item, dict):
                raise ContractError("field result must be an object")
            claims.append({
                "kind": "field_result", "code": None,
                "status": _optional_text(item, "status"),
                "layer": None, "resource_id": _optional_text(item, "resource_id"), "measurement_point": None,
                "scope": {key: _optional_text(item, key) for key in ("field", "target") if item.get(key) is not None},
                "support": _refs([item[key] for key in ("required_ref", "expected_ref", "actual_ref", "actual_target_ref", "equivalence_ref", "topology_ref") if isinstance(item.get(key), dict)]),
                "counterevidence": _refs(item.get("counterevidence")),
                "gaps": _gap_codes(item.get("gaps")),
            })
        for item in tests:
            if not isinstance(item, dict):
                raise ContractError("test result must be an object")
            refs = []
            for key in ("measurement_ref", "method_ref", "instrument_ref", "topology_ref", "direction_mapping_ref"):
                if isinstance(item.get(key), dict):
                    refs.append(item[key])
            for key in ("criterion_refs", "window_refs", "calibration_refs"):
                if isinstance(item.get(key), list):
                    refs.extend(ref for ref in item[key] if isinstance(ref, dict))
            claims.append({
                "kind": "test_result", "code": None,
                "status": _optional_text(item, "status"),
                "layer": None, "resource_id": _optional_text(item, "resource_id"),
                "measurement_point": _optional_text(item, "measurement_point"),
                "scope": {key: _optional_text(item, key) for key in ("criterion_id", "absolute_direction") if item.get(key) is not None},
                "support": _refs(refs), "counterevidence": _refs(item.get("counterevidence")),
                "gaps": _gap_codes(item.get("gaps")),
            })
    return claims
