"""Validation for records from separately run controlled lab experiments."""

from __future__ import annotations

from typing import Any

STAGES = (
    "baseline", "injection_proof", "diagnosis", "cleanup",
    "original_operation_recovery", "residual_resource_check",
)


def _scope(record: dict[str, Any]) -> dict[str, Any] | None:
    value = record.get("operation_scope")
    if not isinstance(value, dict) or not value:
        return None
    return value


def _valid_refs(value: Any) -> bool:
    return (isinstance(value, list) and bool(value) and all(
        isinstance(ref, dict) and isinstance(ref.get("run_id"), str) and bool(ref["run_id"])
        and isinstance(ref.get("evidence_id"), str) and bool(ref["evidence_id"])
        for ref in value
    ))


def validate_experiment(record: Any) -> dict[str, Any]:
    """Return validity and explicit reasons; never executes an injection.

    A valid record contains six passed stages, evidence references for each stage,
    and one identical operation scope carried through recovery and residual checks.
    """
    reasons: list[str] = []
    if (not isinstance(record, dict) or record.get("schema_version") != 1
            or isinstance(record.get("schema_version"), bool)):
        return {"valid": False, "validity": "invalid", "reasons": ["invalid_record_schema"], "stages": {}}
    stages = record.get("stages")
    if not isinstance(stages, dict):
        return {"valid": False, "validity": "invalid", "reasons": ["missing_stages"], "stages": {}}
    status_report: dict[str, Any] = {}
    common_scope: dict[str, Any] | None = None
    for name in STAGES:
        stage = stages.get(name)
        if not isinstance(stage, dict):
            reasons.append(f"missing_stage:{name}")
            status_report[name] = "missing"
            continue
        status = stage.get("status")
        status_report[name] = status if isinstance(status, str) else "missing"
        if status != "passed":
            reasons.append(f"stage_not_passed:{name}")
        if not _valid_refs(stage.get("evidence")):
            reasons.append(f"missing_or_invalid_evidence:{name}")
        scope = _scope(stage)
        if scope is None:
            reasons.append(f"missing_operation_scope:{name}")
        elif common_scope is None:
            common_scope = scope
        elif scope != common_scope:
            reasons.append(f"operation_scope_mismatch:{name}")
    unknown = set(stages) - set(STAGES)
    if unknown:
        reasons.append("unknown_stages")
    return {"valid": not reasons, "validity": "valid" if not reasons else "invalid",
            "reasons": reasons, "stages": status_report}
