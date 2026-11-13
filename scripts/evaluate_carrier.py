#!/usr/bin/env python3
"""Run deterministic carrier fixture cases through the restricted local adapter."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation.carrier.contract import ContractError, dumps_bounded, loads_bounded, validate_answer, validate_task
from evaluation.carrier.experiments import validate_experiment
from evaluation.carrier.scoring import score_answer
from evaluation.carrier import corpus, isolation


def _canonical(value: Any, roots: tuple[str, ...] = ()) -> Any:
    """Remove parent timing and remap trial paths while preserving answer truth."""
    if isinstance(value, dict):
        return {key: ("<VISIBLE_RUN_DIR>" if key == "run_dir" and isinstance(child, str)
                      else _canonical(child, roots)) for key, child in sorted(value.items())
                if key != "elapsed_ms"}
    if isinstance(value, list):
        return [_canonical(child, roots) for child in value]
    if isinstance(value, str):
        value = re.sub(r"(?:/tmp|/var/tmp)/carrier-m6-[^/]+", "<TRIAL_ROOT>", value)
        for root in roots:
            if root:
                value = value.replace(root, "<TRIAL_ROOT>")
        return value
    return value


def canonical_json(value: Any, roots: tuple[str, ...] = ()) -> str:
    return json.dumps(_canonical(value, roots), ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def _prepare_output_dir(output_dir: Path, replay_dir: Path | None = None) -> Path:
    """Create an exclusive output directory before any trial work begins."""
    output = output_dir.resolve()
    replay = replay_dir.resolve(strict=True) if replay_dir is not None else None
    if replay is not None:
        if not replay.is_dir():
            raise ValueError("replay path must be a directory")
        if output == replay or output.is_relative_to(replay) or replay.is_relative_to(output):
            raise ValueError("replay source and output directories must be separate")
    output.mkdir(parents=True, exist_ok=False)
    return output


def _copy_code(repo: Path, code: Path) -> None:
    product_source = repo / "skills" / "netops-incident" / "scripts"
    product_target = code / "product"
    scripts_target = product_target / "scripts"
    scripts_target.mkdir(parents=True)
    for name in ("diagnose_access.py", "diagnose_transport.py", "review_service.py"):
        shutil.copy2(product_source / name, scripts_target / name)
    shutil.copytree(product_source / "case_runtime", scripts_target / "case_runtime")
    schema_source = repo / "skills" / "netops-incident" / "schemas"
    schema_target = product_target / "schemas"
    schema_target.mkdir()
    for name in ("service-context.schema.json", "carrier-evidence.schema.json"):
        shutil.copy2(schema_source / name, schema_target / name)
    package = repo / "evaluation" / "carrier"
    for name in ("adapter.py", "bootstrap.py", "isolation.py", "contract.py"):
        source = package / name
        if source.is_file():
            shutil.copy2(source, code / name)
    for path in sorted(code.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    code.chmod(0o555)


def _failed_answer(task: dict[str, Any], completion: str) -> dict[str, Any]:
    return {"schema_version": 1, "task_id": task["task_id"], "completion": completion,
            "jobs": [{"job_id": job["job_id"], "completion": completion,
                      "raw_result": None, "normalized_claims": [],
                      "provider_metrics": {"tokens": None, "cost": None}}
                     for job in task["jobs"]]}


def _invoke(repo: Path, task_path: Path, visible_root: Path, work: Path) -> tuple[dict[str, Any], int, str, str]:
    task = validate_task(loads_bounded(task_path.read_bytes()))
    work.mkdir(parents=True, exist_ok=True)
    code = work / "code"
    tmp = work / "tmp"
    code.mkdir()
    tmp.mkdir()
    _copy_code(repo, code)
    adapter = code / "adapter.py"
    if not adapter.is_file():
        return _failed_answer(task, "process_error"), 0, "adapter_unavailable", "invalid"
    argv = [sys.executable, str(adapter), "--task", str(task_path), "--product", str(code / "product")]
    start = time.monotonic_ns()
    result = isolation.run_isolated(argv, read_roots=[code, visible_root], write_root=tmp,
                                    blocked_roots=[repo])
    elapsed_ms = max(0, (time.monotonic_ns() - start) // 1_000_000)
    status_map = {"ok": "complete", "timeout": "timeout", "process_error": "process_error",
                  "output_limit": "invalid_output", "invalid_output": "invalid_output",
                  "isolation_unavailable": "process_error"}
    if result.get("status") != "ok":
        completion = status_map.get(result.get("status"), "process_error")
        validity = "invalid" if result.get("status") == "isolation_unavailable" else "valid"
        return (_failed_answer(task, completion), elapsed_ms,
                result.get("reason", result.get("status", "worker_failed")), validity)
    try:
        answer = validate_answer(loads_bounded(result.get("stdout", "")), task)
    except (ContractError, TypeError):
        return _failed_answer(task, "invalid_output"), elapsed_ms, "worker_answer_rejected", "valid"
    return answer, elapsed_ms, "", "valid"


def _run_case(repo: Path, case_id: str, output_root: Path) -> dict[str, Any]:
    case_dir = output_root / case_id
    case_dir.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="carrier-m6-") as temp_name:
        work = Path(temp_name)
        materialized = corpus.materialize_case(repo, case_id, work / "materialized")
        task_path = Path(materialized["task_path"])
        visible_root = Path(materialized["visible_root"])
        task = validate_task(loads_bounded(task_path.read_bytes()))
        answer, elapsed_ms, failure, trial_validity = _invoke(repo, task_path, visible_root, work / "trial")
        oracle = materialized["oracle"]
        scores = score_answer(task, answer, oracle, elapsed_ms=elapsed_ms,
                              trial_validity=trial_validity,
                              visible_refs_by_job=materialized.get("visible_refs_by_job"))
        report = {"schema_version": 1, "case_id": case_id,
                  "evaluation_kind": "fixture_replay", "adapter_execution": "completed" if not failure else "failed",
                  "controlled_experiment": "not_run", "actual_client_validation": "not_run",
                  "failure": failure or None, "task": task, "answer": answer, "scores": scores,
                  "experiment": {"valid": None, "reason": "not_applicable_to_fixture_replay"}}
        with (case_dir / "report.json").open("x", encoding="utf-8") as report_file:
            report_file.write(dumps_bounded(report) + "\n")
        return report


def _case_ids(repo: Path) -> list[str]:
    catalog = corpus.load_catalog(repo)
    cases = catalog.get("cases") if isinstance(catalog, dict) else None
    if not isinstance(cases, list):
        raise ValueError("invalid carrier M6 catalog")
    ids = [case.get("case_id") for case in cases if isinstance(case, dict)]
    if len(ids) != len(cases) or len(set(ids)) != len(ids):
        raise ValueError("catalog has invalid or duplicate case IDs")
    return ids


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--case", help="run one opaque case ID")
    group.add_argument("--all", action="store_true", help="run the complete declared catalog")
    group.add_argument("--replay", type=Path, help="rerun all cases and compare canonical reports with this directory")
    parser.add_argument("--output-dir", type=Path, default=Path("carrier-m6-results"))
    parser.add_argument("--experiment-record", type=Path,
                        help="validate a previously captured controlled experiment record without running it")
    args = parser.parse_args()
    try:
        if args.experiment_record:
            if args.case or args.all or args.replay:
                parser.error("--experiment-record is a standalone validation mode")
            output_root = _prepare_output_dir(args.output_dir)
            record = loads_bounded(args.experiment_record.read_bytes())
            experiment = validate_experiment(record)
            with (output_root / "experiment-validation.json").open("x", encoding="utf-8") as report_file:
                report_file.write(dumps_bounded(experiment) + "\n")
            print(dumps_bounded({"schema_version": 1, "experiment_validation": experiment,
                                 "provider_execution": "not_run"}))
            return 0 if experiment["valid"] else 1
        if not (args.case or args.all or args.replay):
            parser.error("choose --case, --all, or --replay")
        ids = _case_ids(ROOT)
        if args.case and args.case not in ids:
            raise ValueError("unknown case ID")
        selected = [args.case] if args.case else ids
        output_root = _prepare_output_dir(args.output_dir, args.replay)
        reports = [_run_case(ROOT, case_id, output_root) for case_id in selected]
        if args.replay:
            mismatches = []
            for case_id, current in zip(selected, reports):
                previous_path = args.replay / case_id / "report.json"
                if not previous_path.is_file():
                    mismatches.append(case_id)
                    continue
                previous = loads_bounded(previous_path.read_bytes())
                if canonical_json(current) != canonical_json(previous):
                    mismatches.append(case_id)
            print(dumps_bounded({"schema_version": 1, "replay_matches": not mismatches,
                                 "compared_cases": len(selected), "mismatches": mismatches}))
            setup_failed = any(report["scores"]["trial_validity"] == "invalid" for report in reports)
            all_failed = not any(report["answer"].get("completion") == "complete" for report in reports)
            return 1 if mismatches or setup_failed or all_failed else 0
        print(dumps_bounded({"schema_version": 1, "cases": len(reports), "output_dir": str(output_root)}))
        setup_failed = any(report["scores"]["trial_validity"] == "invalid" for report in reports)
        all_failed = not any(report["answer"].get("completion") == "complete" for report in reports)
        return 1 if setup_failed or all_failed else 0
    except (OSError, ValueError, ContractError, KeyError, TypeError) as exc:
        print(f"carrier evaluation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
