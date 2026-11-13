#!/usr/bin/env python3
"""Prepare small public M5 validation inputs from self-authored source fixtures."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "carrier-m5"
INGEST = ROOT / "skills" / "netops-incident" / "scripts" / "ingest.py"
SUMMARY_FILES = ("manifest.json", "evidence.jsonl", "diagnosis.json", "report.md")
VISIBLE_FILES = (*SUMMARY_FILES, "carrier-visible.json")
MAX_REQUEST_BYTES = 1_048_576


def _read_fixture_json(path: Path, fixture_root: Path) -> Any:
    """Read one bounded regular fixture beneath the selected M5 fixture root."""
    resolved_root = fixture_root.resolve(strict=True)
    if path.is_symlink() or not path.resolve(strict=True).is_relative_to(resolved_root):
        raise ValueError("fixture path escapes the M5 fixture root")
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.stat().st_size > 2 * MAX_REQUEST_BYTES:
        raise ValueError("fixture is not a bounded regular file")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key in fixture")
            result[key] = value
        return result

    data = resolved.read_bytes()
    if len(data) > 2 * MAX_REQUEST_BYTES:
        raise ValueError("fixture exceeds byte limit")
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite fixture number")))


def _hashes(run_dir: Path) -> dict[str, str]:
    return {name: hashlib.sha256((run_dir / name).read_bytes()).hexdigest()
            for name in SUMMARY_FILES}


def _replace_tokens(value: Any, run_dirs: dict[str, str], hashes: dict[str, dict[str, str]]) -> Any:
    if isinstance(value, str):
        if value.startswith("$RUN:"):
            key = value[5:]
            if key not in run_dirs:
                raise ValueError("unknown run token")
            return run_dirs[key]
        if value == "$HASH":
            raise ValueError("unqualified hash token")
        return value
    if isinstance(value, list):
        return [_replace_tokens(item, run_dirs, hashes) for item in value]
    if isinstance(value, dict):
        if set(value) == {"$HASH"}:
            marker = value["$HASH"]
            if not isinstance(marker, str) or marker.count("/") != 1:
                raise ValueError("malformed hash token")
            run_key, artifact = marker.split("/", 1)
            return hashes[run_key][artifact]
        return {key: _replace_tokens(item, run_dirs, hashes) for key, item in value.items()}
    return value


def _materialize_case(repo: Path, case_id: str, dest: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Import the selected source files with M2 and return public bundles plus request."""
    from importlib.util import module_from_spec, spec_from_file_location

    fixtures = repo / "tests" / "fixtures" / "carrier-m5"
    ingest = repo / "skills" / "netops-incident" / "scripts" / "ingest.py"
    refs_spec = spec_from_file_location("validation_fixture_refs", fixtures / "materialize_refs.py")
    if refs_spec is None or refs_spec.loader is None:
        raise ValueError("fixture reference resolver unavailable")
    refs = module_from_spec(refs_spec)
    refs_spec.loader.exec_module(refs)
    scenario_path = fixtures / "cases" / case_id / "scenario.json"
    scenario = _read_fixture_json(scenario_path, fixtures)
    row_ids: dict[str, dict[str, str]] = {}
    run_ids: dict[str, str] = {}
    run_dirs: dict[str, str] = {}
    hashes: dict[str, dict[str, str]] = {}
    public_runs: dict[str, Path] = {}

    with tempfile.TemporaryDirectory(prefix="netops-validation-") as private_tmp:
        temp_root = Path(private_tmp)
        for source in scenario["sources"]:
            key = source["run_key"]
            config = refs.resolve_source_tokens(
                _read_fixture_json(fixtures / source["config_path"], fixtures),
                row_ids, run_ids)
            data = refs.resolve_source_tokens(
                _read_fixture_json(fixtures / source["input_path"], fixtures),
                row_ids, run_ids)
            attempt = temp_root / ("source-" + str(len(run_ids)))
            source_root = attempt / "source"
            source_root.mkdir(parents=True)
            raw_path = source_root / "input.json"
            if isinstance(data, dict) and isinstance(data.get("records"), list):
                header = {name: value for name, value in data.items() if name != "records"}
                raw_path.write_text(json.dumps(header, separators=(",", ":"))[:-1]
                                    + ',"records":[\n'
                                    + ",\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":"))
                                                   for row in data["records"])
                                    + "\n]}\n", encoding="utf-8")
            else:
                raw_path.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n",
                                    encoding="utf-8")
            config_path = attempt / "config.json"
            config_path.write_text(json.dumps(config, ensure_ascii=False, separators=(",", ":")) + "\n",
                                   encoding="utf-8")
            run_dir = attempt / "run"
            result = subprocess.run(
                [sys.executable, "-B", str(ingest), "--source-root", str(source_root),
                 "--source", "input.json", "--config", str(config_path), "--out", str(run_dir),
                 "--private-out", str(attempt / "private")],
                capture_output=True, text=True, check=False)
            if result.returncode != 0:
                raise ValueError("M2 rejected a self-authored validation source")
            ingest_summary = json.loads(result.stdout)
            if ingest_summary.get("parse_status") != "complete":
                raise ValueError("M2 did not produce a complete visible bundle")
            evidence = [json.loads(line) for line in (run_dir / "evidence.jsonl").read_text().splitlines()
                        if line.strip()]
            keys = source["row_keys"]
            if len(keys) != len(evidence) or len(keys) != len(set(keys)):
                raise ValueError("source row labels do not match emitted M2 records")
            row_ids[key] = {label: row["id"] for label, row in zip(keys, evidence)}
            run_ids[key] = config["run_id"]
            bundle = dest / "runs" / key
            bundle.mkdir(parents=True)
            for name in VISIBLE_FILES:
                shutil.copyfile(run_dir / name, bundle / name)
            public_runs[key] = bundle
            run_dirs[key] = (Path(dest.name) / bundle.relative_to(dest)).as_posix()
            hashes[key] = _hashes(bundle)

    request = copy.deepcopy(scenario["request"])
    run_templates = request.pop("runs")
    request = refs.resolve_row_refs(request, row_ids)
    run_key_by_id = {run_id: key for key, run_id in run_ids.items()}
    request = _replace_tokens(request, run_dirs, hashes)
    request["runs"] = []
    for run_template in run_templates:
        key = run_key_by_id[run_template["run_id"]]
        request["runs"].append({
            "run_id": run_template["run_id"],
            "run_dir": run_dirs[key],
            "expected_summary_hashes": hashes[key],
        })
    # The checked request uses portable relative run paths until the user resolves it.
    encoded = json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_REQUEST_BYTES:
        raise ValueError("prepared request exceeds the provider byte limit")
    return {"runs": run_dirs, "hashes": hashes}, request


MATERIALIZER = '''#!/usr/bin/env python3
"""Resolve portable request run paths under a user-selected examples directory."""
import argparse, hashlib, json, os, stat, time
from pathlib import Path, PurePosixPath

MAX_BYTES = 1_048_576
SUMMARY = ("manifest.json", "evidence.jsonl", "diagnosis.json", "report.md")
DEADLINE = time.monotonic() + 10

def no_symlink_components(path):
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if current.is_symlink(): return False
    return True

def confined_file(root, relative):
    rel = PurePosixPath(relative)
    if rel.is_absolute() or ".." in rel.parts or "\\\\" in relative: raise ValueError("unsafe relative path")
    candidate = root.joinpath(*rel.parts)
    if not no_symlink_components(candidate): raise ValueError("symlink path")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root) or not resolved.is_file(): raise ValueError("path escapes root or is not a file")
    if resolved.stat().st_size > MAX_BYTES: raise ValueError("file exceeds input byte limit")
    return resolved

def bounded_json(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES: raise ValueError("input is not bounded regular file")
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES: raise ValueError("input exceeds byte limit")
    value = json.loads(data.decode("utf-8"))
    todo = [(value, 0)]; nodes = 0
    while todo:
        if time.monotonic() > DEADLINE: raise ValueError("materialization time limit")
        item, depth = todo.pop(); nodes += 1
        if nodes > 20000 or depth > 20: raise ValueError("JSON structure exceeds limits")
        if isinstance(item, dict): todo.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list): todo.extend((child, depth + 1) for child in item)
    return value

def bounded_bytes(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES: raise ValueError("bundle file is not bounded regular file")
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES: raise ValueError("bundle file exceeds byte limit")
    return data

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="directory containing the selected example")
    parser.add_argument("--template", required=True, type=Path, help="relative request template path")
    parser.add_argument("--out", required=True, type=Path, help="new request JSON path")
    args = parser.parse_args()
    try:
        if not no_symlink_components(args.root.absolute()): raise ValueError("root contains a symlink")
        root = args.root.resolve(strict=True)
        if not root.is_dir(): raise ValueError("root must be a directory")
        source = confined_file(root, args.template.as_posix())
        request = bounded_json(source)
        runs = request.get("runs") if isinstance(request, dict) else None
        if not isinstance(runs, list) or not 1 <= len(runs) <= 8: raise ValueError("request must contain 1 to 8 runs")
        total = 0
        for run in runs:
            if not isinstance(run, dict) or not isinstance(run.get("expected_summary_hashes"), dict): raise ValueError("invalid run entry")
            rel = PurePosixPath(run.get("run_dir", ""))
            if rel.is_absolute() or ".." in rel.parts: raise ValueError("unsafe run path")
            lexical = root.joinpath(*rel.parts)
            if not no_symlink_components(lexical): raise ValueError("run path contains a symlink")
            run_dir = lexical.resolve(strict=True)
            if not run_dir.is_relative_to(root) or not run_dir.is_dir(): raise ValueError("run path escapes root")
            for name in (*SUMMARY, "carrier-visible.json"):
                if time.monotonic() > DEADLINE: raise ValueError("materialization time limit")
                file = confined_file(root, (rel / name).as_posix())
                data = bounded_bytes(file)
                total += len(data)
                if total > 16 * MAX_BYTES: raise ValueError("bundles exceed aggregate byte limit")
                if name in SUMMARY:
                    expected = run["expected_summary_hashes"].get(name)
                    if not isinstance(expected, str) or hashlib.sha256(data).hexdigest() != expected: raise ValueError("bundle hash mismatch")
            manifest = bounded_json(confined_file(root, (rel / "manifest.json").as_posix()))
            visible_hash = manifest.get("artifact_hashes", {}).get("carrier-visible.json")
            visible = confined_file(root, (rel / "carrier-visible.json").as_posix())
            if visible_hash != hashlib.sha256(bounded_bytes(visible)).hexdigest(): raise ValueError("visible bundle hash mismatch")
            run["run_dir"] = str(run_dir)
        out = args.out.absolute()
        if not no_symlink_components(out.parent): raise ValueError("output parent contains a symlink")
        if not out.parent.is_dir() or out.exists() or out.is_symlink(): raise ValueError("output parent must exist and output must be new")
        if out.resolve().is_relative_to(root): raise ValueError("output must be outside the example root")
        with out.open("x", encoding="utf-8") as stream:
            json.dump(request, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":")); stream.write("\\n")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, RecursionError) as exc:
        parser.error("cannot materialize checked request: " + type(exc).__name__)
    return 0

if __name__ == "__main__": raise SystemExit(main())
'''


def prepare_inputs(repo_root: Path, output_dir: Path) -> dict[str, Any]:
    """Write prepared normal/change bundles and malformed CLI input to a new directory."""
    repo = Path(repo_root).resolve(strict=True)
    output = Path(output_dir).absolute()
    ancestor = Path(output.anchor)
    for part in output.parts[1:-1]:
        ancestor = ancestor / part
        if ancestor.is_symlink():
            raise ValueError("validation input output path contains a symlink")
    if output.exists() or output.is_symlink():
        raise FileExistsError("validation input output directory already exists")
    if output.resolve().is_relative_to(repo) or repo.is_relative_to(output.resolve()):
        raise ValueError("validation input output and source tree must be separate")
    output.mkdir(parents=True)
    results = {}
    for key, case_id, folder, behavior in (
        ("normal", "case-009", "normal", {"technical_conformance": "conformant", "human_decision": "pending_user", "evidence_is_historical": True}),
        ("missing_reverse", "case-006", "missing-reverse", {"technical_conformance": "unverified", "direction_status": {"A_to_B": "reviewable", "B_to_A": "unverified"}, "reason": "missing_reverse_measurements", "human_decision": "pending_user"}),
    ):
        destination = output / folder
        destination.mkdir()
        metadata, request = _materialize_case(repo, case_id, destination)
        template_rel = Path(folder) / "request.template.json"
        (output / template_rel).write_text(json.dumps(request, ensure_ascii=False, sort_keys=True,
                                                       separators=(",", ":")) + "\n", encoding="utf-8")
        results[key] = {"bundle_root": (Path(folder) / "runs").as_posix(),
                        "request_template": template_rel.as_posix(),
                        "expected_behavior": behavior}
    malformed = output / "malformed-input.json"
    malformed.write_text('{"schema_version": 1, "runs": [}\n', encoding="utf-8")
    materializer = output / "materialize_request.py"
    materializer.write_text(MATERIALIZER, encoding="utf-8")
    results["malformed"] = {"input": malformed.relative_to(output).as_posix(),
                            "expected_behavior": {"cli": "reject_invalid_json"}}
    results["materializer"] = materializer.relative_to(output).as_posix()
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare_inputs(args.repo_root, args.out), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"validation input preparation failed: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
