#!/usr/bin/env python3
"""Recheck a locally supplied, hash-pinned corpus without downloading or probing."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "docs/research/real-pcap-corpus.json"
CLI = ROOT / "skills/internet-access-triage/scripts/diagnose.py"
CORPUS_PREFIX = Path('.tools/pcap-corpus')


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def run(command: list[str], timeout: int = 40) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                          check=False, timeout=timeout)


def inside(base: Path, relative: str) -> Path:
    candidate = (base / relative).resolve()
    if not candidate.is_relative_to(base.resolve()):
        raise ValueError(f"path escapes its directory: {relative}")
    return candidate


def validate_case(item: dict, capture: Path, output: Path) -> dict:
    checks: dict[str, bool] = {}
    commands: list[dict] = []
    def execute(command: list[str]) -> subprocess.CompletedProcess[str]:
        started = time.monotonic()
        result = run(command)
        commands.append({'argv': command, 'returncode': result.returncode,
                         'elapsed_seconds': round(time.monotonic() - started, 3),
                         'stderr': result.stderr[-4096:]})
        return result

    result = execute([sys.executable, '-B', str(CLI), '--pcap', str(capture), '--out', str(output)])
    checks['cli_exit_zero'] = result.returncode == 0
    if result.returncode != 0:
        return {'name': item['name'], 'variant': item['variant'], 'checks': checks,
                'commands': commands, 'stdout': result.stdout[-4096:]}
    manifest = json.loads((output / 'manifest.json').read_text())
    diagnosis = json.loads((output / 'diagnosis.json').read_text())
    evidence = [json.loads(line) for line in (output / 'evidence.jsonl').read_text().splitlines()]
    record = next(e for e in evidence if e.get('kind') == 'pcap_analysis')
    observation = record['observation']
    summary = observation['summary']
    expected = item['independent_metrics']
    checks['input_hash'] = manifest['scope']['capture_sha256'] == item['sha256']
    checks['artifact_hashes'] = all(inside(output, path).is_file() and digest(inside(output, path)) == h
                                   for path, h in manifest['artifact_hashes'].items())
    skill = ROOT / 'skills/internet-access-triage'
    checks['source_hashes'] = all(inside(skill, path).is_file() and digest(inside(skill, path)) == h
                                 for path, h in manifest['source_hashes'].items())
    source_checks = []
    for ev in evidence:
        for source in ev.get('sources', []):
            if source['kind'] == 'external_input':
                source_checks.append(source['sha256'] == item['sha256'])
            elif source['kind'] == 'run_artifact':
                p = inside(output, source['path'])
                source_checks.append(p.is_file() and digest(p) == source['sha256'])
    checks['evidence_source_hashes'] = bool(source_checks) and all(source_checks)
    ids = {e['id'] for e in evidence}
    refs = set(diagnosis['evidence_ids'])
    for candidate in diagnosis['candidates']:
        refs.update(candidate['evidence_ids'])
        refs.update(candidate['counterevidence_ids'])
    for counter in diagnosis.get('counterevidence', []):
        refs.add(counter['evidence_id'])
    checks['diagnosis_references'] = refs <= ids
    checks['diagnosis_scoped'] = diagnosis['status'] == item['cli_status'] == 'insufficient_evidence'
    checks['no_live_network'] = all(not call['network_request_started'] for call in manifest['subprocess_calls'])
    checks['complete_without_truncation'] = record['status'] == 'complete' and not observation['output_truncated']
    checks['no_validation_errors'] = not any(manifest['validation_errors'].values())
    frame_result = execute(['tshark', '-2', '-n', '-r', str(capture), '-T', 'fields',
                            '-e', 'frame.number', '-e', 'frame.cap_len', '-e', 'frame.len'])
    frame_rows = [line.split('\t') for line in frame_result.stdout.splitlines()]
    frame_count = len(frame_rows)
    truncated_count = sum(int(row[1]) < int(row[2]) for row in frame_rows if len(row) == 3)
    checks['independent_frames'] = frame_result.returncode == 0 and frame_count == expected['frames']
    checks['independent_truncation'] = (all(len(row) == 3 for row in frame_rows)
                                        and truncated_count == expected['truncated_frames'])
    checks['selected_frames'] = summary['frames'] == frame_count
    checks['truncated_frames'] = summary['truncated_frames'] == truncated_count
    independent = {}
    for name, value in [('queries', 0), ('responses', 1)]:
        command = ['tshark', '-2', '-n', '-r', str(capture), '-Y',
                   f'dns.id && dns.flags.response == {value}', '-T', 'fields', '-e', 'frame.number']
        filtered = execute(command)
        independent[name] = len(filtered.stdout.splitlines())
        frozen = expected['dns_query_frames' if value == 0 else 'dns_response_frames']
        checks['independent_dns_' + name] = filtered.returncode == 0 and independent[name] == frozen
        checks['runtime_dns_' + name] = summary['dns_' + name] == independent[name]
    checks['no_unknown_directions'] = summary['dns_direction_unknown_frames'] == 0
    checks['no_mixed_directions'] = summary['dns_mixed_direction_frames'] == 0
    return {'name': item['name'], 'variant': item['variant'], 'input_sha256': item['sha256'],
            'checks': checks, 'commands': commands, 'diagnosis_status': diagnosis['status'],
            'runtime_summary': summary, 'independent_dns_frames': independent,
            'manifest_duration_ns': manifest['duration_ns']}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument('--corpus', type=Path, default=ROOT / CORPUS_PREFIX)
    parser.add_argument('--out', type=Path, required=True, help='new directory for run artifacts')
    args = parser.parse_args()
    args.out = args.out.absolute()
    args.corpus = args.corpus.absolute()
    try:
        if args.out.exists() or args.out.is_symlink():
            raise ValueError(f'output already exists: {args.out}')
        manifest = json.loads(args.manifest.read_text())
        entries = manifest['files']
        if not entries:
            raise ValueError('manifest has no inputs')
        inputs = []
        names = set()
        for item in entries:
            name = item['name'] + '-' + item['variant']
            if not name.replace('-', '').isalnum() or name in names:
                raise ValueError(f'invalid or duplicate case name: {name}')
            names.add(name)
            relative = Path(item['path']).relative_to(CORPUS_PREFIX)
            capture = inside(args.corpus, str(relative))
            if not capture.is_file():
                raise ValueError(f'missing input: {capture}')
            if digest(capture) != item['sha256']:
                raise ValueError(f'hash mismatch: {capture}')
            inputs.append((item, capture, name))
        args.out.mkdir(parents=True, exist_ok=False)
        results = []
        for item, capture, name in inputs:
            try:
                result = validate_case(item, capture, args.out / name)
            except (OSError, ValueError, KeyError, StopIteration, json.JSONDecodeError,
                    subprocess.TimeoutExpired) as exc:
                result = {'name': item['name'], 'variant': item['variant'],
                          'checks': {'execution_exception': False}, 'error': str(exc)}
            results.append(result)
            failures = [k for k, v in result['checks'].items() if not v]
            print(f"{name}: {'PASS' if not failures else 'FAIL ' + ', '.join(failures)}", flush=True)
        passed = all(all(r['checks'].values()) for r in results)
        (args.out / 'validation.json').write_text(json.dumps({'passed': passed, 'results': results}, indent=2) + '\n')
        return 0 if passed else 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f'validation failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
