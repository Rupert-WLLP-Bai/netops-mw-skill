"""Run copied carrier provider command-line tools for one visible task."""
from __future__ import annotations

import argparse
import json
import os
import selectors
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import contract

_INPUT_LIMIT = 16 * 1024 * 1024
_REQUEST_LIMIT = 1024 * 1024
_PROVIDER_OUTPUT_LIMIT = 2 * 1024 * 1024
_PROVIDER_TIMEOUT_SECONDS = 30
_CLI = {'access': 'diagnose_access.py', 'transport': 'diagnose_transport.py',
        'service_review': 'review_service.py'}


def _json(data: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def _under(root: Path, child: Path) -> bool:
    try:
        child.relative_to(root)
        return True
    except ValueError:
        return False


def _validate_request_paths(value, visible_root: Path) -> None:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if key == 'run_dir':
                    if not isinstance(child, str) or not Path(child).is_absolute():
                        raise ValueError('invalid_visible_run')
                    supplied = Path(child)
                    if any(part.is_symlink() for part in (supplied, *supplied.parents)):
                        raise ValueError('visible_run_contains_symlink')
                    resolved = Path(child).resolve(strict=True)
                    if not _under(visible_root, resolved) or not resolved.is_dir():
                        raise ValueError('run_outside_visible_root')
                pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)


def _run_bounded(command: list[str], timeout: float):
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               close_fds=True, bufsize=0)
    selector = selectors.DefaultSelector()
    streams = {'stdout': process.stdout, 'stderr': process.stderr}
    for name, stream in streams.items():
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    chunks = {'stdout': bytearray(), 'stderr': bytearray()}
    total = 0
    overflow = False
    try:
        import time
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                overflow = False
                process.kill()
                process.wait()
                return 'timeout', b'', b''
            for key, _ in selector.select(min(remaining, .1)):
                try:
                    data = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                total += len(data)
                if total > _PROVIDER_OUTPUT_LIMIT:
                    overflow = True
                    process.kill()
                    process.wait()
                    break
                chunks[key.data].extend(data)
            if overflow:
                break
        process.wait()
        return ('process_error' if process.returncode else 'complete',
                bytes(chunks['stdout']), bytes(chunks['stderr']))
    finally:
        selector.close()
        for stream in streams.values():
            if stream is not None:
                stream.close()
        if process.poll() is None:
            process.kill()
            process.wait()


def _load_task(task_path: Path) -> dict:
    if not task_path.is_absolute():
        raise ValueError('task_path_must_be_absolute')
    if task_path.is_symlink():
        raise ValueError('task_path_must_not_be_symlink')
    if task_path.stat().st_size > _INPUT_LIMIT:
        raise ValueError('task_too_large')
    task = _json(task_path.read_bytes())
    if (not isinstance(task, dict) or set(task) != {'schema_version', 'task_id', 'prompt', 'jobs'} or
            task['schema_version'] != 1 or not isinstance(task['task_id'], str) or
            not isinstance(task['prompt'], str) or len(task['prompt']) > 32768 or
            not isinstance(task['jobs'], list) or not 1 <= len(task['jobs']) <= 64):
        raise ValueError('invalid_visible_task')
    visible_root = task_path.parent.resolve(strict=True)
    seen = set()
    for job in task['jobs']:
        if (not isinstance(job, dict) or set(job) != {'job_id', 'provider', 'ticket', 'request'} or
                not isinstance(job['job_id'], str) or job['job_id'] in seen or
                job['provider'] not in _CLI or not isinstance(job['ticket'], str) or
                len(job['ticket']) > 32768 or
                not isinstance(job['request'], dict)):
            raise ValueError('invalid_visible_job')
        seen.add(job['job_id'])
        _validate_request_paths(job['request'], visible_root)
    return task


def run_task(task_path: Path, product_root: Path) -> dict:
    task = _load_task(task_path)
    product_root = product_root.resolve(strict=True)
    scripts = product_root / 'scripts'
    if not scripts.is_dir():
        scripts = product_root
    jobs = []
    with tempfile.TemporaryDirectory(prefix='carrier-adapter-') as temp:
        temp_root = Path(temp)
        for job in task['jobs']:
            script = (scripts / _CLI[job['provider']]).resolve(strict=True)
            if not _under(product_root, script) or not script.is_file():
                raise ValueError('provider_cli_not_in_product')
            request_path = temp_root / ('request-' + str(len(jobs)) + '.json')
            request_bytes = json.dumps(job['request'], ensure_ascii=False, sort_keys=True,
                                       separators=(',', ':'), allow_nan=False).encode('utf-8')
            if len(request_bytes) > _REQUEST_LIMIT:
                raise ValueError('provider_request_too_large')
            request_path.write_bytes(request_bytes)
            # -I prevents environment and user-site imports. The copied product's
            # scripts directory is inserted explicitly for its case_runtime package.
            runner = ('import runpy,sys; script=sys.argv[2]; sys.path.insert(0,sys.argv[1]); '
                      'sys.argv=sys.argv[2:]; runpy.run_path(script,run_name="__main__")')
            status, stdout, _stderr = _run_bounded(
                [sys.executable, '-B', '-I', '-S', '-c', runner, str(scripts), str(script),
                 '--input', str(request_path)], _PROVIDER_TIMEOUT_SECONDS)
            raw = None
            if status == 'complete':
                try:
                    raw = _json(stdout)
                    if not isinstance(raw, dict):
                        raise ValueError('provider_output_not_object')
                except (UnicodeError, ValueError, json.JSONDecodeError):
                    status = 'invalid_output'
            normalized = contract.normalize_result(job['provider'], raw) if raw is not None else []
            jobs.append({'job_id': job['job_id'], 'completion': status, 'raw_result': raw,
                         'normalized_claims': normalized,
                         'provider_metrics': {'tokens': None, 'cost': None}})
    statuses = {job['completion'] for job in jobs}
    completion = ('complete' if statuses == {'complete'} else
                  'timeout' if 'timeout' in statuses else
                  'invalid_output' if 'invalid_output' in statuses else 'process_error')
    return {'schema_version': 1, 'task_id': task['task_id'], 'completion': completion,
            'jobs': jobs}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--task', type=Path, required=True)
    parser.add_argument('--product', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        answer = run_task(args.task, args.product)
        sys.stdout.write(json.dumps(answer, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':'), allow_nan=False) + '\n')
        return 0
    except (OSError, ValueError, TypeError, RuntimeError, RecursionError):
        # Do not leak host paths, request details, or provider stderr.
        answer = {'schema_version': 1, 'task_id': None, 'completion': 'process_error', 'jobs': []}
        sys.stdout.write(json.dumps(answer, separators=(',', ':')) + '\n')
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
