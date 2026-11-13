"""Fail-closed Linux launcher for copied carrier-provider adapters.

The parent owns the oracle. This module sends only adapter arguments and a small
filesystem policy to a fresh bootstrap process; the bootstrap never receives an
oracle path unless a caller incorrectly supplies one as a grant (which is rejected
when it is covered by ``blocked_roots``).
"""
from __future__ import annotations

import json
import math
import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

_BOOTSTRAP = Path(__file__).with_name('bootstrap.py')
_MAX_POLICY_BYTES = 65536
_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 3600
_STDERR_RETAIN_BYTES = 32768


def _canonical_directory(value: os.PathLike[str] | str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError('isolation paths must be absolute')
    # Resolve symlinks before constructing a grant, then reject any symlink in the
    # supplied spelling so a later replacement cannot redirect the allowlist.
    spelling = path
    parts = [spelling, *spelling.parents]
    if any(part.is_symlink() for part in parts):
        raise ValueError('isolation path contains a symlink')
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError('isolation grant must be a directory')
    return resolved


def _covers(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _policy(read_roots, write_root, blocked_roots) -> dict[str, Any]:
    reads = sorted({_canonical_directory(path) for path in read_roots}, key=str)
    if not reads:
        raise ValueError('at least one read root is required')
    writes = _canonical_directory(write_root)
    blocked = sorted({_canonical_directory(path) for path in blocked_roots}, key=str)
    grants = [*reads, writes]
    for private in blocked:
        if any(_covers(grant, private) for grant in grants):
            raise ValueError('an isolation grant covers a blocked root')
        if any(_covers(private, grant) for grant in grants):
            # A grant nested in a private tree is as suspicious as a covering grant.
            raise ValueError('an isolation grant is inside a blocked root')
    if any(_covers(writes, root) or _covers(root, writes) for root in reads):
        raise ValueError('read and write roots must be disjoint')
    return {'read_roots': [str(p) for p in reads], 'write_root': str(writes),
            'blocked_roots': [str(p) for p in blocked]}


def _canonical_python_argv(argv) -> tuple[list[str], Path]:
    """Use the base interpreter, never a repository-local venv executable."""
    base_text = getattr(sys, '_base_executable', None) or sys.executable
    base = Path(base_text).resolve(strict=True)
    current = Path(sys.executable).resolve(strict=True)
    requested = Path(argv[0])
    if not requested.is_absolute():
        raise ValueError('adapter interpreter must be absolute')
    requested = requested.resolve(strict=True)
    if requested not in {base, current}:
        raise ValueError('adapter must use the current Python interpreter')
    normalized = list(argv)
    normalized[0] = str(base)
    normalized.insert(1, '-B')
    return normalized, base


def _strict_json(data: bytes) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result

    return json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def _kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass


def run_isolated(argv, *, read_roots, write_root, blocked_roots=(),
                 timeout_seconds=90, output_limit_bytes=2097152):
    """Run a copied adapter under inherited Landlock and seccomp restrictions.

    This launcher requires Linux and an explicitly supported bootstrap ABI. Setup
    errors are returned as ``isolation_unavailable``; there is no unsandboxed path.
    """
    started = time.monotonic()
    result = {'status': 'isolation_unavailable', 'stdout': '', 'stderr': '',
              'elapsed_ms': 0, 'reason': 'invalid_isolation_request'}
    if not sys.platform.startswith('linux'):
        result['reason'] = 'linux_required'
        return result
    if (not isinstance(argv, (list, tuple)) or not argv or
            any(not isinstance(item, str) or not item or '\x00' in item for item in argv)):
        result['reason'] = 'invalid_argv'
        return result
    if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or
            timeout_seconds <= 0 or timeout_seconds > _MAX_TIMEOUT_SECONDS or
            not math.isfinite(timeout_seconds) or isinstance(output_limit_bytes, bool) or
            not isinstance(output_limit_bytes, int) or not 1 <= output_limit_bytes <= _MAX_OUTPUT_BYTES):
        result['reason'] = 'invalid_limits'
        return result
    try:
        policy = _policy(read_roots, write_root, blocked_roots)
        candidate_argv, base_python = _canonical_python_argv(argv)
        blocked = [Path(path) for path in policy['blocked_roots']]
        if any(_covers(root, base_python) for root in blocked):
            raise ValueError('base interpreter is under a blocked root')
        payload = json.dumps({'argv': candidate_argv, **policy}, separators=(',', ':'),
                             ensure_ascii=True, allow_nan=False).encode('ascii')
        if len(payload) > _MAX_POLICY_BYTES:
            raise ValueError('policy exceeds limit')
        if not _BOOTSTRAP.is_file():
            raise ValueError('trusted bootstrap is missing')
    except (OSError, TypeError, ValueError):
        result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
        return result

    env = {'PATH': os.defpath, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
           'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    try:
        proc = subprocess.Popen([str(base_python), '-I', '-S', str(_BOOTSTRAP)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, close_fds=True,
                                start_new_session=True, cwd=str(Path(policy['write_root'])),
                                env=env, bufsize=0)
        assert proc.stdin is not None
        proc.stdin.write(payload)
        proc.stdin.close()
    except (OSError, ValueError):
        if 'proc' in locals():
            _kill_group(proc)
            proc.wait()
        result['reason'] = 'bootstrap_start_failed'
        result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
        return result

    selector = selectors.DefaultSelector()
    streams = {'stdout': proc.stdout, 'stderr': proc.stderr}
    output = bytearray()
    stderr = bytearray()
    total_bytes = 0
    overflow = False
    timed_out = False
    deadline = started + float(timeout_seconds)
    try:
        for name, stream in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            if proc.poll() is not None:
                # A successful launcher must not leave detached work in its group.
                _kill_group(proc)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _kill_group(proc)
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total_bytes += len(chunk)
                if total_bytes > output_limit_bytes:
                    overflow = True
                    _kill_group(proc)
                    break
                if key.data == 'stdout':
                    output.extend(chunk)
                else:
                    keep = max(0, _STDERR_RETAIN_BYTES - len(stderr))
                    stderr.extend(chunk[:keep])
            if overflow:
                break
        if proc.poll() is None:
            try:
                proc.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_group(proc)
        # The launcher may have exited while a multiprocessing child remains.
        # Terminate the complete process group even on ordinary completion.
        _kill_group(proc)
        proc.wait()
    finally:
        _kill_group(proc)
        if proc.poll() is None:
            proc.wait()
        selector.close()
        for stream in streams.values():
            if stream is not None:
                stream.close()

    result['stdout'] = output.decode('utf-8', 'replace')
    result['stderr'] = stderr.decode('utf-8', 'replace')
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
    if timed_out:
        result.update(status='timeout', reason='deadline_exceeded')
    elif overflow:
        result.update(status='output_limit', reason='output_limit_exceeded')
    elif proc.returncode != 0:
        if result['stderr'].startswith('isolation_unavailable:'):
            result.update(status='isolation_unavailable', reason='sandbox_setup_failed')
        else:
            result.update(status='process_error', reason='adapter_failed')
    else:
        try:
            answer = _strict_json(output)
            if not isinstance(answer, dict):
                raise ValueError('answer must be an object')
        except (UnicodeError, ValueError, json.JSONDecodeError):
            result.update(status='invalid_output', reason='adapter_output_not_json')
        else:
            result.update(status='ok', reason=None)
    return result
