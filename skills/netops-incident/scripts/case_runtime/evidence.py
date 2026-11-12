"""Import bounded evidence snapshots and record scoped decisions."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath
from .store import CaseError, TERMINAL, nonempty, timestamp, token, transact

SUMMARIES = ('manifest.json', 'evidence.jsonl', 'diagnosis.json', 'report.md')
LIMIT = 16 * 1024 * 1024

def sha(data):
    return hashlib.sha256(data).hexdigest()

def rename_noreplace(source: Path, destination: Path):
    """Publish an import without replacing even an empty destination."""
    if os.name == 'nt':
        os.rename(source, destination)
        return
    import ctypes
    import errno
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    if rename is None:
        raise CaseError('atomic no-replace rename is unavailable')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise CaseError('import destination already exists')
        raise CaseError('atomic no-replace rename failed: ' + os.strerror(error))

def read_confined(root: Path, relative: str, max_bytes: int) -> bytes:
    if not isinstance(relative, str) or not relative or '\\' in relative:
        raise CaseError('invalid relative path')
    p = PurePosixPath(relative)
    if p.is_absolute() or p.as_posix() != relative or any(part in ('.', '..') for part in relative.split('/')):
        raise CaseError('unsafe relative path')
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise CaseError('unsafe source directory')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fds = []
    try:
        if not hasattr(os, 'O_NOFOLLOW'):
            raise CaseError('safe no-symlink reads are unavailable')
        absolute = Path(os.path.abspath(root))
        fd = os.open(str(absolute.anchor), flags | getattr(os, 'O_DIRECTORY', 0))
        fds.append(fd)
        for part in absolute.parts[1:]:
            fd = os.open(part, flags | getattr(os, 'O_DIRECTORY', 0), dir_fd=fd)
            fds.append(fd)
        for part in p.parts[:-1]:
            fd = os.open(part, flags | getattr(os, 'O_DIRECTORY', 0), dir_fd=fd)
            fds.append(fd)
        fd = os.open(p.parts[-1], flags, dir_fd=fd)
        fds.append(fd)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise CaseError('source is not a bounded regular file')
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b''.join(chunks)
        after = os.fstat(fd)
        if len(data) > max_bytes or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(data) != before.st_size:
            raise CaseError('source changed or exceeded limit')
        return data
    except OSError as exc:
        raise CaseError('cannot safely read source: ' + str(exc)) from exc
    finally:
        for fd in reversed(fds):
            os.close(fd)

def strict_json(data):
    try:
        return json.loads(data, parse_constant=lambda value: (_ for _ in ()).throw(CaseError('non-finite JSON number')))
    except (UnicodeError, ValueError) as exc:
        raise CaseError('invalid JSON') from exc

def validate_run(data):
    run_id = token(data.get('run_id'), 'run_id')
    root = Path(nonempty(data.get('run_dir'), 'run_dir'))
    expected = data.get('expected_summary_hashes')
    if not isinstance(expected, dict) or set(expected) != set(SUMMARIES):
        raise CaseError('four expected summary hashes are required')
    snapshots = {name: read_confined(root, name, LIMIT) for name in SUMMARIES}
    if sum(map(len, snapshots.values())) > 32 * 1024 * 1024:
        raise CaseError('summary limit exceeded')
    if any(expected[name] != sha(content) for name, content in snapshots.items()):
        raise CaseError('summary hash mismatch')
    manifest = strict_json(snapshots['manifest.json'])
    diagnosis = strict_json(snapshots['diagnosis.json'])
    try:
        records = [strict_json(line) for line in snapshots['evidence.jsonl'].splitlines() if line.strip()]
    except (TypeError, ValueError) as exc:
        raise CaseError('invalid evidence stream') from exc
    if not isinstance(manifest, dict) or manifest.get('run_id') != run_id or not isinstance(diagnosis, dict):
        raise CaseError('invalid manifest or diagnosis')
    errors = manifest.get('validation_errors')
    if not isinstance(errors, dict) or any(value != [] for value in errors.values()) or set(errors) != {'evidence', 'diagnosis'}:
        raise CaseError('collector validation errors')
    window = manifest.get('run_window')
    if not isinstance(window, dict) or timestamp(window.get('started_at_utc')) > timestamp(window.get('ended_at_utc')):
        raise CaseError('invalid run window')
    artifact_hashes = manifest.get('artifact_hashes')
    if not isinstance(artifact_hashes, dict):
        raise CaseError('missing artifact hashes')
    for name in SUMMARIES[1:]:
        if artifact_hashes.get(name) != sha(snapshots[name]):
            raise CaseError('manifest summary hash mismatch')
    ids = set()
    for record in records:
        if not isinstance(record, dict):
            raise CaseError('invalid evidence record')
        eid = token(record.get('id'), 'evidence id')
        if eid in ids:
            raise CaseError('duplicate evidence id')
        ids.add(eid)
        timestamp(record.get('started_at_utc'))
        sources = record.get('sources', [])
        if not isinstance(sources, list):
            raise CaseError('invalid evidence sources')
        for source in sources:
            if not isinstance(source, dict):
                raise CaseError('invalid source')
            if source.get('kind') == 'run_artifact':
                name = source.get('path')
                content = read_confined(root, name, LIMIT)
                if sha(content) != source.get('sha256') or artifact_hashes.get(name) != sha(content):
                    raise CaseError('source hash mismatch')
    def check_refs(value, key=None):
        if isinstance(value, dict):
            for k, v in value.items():
                check_refs(v, k)
        elif key in ('evidence_ids', 'counterevidence_ids'):
            if not isinstance(value, list) or any(not isinstance(item, str) or item not in ids for item in value):
                raise CaseError('unknown diagnosis evidence')
        elif key == 'evidence_id' and (not isinstance(value, str) or value not in ids):
            raise CaseError('unknown diagnosis evidence')
        elif isinstance(value, list):
            for item in value:
                check_refs(item)
    check_refs(diagnosis)
    if diagnosis.get('status') not in ('fault_observed', 'healthy_within_scope', 'not_reproduced', 'insufficient_evidence'):
        raise CaseError('invalid diagnosis status')
    return snapshots, manifest, diagnosis, sorted(ids)

def import_run(case_dir, data, allow_terminal=False):
    created = []
    def change(state, conn):
        if state['status'] in TERMINAL and not allow_terminal:
            raise CaseError('case is terminal')
        snapshots, manifest, diagnosis, ids = validate_run(data)
        run_id = data['run_id']
        if any(item['run_id'] == run_id for item in state['imports']):
            raise CaseError('run ID already imported')
        imports = Path(case_dir) / 'imports'
        stage = Path(tempfile.mkdtemp(prefix='.stage-', dir=imports))
        try:
            for name, content in snapshots.items():
                fd = os.open(str(stage / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
            destination = imports / run_id
            if destination.exists() or destination.is_symlink():
                raise CaseError('import destination already exists')
            rename_noreplace(stage, destination)
            created.append(destination)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
        item = {'run_id': run_id, 'summary_hashes': {k: sha(v) for k, v in snapshots.items()}, 'evidence_ids': ids, 'diagnosis': diagnosis, 'scope': manifest.get('scope'), 'run_window': manifest['run_window'], 'collection_time': manifest.get('completed_at_utc'), 'omissions': manifest.get('failures', []), 'redaction': manifest.get('privacy'), 'access_class': 'restricted', 'source': str(data['run_dir'])}
        state['imports'].append(item)
        return {'run_id': run_id, 'summary_hashes': item['summary_hashes']}
    try:
        return transact(case_dir, data, 'import-run', change)
    except Exception:
        for path in created:
            shutil.rmtree(path)
        raise

def validate_refs(state, refs):
    if not isinstance(refs, list):
        raise CaseError('evidence references must be a list')
    known = {(item['run_id'], eid) for item in state['imports'] for eid in item['evidence_ids']}
    for ref in refs:
        if not isinstance(ref, dict) or set(ref) != {'run_id', 'evidence_id'} or (ref['run_id'], ref['evidence_id']) not in known:
            raise CaseError('unknown or unqualified evidence reference')

def record_decision(case_dir, data):
    def change(state, conn):
        if state['status'] in TERMINAL:
            raise CaseError('case is terminal')
        keys = ('observations', 'hypotheses', 'support', 'counterevidence', 'confidence', 'limitations', 'next_test', 'expected_support', 'expected_counterevidence', 'changed_condition')
        if not all(key in data for key in keys) or not isinstance(data['hypotheses'], list) or len(data['hypotheses']) > 2 or not isinstance(data['observations'], list):
            raise CaseError('invalid decision')
        validate_refs(state, data['support'])
        validate_refs(state, data['counterevidence'])
        if data['next_test']:
            nonempty(data['next_test'], 'next test')
            if not data['expected_support'] or not data['expected_counterevidence']:
                raise CaseError('next test requires predicted support and counterevidence')
            if any(d['next_test'] == data['next_test'] for d in state['decisions']) and not data['changed_condition']:
                raise CaseError('repeated test requires changed condition')
        decision = {key: data[key] for key in keys}
        authorization = data.get('authorized_collection')
        if authorization is not None:
            if not isinstance(authorization, dict) or set(authorization) != {'target', 'vantage', 'authorization_ref'}:
                raise CaseError('invalid collection authorization')
            for key, value in authorization.items():
                nonempty(value, key)
            if authorization['target'] != state['scope']['target'] or authorization['vantage'] != state['scope']['vantage']:
                raise CaseError('collection authorization does not match scope')
        decision['authorized_collection'] = authorization
        decision['event_id'] = data['event_id']
        decision['scope'] = dict(state['scope'])
        decision['stop_reason'] = None if data['next_test'] and state['budget']['rounds'] > 0 else 'no permissible next test or budget'
        state['decisions'].append(decision)
        return {'decision': decision}
    return transact(case_dir, data, 'decision', change)
