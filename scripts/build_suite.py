#!/usr/bin/env python3
"""Build a deterministic, self-contained network skill suite archive."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from io import BytesIO
from pathlib import Path, PurePosixPath

SKILL_FILES = {
    'internet-access-triage': (
        'LICENSE', 'SKILL.md', 'config/defaults.json', 'references/collection-limits.md',
        'references/evidence-contract.md', 'schemas/diagnosis.schema.json',
        'schemas/evidence.schema.json', 'scripts/diagnose.py', 'scripts/netops/__init__.py',
        'scripts/netops/contract.py', 'scripts/netops/diagnosis.py', 'scripts/netops/live.py',
        'scripts/netops/pcap.py', 'scripts/netops/report.py', 'scripts/netops/runner.py',
        'scripts/netops/urls.py',
    ),
    'netops-incident': (
        'LICENSE', 'SKILL.md', 'references/case-contract.md', 'scripts/case.py',
        'scripts/case_runtime/__init__.py', 'scripts/case_runtime/store.py',
        'scripts/case_runtime/evidence.py', 'scripts/case_runtime/collection.py',
        'scripts/case_runtime/recovery.py',
    ),
    'netops-pcap-analysis': ('LICENSE', 'SKILL.md', 'references/offline-analysis.md'),
    'netops-verify-recovery': ('LICENSE', 'SKILL.md', 'references/verification.md'),
    'netops-handoff': ('LICENSE', 'SKILL.md', 'references/handoff.md'),
}
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

class ReleaseError(Exception):
    """The release source or destination violates the package contract."""

def read_skill(root: Path, name: str, allowed: tuple[str, ...]) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        raise ReleaseError('skill root must be a real directory: ' + str(root))
    files = set(allowed)
    directories = {str(parent) for path in allowed for parent in PurePosixPath(path).parents if str(parent) != '.'}
    found = set()
    def visit(directory: Path, prefix: str):
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                relative = prefix + '/' + entry.name if prefix else entry.name
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISLNK(mode):
                    raise ReleaseError('symlink in source: ' + relative)
                if stat.S_ISDIR(mode):
                    if entry.name == '__pycache__':
                        continue
                    if relative not in directories:
                        raise ReleaseError('unexpected directory: ' + relative)
                    visit(Path(entry.path), relative)
                elif stat.S_ISREG(mode):
                    if entry.name.endswith('.pyc'):
                        continue
                    if relative not in files:
                        raise ReleaseError('unexpected file: ' + relative)
                    found.add(relative)
                else:
                    raise ReleaseError('nonregular source entry: ' + relative)
    visit(root, '')
    if found != files:
        raise ReleaseError('missing required files: ' + ', '.join(sorted(files - found)))
    result = {}
    for relative in sorted(allowed):
        path = PurePosixPath(relative)
        if path.is_absolute() or path.as_posix() != relative or '..' in path.parts or '\\' in relative:
            raise ReleaseError('unsafe allowlist path')
        file = root.joinpath(*path.parts)
        if file.is_symlink() or not file.is_file():
            raise ReleaseError('invalid source file: ' + relative)
        content = file.read_bytes()
        try:
            content.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ReleaseError('source file is not UTF-8: ' + relative) from exc
        if any(byte == 0 or (byte < 32 and byte not in (9, 10, 13)) for byte in content):
            raise ReleaseError('binary source file: ' + relative)
        result[name + '/' + relative] = content
    skill = result[name + '/SKILL.md'].decode('utf-8')
    parts = skill.split('---\n', 2)
    if not skill.startswith('---\n') or len(parts) != 3 or not re.search(r'(?m)^name:\s*' + re.escape(name) + r'\s*$', parts[1]) or not re.search(r'(?m)^  version:\s*0\.1\.0\s*$', parts[1]):
        raise ReleaseError('invalid skill name or version: ' + name)
    return result

def read_inventory(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ReleaseError('inventory must be a regular file')
    content = path.read_bytes()
    try:
        inventory = json.loads(content)
    except (ValueError, UnicodeError) as exc:
        raise ReleaseError('invalid inventory') from exc
    expected = {(name, '0.1.0') for name in SKILL_FILES}
    skills = inventory.get('skills') if isinstance(inventory, dict) else None
    if not isinstance(skills, list) or len(skills) != len(expected) or not all(isinstance(item, dict) and set(item) == {'name', 'version'} and isinstance(item['name'], str) and isinstance(item['version'], str) for item in skills):
        raise ReleaseError('invalid inventory skills')
    if {(item['name'], item['version']) for item in skills} != expected or inventory.get('suite') != 'network-skill-suite' or inventory.get('version') != '0.1.0' or inventory.get('schema_version') != 1 or inventory.get('license') != 'Apache-2.0':
        raise ReleaseError('inventory versions or license mismatch')
    provider = inventory.get('provider')
    controller = inventory.get('controller')
    if not isinstance(provider, dict) or provider.get('name') != 'internet-access-triage' or provider.get('compatible_version') != '0.1.x' or provider.get('cli') != 'scripts/diagnose.py' or provider.get('interfaces') != ['--version', '--url', '--pcap']:
        raise ReleaseError('invalid provider interface')
    if controller != {'name': 'netops-incident', 'cli': 'scripts/case.py', 'schema_version': 1}:
        raise ReleaseError('invalid controller interface')
    return content

def archive_bytes(files: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, 'w', allowZip64=False) as archive:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.extra = b''
            info.comment = b''
            archive.writestr(info, content)
    return buffer.getvalue()

def write_exclusive(path: Path, content: bytes):
    created = False
    try:
        with path.open('xb') as stream:
            created = True
            stream.write(content)
    except OSError:
        if created:
            path.unlink(missing_ok=True)
        raise

def build_suite(source_root: Path, output_zip: Path, manifest_path: Path | None = None) -> dict:
    """Build from a repository root; refuse to overwrite the archive or sidecar."""
    source, output = Path(source_root), Path(output_zip)
    manifest = Path(manifest_path) if manifest_path is not None else output.with_suffix('.manifest.json')
    if source.is_symlink() or not source.is_dir() or (source/'skills').is_symlink() or not (source/'skills').is_dir():
        raise ReleaseError('source must contain a real skills directory')
    if output.suffix.lower() != '.zip' or output.resolve() == manifest.resolve():
        raise ReleaseError('output must be a ZIP distinct from its manifest')
    skills_root = (source/'skills').resolve()
    with os.scandir(skills_root) as entries:
        for entry in entries:
            if entry.name not in set(SKILL_FILES) | {'suite-inventory.json'}:
                raise ReleaseError('unexpected skills source entry: ' + entry.name)
    if output.resolve().is_relative_to(skills_root) or manifest.resolve().is_relative_to(skills_root):
        raise ReleaseError('outputs must be outside skill sources')
    files = {}
    for name, allowed in SKILL_FILES.items():
        files.update(read_skill(source/'skills'/name, name, allowed))
    files['suite-inventory.json'] = read_inventory(source/'skills/suite-inventory.json')
    content = archive_bytes(files)
    result = {'package': 'network-skill-suite', 'version': '0.1.0', 'archive': {'file': output.name, 'sha256': hashlib.sha256(content).hexdigest(), 'size_bytes': len(content)}, 'file_count': len(files), 'files': [{'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)} for name, data in sorted(files.items())]}
    sidecar = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode('utf-8')
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        write_exclusive(output, content)
        created.append(output)
        write_exclusive(manifest, sidecar)
        created.append(manifest)
    except OSError as exc:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise ReleaseError('cannot create release output without overwrite: ' + str(exc)) from exc
    return result

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parent.parent, help='repository source root')
    parser.add_argument('--out', required=True, type=Path, help='new ZIP path')
    parser.add_argument('--manifest', type=Path, help='new manifest path')
    args = parser.parse_args(argv)
    try:
        result = build_suite(args.source, args.out, args.manifest)
    except (ReleaseError, OSError) as exc:
        print('suite build failed: ' + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0

if __name__ == '__main__':
    sys.exit(main())
