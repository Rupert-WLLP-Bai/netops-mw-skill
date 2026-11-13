#!/usr/bin/env python3
"""Build one deterministic, allowlisted Skill ZIP and its hash manifest."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path


def _load_suite_builder():
    path = Path(__file__).resolve().with_name('build_suite.py')
    spec = importlib.util.spec_from_file_location('netops_suite_builder', path)
    if spec is None or spec.loader is None:
        raise RuntimeError('cannot load suite builder')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_skill(source_root: Path, name: str, output_zip: Path, manifest_path: Path | None = None) -> dict:
    builder = _load_suite_builder()
    if name not in builder.SKILL_FILES:
        raise builder.ReleaseError('unknown skill: ' + name)
    source, output = Path(source_root), Path(output_zip)
    manifest = Path(manifest_path) if manifest_path is not None else output.with_suffix('.manifest.json')
    if source.is_symlink() or not source.is_dir() or output.suffix.lower() != '.zip' or output.resolve() == manifest.resolve():
        raise builder.ReleaseError('invalid source or output path')
    skills_root = source / 'skills'
    if skills_root.is_symlink() or not skills_root.is_dir():
        raise builder.ReleaseError('source must contain a real skills directory')
    skills_root = skills_root.resolve()
    if output.resolve().is_relative_to(skills_root) or manifest.resolve().is_relative_to(skills_root):
        raise builder.ReleaseError('outputs must be outside skill sources')
    files = builder.read_skill(source / 'skills' / name, name, builder.SKILL_FILES[name])
    content = builder.archive_bytes(files)
    version = builder.SKILL_VERSIONS[name]
    result = {
        'package': name,
        'version': version,
        'archive': {'file': output.name, 'sha256': hashlib.sha256(content).hexdigest(), 'size_bytes': len(content)},
        'file_count': len(files),
        'files': [{'path': path, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)} for path, data in sorted(files.items())],
    }
    sidecar = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode('utf-8')
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        builder.write_exclusive(output, content)
        created.append(output)
        builder.write_exclusive(manifest, sidecar)
        created.append(manifest)
    except OSError as exc:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise builder.ReleaseError('cannot create release output without overwrite: ' + str(exc)) from exc
    return result


def main(argv=None):
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=repo, help='repository root')
    parser.add_argument('--skill', required=True, help='exact Skill directory name')
    parser.add_argument('--out', required=True, type=Path, help='new ZIP path')
    parser.add_argument('--manifest', type=Path, help='new sidecar path')
    args = parser.parse_args(argv)
    try:
        result = build_skill(args.source, args.skill, args.out, args.manifest)
    except Exception as exc:
        print('skill build failed: ' + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
