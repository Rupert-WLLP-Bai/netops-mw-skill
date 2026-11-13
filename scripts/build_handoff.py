#!/usr/bin/env python3
"""Assemble a deterministic, self-contained engineering handoff directory."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

GUIDE_FILES = (
    'README.md', 'client-cases.md', 'expert-routing-prompt.md',
    'per-skill-validation-ledger.md', 'security-criteria-ledger.md',
    'dependency-inventory.md', 'pcap-index.md',
)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError('cannot load ' + str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _json_bytes(value) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8')


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def build_handoff(repo_root: Path, output_dir: Path) -> dict:
    root, output = Path(repo_root).resolve(), Path(output_dir).absolute()
    if Path(repo_root).is_symlink() or not root.is_dir():
        raise ValueError('repository root must be a real directory')
    if output.exists() or output.is_symlink():
        raise FileExistsError('handoff destination already exists: ' + str(output))
    if output.resolve(strict=False).is_relative_to(root) or root.is_relative_to(output.resolve(strict=False)):
        raise ValueError('handoff destination must not overlap repository source')
    build_suite = _load('netops_build_suite', root / 'scripts' / 'build_suite.py')
    build_skill = _load('netops_build_skill', root / 'scripts' / 'build_skill.py')
    guides = root / 'docs' / 'release'
    for name in GUIDE_FILES:
        path = guides / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('missing or unsafe release guide: ' + name)
    if (root / 'scripts' / 'prepare_validation_inputs.py').is_symlink():
        raise ValueError('validation input helper must not be a symlink')
    prepare = _load('netops_prepare_validation_inputs', root / 'scripts' / 'prepare_validation_inputs.py')
    output.mkdir(parents=True)
    try:
        (output / 'packages').mkdir()
        (output / 'guide').mkdir()
        for name in GUIDE_FILES:
            shutil.copyfile(guides / name, output / 'guide' / name)
        manifests = []
        suite_path = output / 'packages' / ('network-skill-suite-' + build_suite.SUITE_VERSION + '.zip')
        manifests.append(build_suite.build_suite(root, suite_path))
        skill_module = build_skill
        for skill in sorted(build_suite.SKILL_FILES):
            version = build_suite.SKILL_VERSIONS[skill]
            archive = output / 'packages' / f'{skill}-{version}.zip'
            manifests.append(skill_module.build_skill(root, skill, archive))
        validation_root = output / 'validation-inputs'
        metadata = prepare.prepare_inputs(root, validation_root)
        if not isinstance(metadata, dict):
            raise ValueError('prepare_inputs must return a metadata object')
        ledger = []
        skills = [item for item in manifests if item['package'] != 'network-skill-suite']
        for package in skills:
            categories = ('V-01', 'V-02', 'V-03', 'normal', 'change', 'error', 'invocation')
            ledger.append({
                'skill': package['package'], 'version': package['version'],
                'archive': 'packages/' + package['archive']['file'],
                'sha256': package['archive']['sha256'], 'actual_result': 'pending_user',
                'checks': {name: {
                    'preconditions': 'pending_user', 'input': 'pending_user',
                    'process': 'pending_user', 'expected_output': 'pending_user',
                    'actual_result': 'pending_user', 'evidence_paths': [],
                } for name in categories},
                'environment': 'pending_user', 'client_version': 'pending_user', 'verifier': 'pending_user',
                'tool_versions': 'pending_user', 'validation_date': 'pending_user', 'evidence_paths': [],
            })
        (output / 'validation-ledger.json').write_bytes(_json_bytes({
            'status': 'engineering_preparation_only', 'actual_results': 'pending_user', 'skills': ledger,
        }))
        source_records = []
        for package in manifests:
            for item in package['files']:
                source_records.append({'package': package['package'], 'version': package['version'], **item})
        inventory = {
            'schema_version': 1,
            'suite': {'name': 'network-skill-suite', 'version': build_suite.SUITE_VERSION,
                      'license': 'Apache-2.0', 'archive': 'packages/' + suite_path.name,
                      'sha256': manifests[0]['archive']['sha256']},
            'packages': [{'name': p['package'], 'version': p['version'], 'archive': 'packages/' + p['archive']['file'],
                          'sha256': p['archive']['sha256'], 'file_count': p['file_count'],
                          'license': 'Apache-2.0'} for p in manifests],
            'source_members': sorted(source_records, key=lambda r: (r['package'], r['path'])),
            'dependencies': {
                'runtime': ['Python standard library; Python 3.10+'],
                'optional_external_tools': ['curl (HTTP collection)', 'dnslookup (optional DNS collection)',
                                            'native ping (optional reachability collection)', 'TShark (offline packet analysis)'],
                'development_only': ['jsonschema 4.26 (schema validation tests)', 'PyYAML 6.0.3 (optional Skill frontmatter validation)'],
                'license': 'Bundled Skill files include their LICENSE; external tools and development packages are not bundled.',
            },
            'license_inventory': [
                {'component': 'network-skill-suite and eight bundled Skills', 'license': 'Apache-2.0', 'bundled': True},
                {'component': 'Python standard library', 'license': 'Python Software Foundation License', 'bundled': False},
                {'component': 'curl, dnslookup, native ping, TShark', 'license': 'provided by selected host distribution', 'bundled': False},
                {'component': 'jsonschema 4.26 and PyYAML 6.0.3', 'license': 'development environment packages', 'bundled': False},
            ],
        }
        (output / 'source-and-dependency-inventory.json').write_bytes(_json_bytes(inventory))
        (output / 'validation-inputs.json').write_bytes(_json_bytes({
            'base_directory': 'validation-inputs', 'artifacts': metadata,
        }))
        # All generated paths are relative, and the checksum ledger deliberately excludes itself.
        checksums = {}
        for path in sorted(output.rglob('*')):
            if path.is_symlink():
                raise ValueError('symlink in handoff output: ' + str(path.relative_to(output)))
            if path.is_file():
                rel = path.relative_to(output).as_posix()
                checksums[rel] = _hash_file(path)
        (output / 'SHA256SUMS.json').write_bytes(_json_bytes({'algorithm': 'sha256', 'files': checksums}))
        return {'output': str(output), 'file_count': len(checksums) + 1, 'packages': len(manifests),
                'checksum_ledger': 'SHA256SUMS.json', 'validation_inputs': metadata}
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


def main(argv=None):
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=repo, help='repository root')
    parser.add_argument('--out', required=True, type=Path, help='new handoff directory')
    args = parser.parse_args(argv)
    try:
        result = build_handoff(args.source, args.out)
    except Exception as exc:
        print('handoff build failed: ' + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
