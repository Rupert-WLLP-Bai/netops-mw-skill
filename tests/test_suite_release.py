from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
NAMES = ('internet-access-triage', 'netops-incident', 'netops-pcap-analysis', 'netops-verify-recovery', 'netops-handoff')
LEGACY = ('LICENSE', 'SKILL.md', 'config/defaults.json', 'references/collection-limits.md', 'references/evidence-contract.md', 'schemas/diagnosis.schema.json', 'schemas/evidence.schema.json', 'scripts/diagnose.py', 'scripts/netops/__init__.py', 'scripts/netops/contract.py', 'scripts/netops/diagnosis.py', 'scripts/netops/live.py', 'scripts/netops/pcap.py', 'scripts/netops/report.py', 'scripts/netops/runner.py', 'scripts/netops/urls.py')
INCIDENT = ('LICENSE', 'SKILL.md', 'references/case-contract.md', 'references/carrier-evidence-contract.md', 'references/offline-ingestion.md', 'schemas/service-context.schema.json', 'schemas/carrier-evidence.schema.json', 'scripts/case.py', 'scripts/ingest.py', 'scripts/case_runtime/__init__.py', 'scripts/case_runtime/store.py', 'scripts/case_runtime/evidence.py', 'scripts/case_runtime/collection.py', 'scripts/case_runtime/recovery.py', 'scripts/case_runtime/carrier.py', 'scripts/case_runtime/ingest.py')
EXPECTED = {f'internet-access-triage/{name}' for name in LEGACY} | {f'netops-incident/{name}' for name in INCIDENT} | {'suite-inventory.json'}
for name, ref in (('netops-pcap-analysis','offline-analysis'), ('netops-verify-recovery','verification'), ('netops-handoff','handoff')):
    EXPECTED |= {f'{name}/LICENSE', f'{name}/SKILL.md', f'{name}/references/{ref}.md'}

class SuiteReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        spec = importlib.util.spec_from_file_location('suite_builder', REPO/'scripts/build_suite.py')
        self.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.builder)
        self.source = self.root/'source'
        (self.source/'skills').mkdir(parents=True)
        for name in NAMES:
            shutil.copytree(REPO/'skills'/name, self.source/'skills'/name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copyfile(REPO/'skills/suite-inventory.json', self.source/'skills/suite-inventory.json')

    def test_suite_exact_allowlist_and_reproducibility(self):
        first = self.root/'first'/'suite.zip'
        second = self.root/'second'/'suite.zip'
        a = self.builder.build_suite(self.source, first)
        b = self.builder.build_suite(self.source, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(a['archive']['sha256'], hashlib.sha256(first.read_bytes()).hexdigest())
        self.assertEqual(a['archive'], b['archive'])
        self.assertEqual(a['file_count'], 42)
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(set(archive.namelist()), EXPECTED)
            self.assertEqual(len(archive.namelist()), len(EXPECTED))
            self.assertTrue(all(info.date_time == (1980,1,1,0,0,0) for info in archive.infolist()))
            for info in archive.infolist():
                self.assertNotIn('..', Path(info.filename).parts)
                self.assertNotIn('__pycache__', info.filename)
                self.assertNotIn('pcap', Path(info.filename).suffix)
        self.assertEqual(json.loads(first.with_suffix('.manifest.json').read_text()), a)

    def test_reject_extra_missing_symlink_and_overwrite(self):
        out = self.root/'suite.zip'
        extra = self.source/'skills/netops-handoff/unexpected.txt'
        extra.write_text('unexpected')
        with self.assertRaises(self.builder.ReleaseError): self.builder.build_suite(self.source, out)
        extra.unlink()
        required = self.source/'skills/netops-handoff/references/handoff.md'
        data = required.read_bytes(); required.unlink()
        with self.assertRaises(self.builder.ReleaseError): self.builder.build_suite(self.source, out)
        required.write_bytes(data)
        link = self.source/'skills/netops-handoff/link'
        try: link.symlink_to(required)
        except (NotImplementedError, OSError) as exc: self.skipTest(str(exc))
        with self.assertRaises(self.builder.ReleaseError): self.builder.build_suite(self.source, out)
        link.unlink()
        out.write_bytes(b'existing')
        with self.assertRaises(self.builder.ReleaseError): self.builder.build_suite(self.source, out)
        self.assertEqual(out.read_bytes(), b'existing')
        self.assertFalse(out.with_suffix('.manifest.json').exists())
        out.unlink(); out.with_suffix('.manifest.json').write_bytes(b'existing manifest')
        with self.assertRaises(self.builder.ReleaseError): self.builder.build_suite(self.source, out)
        self.assertFalse(out.exists())
        self.assertEqual(out.with_suffix('.manifest.json').read_bytes(), b'existing manifest')

    def test_unexpected_skill_root_and_invalid_inventory_are_rejected(self):
        extra = self.source/'skills/unexpected'
        extra.mkdir()
        with self.assertRaises(self.builder.ReleaseError):
            self.builder.build_suite(self.source, self.root/'bad.zip')
        extra.rmdir()
        inventory = self.source/'skills/suite-inventory.json'
        data = json.loads(inventory.read_text())
        data['provider']['compatible_version'] = '9.x'
        inventory.write_text(json.dumps(data))
        with self.assertRaises(self.builder.ReleaseError):
            self.builder.build_suite(self.source, self.root/'bad.zip')
        data['skills'][0]['version'] = []
        inventory.write_text(json.dumps(data))
        with self.assertRaises(self.builder.ReleaseError):
            self.builder.build_suite(self.source, self.root/'bad.zip')

    def test_python_caches_are_not_packaged(self):
        cache = self.source/'skills/netops-incident/scripts/case_runtime/__pycache__'
        cache.mkdir()
        (cache/'store.pyc').write_bytes(b'cache')
        out = self.root/'suite.zip'
        self.builder.build_suite(self.source, out)
        with zipfile.ZipFile(out) as archive:
            self.assertEqual(set(archive.namelist()), EXPECTED)

    def test_clean_extract_entrypoints_and_missing_provider(self):
        archive = self.root/'suite.zip'
        self.builder.build_suite(self.source, archive)
        extract = self.root/'extract'
        with zipfile.ZipFile(archive) as z: z.extractall(extract)
        collector = extract/'internet-access-triage/scripts/diagnose.py'
        case_cli = extract/'netops-incident/scripts/case.py'
        env = dict(os.environ, PYTHONPATH='')
        def execute(args):
            return subprocess.run([sys.executable, '-B', *map(str,args)], cwd=self.root, env=env, text=True, capture_output=True)
        for args in ([collector,'--help'], [collector,'--version'], [case_cli,'--help']):
            result=execute(args); self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('internet-access-triage 0.1.', execute([collector,'--version']).stdout)
        scope = dict.fromkeys(('vantage','identity','operation','target','protocol','address_family','proxy','workload','original_window'))
        scope['vantage']='branch'
        plan = dict.fromkeys(('criterion','unit','window_seconds','cadence_seconds','maximum_gap_seconds','freshness_seconds','minimum_checks','minimum_coverage','owner','agreement_ref'))
        case=self.root/'case'; data=self.root/'input.json'
        def call(command, payload=None):
            args=[case_cli,command,'--case',case]
            if payload is not None: data.write_text(json.dumps(payload)); args += ['--input',data]
            return execute(args)
        create=dict(case_id='case1',actor='operator',event_id='create1',occurred_at='2026-01-01T00:00:00Z',symptom='symptom',business_impact='impact',scope=scope,verification_plan=plan)
        self.assertEqual(call('create',create).returncode,0)
        before=json.loads(call('get').stdout)
        run=dict(event_id='run1',actor='operator',occurred_at='2026-01-01T00:00:00Z',expected_revision=1,purpose='investigation',provider_cli=str(self.root/'missing/diagnose.py'),mode='offline_pcap',pcap=str(self.root/'capture'),out=str(self.root/'output'),authorization_ref='approved',decision_event_id='missing',actual_vantage='branch',vantage_source='operator')
        result=call('run',run)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('provider',result.stderr)
        self.assertEqual(json.loads(call('get').stdout), before)

if __name__ == '__main__': unittest.main()
