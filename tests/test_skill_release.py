from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
NAMES = ('internet-access-triage', 'netops-incident', 'netops-pcap-analysis', 'netops-verify-recovery', 'netops-handoff', 'telecom-access-diagnostics', 'telecom-transport-diagnostics', 'telecom-service-acceptance')


def load_builder():
    spec = importlib.util.spec_from_file_location('skill_release_builder', REPO / 'scripts' / 'build_skill.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SkillReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        (self.source / 'skills').mkdir(parents=True)
        self.builder = load_builder()
        self.error = self.builder._load_suite_builder().ReleaseError

    def test_all_skill_archives_have_exact_members_versions_and_reproducibility(self):
        for name in NAMES:
            with self.subTest(skill=name):
                shutil.copytree(REPO / 'skills' / name, self.source / 'skills' / name)
                a = self.root / f'{name}-a.zip'
                first = self.builder.build_skill(self.source, name, a)
                expected_version = '0.2.0' if name == 'netops-incident' else '0.1.0'
                self.assertEqual(first['version'], expected_version)
                self.assertEqual(first['archive']['sha256'], hashlib.sha256(a.read_bytes()).hexdigest())
                if name == 'internet-access-triage':
                    self.assertEqual(first['archive']['sha256'], 'f42abc06ffb1d020f037b6984eccce25cb80378aa0823a998d415bc445964a5a')
                with zipfile.ZipFile(a) as archive:
                    self.assertEqual(set(archive.namelist()), {f"{name}/{p['path'].split('/', 1)[1]}" for p in first['files']})
                    self.assertTrue(all(i.date_time == (1980, 1, 1, 0, 0, 0) for i in archive.infolist()))
                    extracted = self.root / 'extracted' / name
                    archive.extractall(extracted)
                    for member in first['files']:
                        relative = member['path'].split('/', 1)[1]
                        self.assertEqual((extracted / name / relative).read_bytes(), (self.source / 'skills' / name / relative).read_bytes())
                self.assertEqual(json.loads(a.with_suffix('.manifest.json').read_text()), first)
                second_path = self.root / f'{name}-b.zip'
                second = self.builder.build_skill(self.source, name, second_path)
                self.assertEqual(a.read_bytes(), second_path.read_bytes())
                self.assertEqual(json.loads(second_path.with_suffix('.manifest.json').read_text()), second)

    def test_unknown_skill_and_overwrite_are_rejected(self):
        with self.assertRaises(self.error):
            self.builder.build_skill(self.source, 'unknown', self.root / 'bad.zip')
        shutil.copytree(REPO / 'skills' / 'netops-pcap-analysis', self.source / 'skills' / 'netops-pcap-analysis')
        out = self.root / 'exists.zip'
        out.write_bytes(b'preserve')
        with self.assertRaises(self.error):
            self.builder.build_skill(self.source, 'netops-pcap-analysis', out)
        self.assertEqual(out.read_bytes(), b'preserve')


if __name__ == '__main__':
    unittest.main()
