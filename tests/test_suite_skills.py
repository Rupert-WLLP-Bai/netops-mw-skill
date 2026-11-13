from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / 'skills'
NAMES = ('internet-access-triage', 'netops-incident', 'netops-pcap-analysis', 'netops-verify-recovery', 'netops-handoff', 'telecom-access-diagnostics', 'telecom-transport-diagnostics')

class SuiteSkillTests(unittest.TestCase):
    def test_skill_inventory_frontmatter(self):
        for name in NAMES:
            with self.subTest(name=name):
                content = (ROOT / name / 'SKILL.md').read_text(encoding='utf-8')
                self.assertTrue(content.startswith('---\n'))
                front = content.split('---\n', 2)[1]
                self.assertRegex(front, rf'(?m)^name:\s*{re.escape(name)}\s*$')
                self.assertRegex(front, r'(?m)^description:\s*\S.+$')
                self.assertRegex(front, r'(?m)^  version:\s*0\.1\.0\s*$')

    def test_skill_references_resolve(self):
        for name in NAMES:
            with self.subTest(name=name):
                root = ROOT / name
                content = (root / 'SKILL.md').read_text(encoding='utf-8')
                for target in re.findall(r'\]\(([^)]+)\)', content):
                    if '://' in target or target.startswith('#'):
                        continue
                    path = (root / target.split('#')[0]).resolve()
                    self.assertTrue(path.is_relative_to(root.resolve()), target)
                    self.assertTrue(path.is_file(), target)

if __name__ == '__main__':
    unittest.main()
