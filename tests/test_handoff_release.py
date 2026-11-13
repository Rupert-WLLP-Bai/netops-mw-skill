from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def load_builder():
    spec = importlib.util.spec_from_file_location('handoff_release_builder', REPO / 'scripts' / 'build_handoff.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HandoffReleaseTests(unittest.TestCase):
    def test_handoff_emits_nine_packages_and_non_self_referential_checksums(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'handoff'
            builder = load_builder()
            result = builder.build_handoff(REPO, output)
            self.assertEqual(result['packages'], 9)
            self.assertEqual(len(list((output / 'packages').glob('*.zip'))), 9)
            checksums = json.loads((output / 'SHA256SUMS.json').read_text())['files']
            self.assertNotIn('SHA256SUMS.json', checksums)
            for relative, digest in checksums.items():
                self.assertEqual(hashlib.sha256((output / relative).read_bytes()).hexdigest(), digest)
            ledger = json.loads((output / 'validation-ledger.json').read_text())
            self.assertEqual(ledger['actual_results'], 'pending_user')
            self.assertTrue(all(row['actual_result'] == 'pending_user' for row in ledger['skills']))
            self.assertTrue((output / 'guide' / 'per-skill-validation-ledger.md').is_file())
            self.assertTrue((output / 'validation-inputs.json').is_file())
            with self.assertRaises(FileExistsError):
                builder.build_handoff(REPO, output)


if __name__ == '__main__':
    unittest.main()
