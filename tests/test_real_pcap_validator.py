from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_real_pcap.py"


class CorpusValidatorSafetyTests(unittest.TestCase):
    def test_refuses_wrong_input_hash_before_creating_run_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / "downloads").mkdir()
            (base / "downloads" / "capture.pcap").write_bytes(b"test input")
            manifest = base / "manifest.json"
            manifest.write_text(json.dumps({"files": [{"name": "sample", "variant": "original",
                "path": ".tools/pcap-corpus/downloads/capture.pcap", "sha256": "0" * 64}]}))
            out = base / "out"
            result = subprocess.run([sys.executable, str(VALIDATOR), "--manifest", str(manifest),
                                     "--corpus", str(base), "--out", str(out)],
                                    capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("hash mismatch", result.stderr)
            self.assertFalse(out.exists())

    def test_refuses_existing_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "existing"
            out.mkdir()
            marker = out / "marker"
            marker.write_text("preserve")
            result = subprocess.run([sys.executable, str(VALIDATOR), "--out", str(out)],
                                    capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("already exists", result.stderr)
            self.assertEqual(marker.read_text(), "preserve")

if __name__ == "__main__":
    unittest.main()
