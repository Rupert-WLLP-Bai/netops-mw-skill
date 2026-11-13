"""Prepared client inputs contain only portable, checked M2 evidence bundles."""
from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.prepare_validation_inputs import MATERIALIZER, prepare_inputs

ROOT = Path(__file__).resolve().parents[1]


class ValidationInputPreparationTests(unittest.TestCase):
    def test_prepared_examples_are_portable_and_keep_decisions_pending(self):
        with tempfile.TemporaryDirectory(prefix="validation-inputs-test-") as temp:
            output = Path(temp) / "validation-inputs"
            result = prepare_inputs(ROOT, output)
            self.assertEqual(result["normal"]["request_template"], "normal/request.template.json")
            self.assertEqual(result["missing_reverse"]["request_template"], "missing-reverse/request.template.json")
            normal = json.loads((output / result["normal"]["request_template"]).read_text())
            changed = json.loads((output / result["missing_reverse"]["request_template"]).read_text())
            self.assertNotIn("case_id", normal)
            self.assertNotIn("case_id", changed)
            self.assertEqual(result["normal"]["expected_behavior"]["human_decision"], "pending_user")
            self.assertEqual(result["missing_reverse"]["expected_behavior"]["direction_status"]["B_to_A"], "unverified")
            for template in (normal, changed):
                encoded = json.dumps(template, ensure_ascii=False).encode()
                self.assertLessEqual(len(encoded), 1_048_576)
                for run in template["runs"]:
                    run_path = Path(run["run_dir"])
                    self.assertFalse(run_path.is_absolute())
                    self.assertNotIn("..", run_path.parts)
                    bundle = output / run_path
                    self.assertTrue((bundle / "carrier-visible.json").is_file())
                    self.assertTrue((bundle / "evidence.jsonl").is_file())
                    self.assertTrue(all(len(line) < 8192 for line in (bundle / "evidence.jsonl").read_bytes().splitlines()))
                    self.assertFalse(any(path.name in {"raw.bin", "pseudonyms.json", "config.json", "input.json"}
                                         for path in bundle.rglob("*")))
            malformed = output / result["malformed"]["input"]
            with self.assertRaises(json.JSONDecodeError):
                json.loads(malformed.read_text())
            self.assertFalse((output / "normal/request.json").exists())

    def test_materializer_confines_paths_bounds_inputs_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory(prefix="materializer-test-") as temp:
            root = Path(temp) / "examples"
            bundle = root / "normal" / "runs" / "run-a"
            bundle.mkdir(parents=True)
            files = {"evidence.jsonl": b"{}\n", "diagnosis.json": b"{}\n", "report.md": b"# sample\n",
                     "carrier-visible.json": b'{"parse_status":"complete"}\n'}
            for name, data in files.items():
                (bundle / name).write_bytes(data)
            summary_hashes = {}
            for name in ("evidence.jsonl", "diagnosis.json", "report.md"):
                summary_hashes[name] = hashlib.sha256(files[name]).hexdigest()
            manifest = {"artifact_hashes": {"carrier-visible.json": hashlib.sha256(files["carrier-visible.json"]).hexdigest()}}
            (bundle / "manifest.json").write_text(json.dumps(manifest))
            summary_hashes["manifest.json"] = hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest()
            request = {"runs": [{"run_id": "sample", "run_dir": "normal/runs/run-a",
                                 "expected_summary_hashes": summary_hashes}]}
            (root / "normal").mkdir(exist_ok=True)
            (root / "normal" / "request.template.json").write_text(json.dumps(request))
            materializer = root / "materialize_request.py"
            materializer.write_text(MATERIALIZER)
            work = Path(temp) / "user-work"
            work.mkdir()
            command = [sys.executable, str(materializer), "--root", str(root),
                       "--template", "normal/request.template.json"]
            good = work / "request.json"
            self.assertEqual(subprocess.run(command + ["--out", str(good)], capture_output=True).returncode, 0)
            self.assertTrue(Path(json.loads(good.read_text())["runs"][0]["run_dir"]).is_absolute())
            self.assertNotEqual(subprocess.run(command + ["--out", str(good)], capture_output=True).returncode, 0)
            traversal = subprocess.run(command[:5] + ["../outside.json"] + ["--out", str(work / "traversal.json")],
                                       capture_output=True)
            self.assertNotEqual(traversal.returncode, 0)
            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (1_048_577))
            self.assertNotEqual(subprocess.run(command[:5] + ["oversized.json", "--out", str(work / "large.json")],
                                               capture_output=True).returncode, 0)
            if os.name == "posix":
                (root / "normal" / "linked-runs").symlink_to(bundle.parent, target_is_directory=True)
                request["runs"][0]["run_dir"] = "normal/linked-runs/run-a"
                (root / "normal" / "linked.template.json").write_text(json.dumps(request))
                self.assertNotEqual(subprocess.run(command[:5] + ["normal/linked.template.json", "--out", str(work / "linked.json")],
                                                   capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
