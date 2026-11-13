"""Static catalog and eventual materialization contract tests for M6."""
from __future__ import annotations

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from evaluation.carrier.corpus import CorpusError, load_catalog, materialize_case


ROOT = Path(__file__).resolve().parents[1]


class CarrierCorpusTests(unittest.TestCase):
    def test_catalog_has_36_unique_cases_in_exclusive_groups(self):
        catalog = load_catalog(ROOT)
        self.assertEqual(len(catalog["cases"]), 36)
        self.assertEqual(len({case["case_id"] for case in catalog["cases"]}), 36)
        self.assertEqual(Counter(case["primary_group"] for case in catalog["cases"]), {
            "true_fault": 6,
            "healthy_misleading": 6,
            "unreliable_ticket": 4,
            "insufficient_evidence": 4,
            "service_acceptance": 8,
            "multi_layer_compound": 8,
        })
        self.assertTrue(all("oracle" not in case and "expected_state" not in case for case in catalog["cases"]))

    def test_compound_catalog_entries_keep_jobs_independent(self):
        catalog = load_catalog(ROOT)
        compound = [case for case in catalog["cases"] if case["primary_group"] == "multi_layer_compound"]
        self.assertEqual(len(compound), 8)
        for case in compound:
            self.assertGreaterEqual(len(case["jobs"]), 2)
            self.assertEqual(case.get("required_bindings", []), [])
            self.assertIn("do not permit", case["prompt"])

    def test_materialization_keeps_oracle_and_authoring_paths_out_of_visible_task(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = materialize_case(ROOT, "case-001", Path(temporary))
            task = json.loads(result["task_path"].read_text(encoding="utf-8"))
            visible = result["visible_root"]
            serialized = json.dumps(task)
            self.assertEqual(task["schema_version"], 1)
            self.assertTrue(task["task_id"].startswith("task-"))
            self.assertNotIn("case-001", str(result["visible_root"]))
            self.assertNotIn("case-001", serialized)
            self.assertNotIn("true_fault", serialized)
            self.assertNotIn("oracle", serialized)
            self.assertEqual(result["oracle"]["task_id"], task["task_id"])
            self.assertTrue(all(Path(job["request"]["runs"][0]["run_dir"]).is_relative_to(visible)
                                for job in task["jobs"]))
            self.assertTrue(result["visible_refs_by_job"]["job-01"])
            self.assertFalse(any("private" in path.parts or "config" in path.name
                                 for path in visible.rglob("*")))

    def test_unknown_case_is_rejected_before_materialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(CorpusError):
                materialize_case(ROOT, "case-999", Path(temporary))


if __name__ == "__main__":
    unittest.main()
