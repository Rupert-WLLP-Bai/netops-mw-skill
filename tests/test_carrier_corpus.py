"""Static catalog and eventual materialization contract tests for M6."""
from __future__ import annotations

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from evaluation.carrier.corpus import (
    CorpusError,
    _remap,
    _seed_m5_protocol_ids,
    _serialize_source,
    load_catalog,
    materialize_case,
)
from evaluation.carrier.contract import validate_oracle


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
            validate_oracle(result["oracle"], task)
            self.assertTrue(all(Path(job["request"]["runs"][0]["run_dir"]).is_relative_to(visible)
                                for job in task["jobs"]))
            self.assertTrue(result["visible_refs_by_job"]["job-01"])
            self.assertFalse(any("private" in path.parts or "config" in path.name
                                 for path in visible.rglob("*")))

    def test_unknown_case_is_rejected_before_materialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(CorpusError):
                materialize_case(ROOT, "case-999", Path(temporary))

    def test_case_018_materializes_declared_source_whose_run_id_is_not_derived_from_run_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = materialize_case(ROOT, "case-018", Path(temporary))
            task = json.loads(result["task_path"].read_text(encoding="utf-8"))
            request = task["jobs"][0]["request"]
            run_ids = {run["run_id"] for run in request["runs"]}
            self.assertEqual(run_ids, {"r0101", "r0102"})
            self.assertTrue(any(binding["record"]["run_id"] == "r0102"
                                for binding in request["bindings"]))
            self.assertTrue(result["visible_refs_by_job"]["job-01"])
            validate_oracle(result["oracle"], task)

    def test_identifier_valued_device_model_stays_equal_across_allowlist_and_record(self):
        identifiers = {}
        config = {
            "value_allowlists": {"device_model": ["synthetic-model-m3"]},
            "pseudonyms": {"fixture-access-resource": "resource-m3"},
        }
        records = {"records": [{"metric": "device_model", "value": "synthetic-model-m3",
                                "object_id": "fixture-access-resource"}]}
        profile = {"device_model": "synthetic-model-m3", "profile_id": "resource-m3"}
        remapped_config = _remap(config, identifiers, {}, opaque_prefix="q01")
        remapped_records = _remap(records, identifiers, {}, opaque_prefix="q01")
        remapped_profile = _remap(profile, identifiers, {}, opaque_prefix="q01")
        configured_model = remapped_config["value_allowlists"]["device_model"][0]
        observed_model = remapped_records["records"][0]["value"]
        self.assertEqual(configured_model, observed_model)
        self.assertEqual(configured_model, remapped_profile["device_model"])
        self.assertNotEqual(configured_model, "synthetic-model-m3")

    def test_m5_protocol_identifiers_survive_opaque_source_remapping(self):
        request = {
            "fields": [{"field": "circuit", "target": "service"},
                       {"field": "vlan", "target": "endpoint_a"}],
            "criteria": [{"criterion_id": "criterion-throughput"}],
            "change_review": {"checks": [{"check_id": "precheck-throughput"}]},
        }
        identifiers = {}
        _seed_m5_protocol_ids(request, identifiers)
        source_config = {"pseudonyms": {
            "fixture-exp-circuit_service": "circuit_service",
            "fixture-criterion-throughput": "criterion-throughput",
        }}
        remapped_config = _remap(source_config, identifiers, {}, opaque_prefix="q01")
        self.assertEqual(identifiers["circuit_service"], "circuit_service")
        self.assertEqual(identifiers["vlan_endpoint_a"], "vlan_endpoint_a")
        self.assertEqual(identifiers["criterion-throughput"], "criterion-throughput")
        self.assertEqual(identifiers["precheck-throughput"], "precheck-throughput")
        self.assertEqual(set(remapped_config["pseudonyms"].values()),
                         {"circuit_service", "criterion-throughput"})
        self.assertTrue(all(key.startswith("q01") for key in remapped_config["pseudonyms"]))

    def test_m5_complete_matrix_uses_calibration_and_direction_source_facts(self):
        with tempfile.TemporaryDirectory() as temporary:
            calibration_gap = materialize_case(ROOT, "case-016", Path(temporary) / "calibration")
            calibration_claims = [claim for claim in calibration_gap["oracle"]["jobs"][0]["claims"]
                                  if claim["kind"] == "test_result"]
            self.assertEqual(len(calibration_claims), 10)
            self.assertTrue(all(claim["status"] == "unverified" for claim in calibration_claims))

            missing_reverse_map = materialize_case(ROOT, "case-006", Path(temporary) / "direction")
            request = json.loads(missing_reverse_map["task_path"].read_text(encoding="utf-8"))["jobs"][0]["request"]
            direction_claims = [claim for claim in missing_reverse_map["oracle"]["jobs"][0]["claims"]
                                if claim["kind"] == "test_result"]
            self.assertEqual(len(direction_claims), len(request["test_results"]))
            self.assertEqual({claim["status"] for claim in direction_claims
                              if claim["scope"]["absolute_direction"] == "A_to_B"}, {"pass"})
            self.assertEqual({claim["status"] for claim in direction_claims
                              if claim["scope"]["absolute_direction"] == "B_to_A"}, {"unverified"})

    def test_m5_acceptance_materialization_resolves_staged_rows_and_splits_telemetry_lines(self):
        source = json.loads((ROOT / "tests/fixtures/carrier-m5/sources/actual-tests/input.json").read_text(encoding="utf-8"))
        lines = _serialize_source(source).splitlines()
        self.assertTrue(all(len(line.encode("utf-8")) <= 8192 for line in lines))
        self.assertGreater(len(lines), len(source["records"]))
        with tempfile.TemporaryDirectory() as temporary:
            result = materialize_case(ROOT, "case-021", Path(temporary))
            task = json.loads(result["task_path"].read_text(encoding="utf-8"))
            request = task["jobs"][0]["request"]
            serialized = json.dumps(request)
            self.assertNotIn("$row", serialized)
            self.assertNotIn("$ID:", serialized)
            self.assertNotIn("$RUN_ID:", serialized)
            self.assertGreaterEqual(len(request["runs"]), 5)
            oracle_job = result["oracle"]["jobs"][0]
            field_claims = [claim for claim in oracle_job["claims"] if claim["kind"] == "field_result"]
            test_claims = [claim for claim in oracle_job["claims"] if claim["kind"] == "test_result"]
            self.assertEqual(len(field_claims), len(request["fields"]))
            self.assertEqual(len(test_claims), len(request["test_results"]))
            self.assertEqual(
                {(claim["scope"]["field"], claim["scope"]["target"]) for claim in field_claims},
                {(item["field"], item["target"]) for item in request["fields"]},
            )
            self.assertTrue(all(claim["support_sets"] for claim in field_claims))
            self.assertTrue(all(claim["support_sets"] for claim in test_claims))
            validate_oracle(result["oracle"], task)
            for run in request["runs"]:
                bundle = Path(run["run_dir"])
                self.assertTrue((bundle / "carrier-visible.json").is_file())
                self.assertTrue((bundle / "manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
