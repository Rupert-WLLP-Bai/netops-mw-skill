"""Focused contract and scorer regressions for carrier M6."""

import unittest
import tempfile
from pathlib import Path

from evaluation.carrier.contract import ContractError, loads_bounded, normalize_result, validate_answer
from evaluation.carrier.experiments import STAGES, validate_experiment
from evaluation.carrier.scoring import score_answer
from scripts.evaluate_carrier import _prepare_output_dir


def ref(run_id, evidence_id):
    return {"run_id": run_id, "evidence_id": evidence_id}


def task(provider="access", request=None):
    return {"schema_version": 1, "task_id": "trial-001", "prompt": "Assess supplied evidence.",
            "jobs": [{"job_id": "job-001", "provider": provider,
                      "ticket": "Service reports a problem.", "request": request or {}}]}


def finding(code, support=(), layer="access", status=None, **extra):
    item = {"code": code, "support": list(support), "counterevidence": [], "layer": layer}
    if status is not None:
        item["status"] = status
    item.update(extra)
    return item


def answer_for(visible_task, raw, completion="complete"):
    provider = visible_task["jobs"][0]["provider"]
    return {"schema_version": 1, "task_id": visible_task["task_id"], "completion": completion,
            "jobs": [{"job_id": "job-001", "completion": completion, "raw_result": raw,
                      "normalized_claims": normalize_result(provider, raw) if raw is not None else [],
                      "provider_metrics": {"tokens": None, "cost": None}}]}


def visible_ref_index(visible_task):
    refs = []
    def visit(value):
        if isinstance(value, dict):
            if isinstance(value.get("run_id"), str) and isinstance(value.get("evidence_id"), str):
                refs.append(ref(value["run_id"], value["evidence_id"]))
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(visible_task["jobs"][0]["request"])
    return {"job-001": refs}


class CarrierEvaluationTests(unittest.TestCase):
    def score(self, visible_task, raw, oracle, *, completion="complete", validity="valid"):
        answer = answer_for(visible_task, raw, completion)
        oracle_job = {"job_id": "job-001", "expected_state": "fault_observed",
                      "service_states": {"technical": None, "acceptance": None, "change": None},
                      "required_gaps": [], "prohibited_codes": [], "forbid_causal_links": True}
        oracle_job.update(oracle)
        oracle_record = {"schema_version": 1, "task_id": visible_task["task_id"], "jobs": [oracle_job], "required_bindings": []}
        return score_answer(visible_task, answer, oracle_record, elapsed_ms=12, trial_validity=validity,
                            visible_refs_by_job=visible_ref_index(visible_task))["jobs"][0]

    def test_lucky_fault_code_without_complete_support_gets_no_grounded_credit(self):
        refs = [ref("run-001", "ev-01"), ref("run-001", "ev-02")]
        visible = task(request={"evidence": refs})
        expected = {"kind": "finding", "code": "optical_degradation", "status": None,
                    "scope": {}, "layer": "access", "fault_class": True,
                    "support_sets": [refs], "counter_refs": []}
        scored = self.score(visible, {"status": "fault_observed", "findings": [finding("optical_degradation", refs[:1])], "gaps": []},
                            {"claims": [expected]})
        self.assertEqual(scored["fault_class"]["score"], 0)
        self.assertEqual(scored["grounding"]["score"], 0)
        self.assertEqual(scored["localization"]["layer"]["score"], 0)

    def test_fabricated_extra_support_ref_gets_no_grounded_credit(self):
        required, fabricated = ref("run-001", "ev-required"), ref("run-999", "ev-fabricated")
        visible = task(request={"evidence": [required]})
        expected = {"kind": "finding", "code": "optical_degradation", "status": None,
                    "scope": {}, "layer": "access", "fault_class": True,
                    "support_sets": [[required]], "counter_refs": []}
        scored = self.score(visible, {"status": "fault_observed",
                                     "findings": [finding("optical_degradation", [required, fabricated])], "gaps": []},
                            {"claims": [expected]})
        self.assertEqual(scored["claim_recall"]["score"], 1)
        self.assertEqual(scored["state"]["score"], 1)
        self.assertEqual(scored["grounding"]["score"], 0)
        self.assertEqual(scored["fault_class"]["score"], 0)
        self.assertEqual(scored["localization"]["layer"]["score"], 0)

    def test_other_job_extra_support_ref_gets_no_grounded_credit(self):
        required, other_job = ref("run-001", "ev-required"), ref("run-002", "ev-other-job")
        visible = task(request={"evidence": [required]})
        answer = answer_for(visible, {"status": "fault_observed",
                                      "findings": [finding("optical_degradation", [required, other_job])], "gaps": []})
        expected = {"kind": "finding", "code": "optical_degradation", "status": None,
                    "scope": {}, "layer": "access", "fault_class": True,
                    "support_sets": [[required]], "counter_refs": []}
        oracle = {"schema_version": 1, "task_id": visible["task_id"],
                  "jobs": [{"job_id": "job-001", "expected_state": "fault_observed",
                            "service_states": {"technical": None, "acceptance": None, "change": None},
                            "required_gaps": [], "prohibited_codes": [], "forbid_causal_links": True,
                            "claims": [expected]}], "required_bindings": []}
        scored = score_answer(visible, answer, oracle, elapsed_ms=12,
                              visible_refs_by_job={"job-001": [required], "job-002": [other_job]})["jobs"][0]
        self.assertEqual(scored["claim_recall"]["score"], 1)
        self.assertEqual(scored["state"]["score"], 1)
        self.assertEqual(scored["grounding"]["score"], 0)
        self.assertEqual(scored["fault_class"]["score"], 0)
        self.assertEqual(scored["localization"]["layer"]["score"], 0)

    def test_each_claim_requires_its_own_support_set(self):
        a, b = ref("run-001", "ev-a"), ref("run-001", "ev-b")
        visible = task(request={"evidence": [a, b]})
        claims = [
            {"kind": "finding", "code": "auth_reject", "status": None, "scope": {}, "layer": "aggregation_subscriber_edge", "fault_class": True, "support_sets": [[a]], "counter_refs": []},
            {"kind": "finding", "code": "dhcp_failure", "status": None, "scope": {}, "layer": "aggregation_subscriber_edge", "fault_class": True, "support_sets": [[b]], "counter_refs": []},
        ]
        raw = {"status": "fault_observed", "findings": [finding("auth_reject", [a], "aggregation_subscriber_edge"),
                                                                finding("dhcp_failure", [a], "aggregation_subscriber_edge")], "gaps": []}
        scored = self.score(visible, raw, {"claims": claims})
        self.assertEqual(scored["grounding"]["numerator"], 1)
        self.assertEqual(scored["grounding"]["denominator"], 2)

    def test_neutral_counter_observation_is_not_a_fault_class(self):
        evidence = ref("run-001", "ev-counter")
        visible = task(request={"evidence": [evidence]})
        expected = {"kind": "finding", "code": "counter_increase", "status": None,
                    "scope": {}, "layer": "access", "fault_class": False,
                    "support_sets": [[evidence]], "counter_refs": []}
        scored = self.score(visible, {"status": "insufficient_evidence", "findings": [finding("counter_increase", [evidence])], "gaps": []},
                            {"expected_state": "insufficient_evidence", "claims": [expected]})
        self.assertIsNone(scored["fault_class"]["score"])
        self.assertEqual(scored["state"]["score"], 1)

    def test_abstention_is_separate_from_timeout(self):
        visible = task()
        oracle = {"expected_state": "insufficient_evidence", "claims": []}
        abstain = self.score(visible, {"status": "insufficient_evidence", "findings": [], "gaps": []}, oracle)
        timeout = self.score(visible, None, oracle, completion="timeout")
        self.assertTrue(abstain["correct_abstention"])
        self.assertFalse(timeout["correct_abstention"])
        self.assertEqual(timeout["completion"], "timeout")

    def test_m5_test_identity_keeps_absolute_directions_separate(self):
        a = {"criterion_id": "throughput", "absolute_direction": "endpoint_a_to_endpoint_b"}
        b = {"criterion_id": "throughput", "absolute_direction": "endpoint_b_to_endpoint_a"}
        visible = task("service_review")
        raw = {"technical_status": "unverified", "acceptance_status": "blocked",
               "change_review": {"status": "not_requested"}, "field_results": [],
               "test_matrix": [{**a, "status": "pass", "measurement_point": "point-a", "counterevidence": []},
                               {**b, "status": "fail", "measurement_point": "point-b", "counterevidence": []}]}
        expected = [{"kind": "test_result", "code": None, "status": "pass", "scope": a,
                     "layer": None, "fault_class": False, "support_sets": [], "counter_refs": []},
                    {"kind": "test_result", "code": None, "status": "pass", "scope": b,
                     "layer": None, "fault_class": False, "support_sets": [], "counter_refs": []}]
        scored = self.score(visible, raw, {"expected_state": None, "claims": expected})
        self.assertEqual(scored["claim_recall"]["numerator"], 1)
        self.assertEqual(scored["claim_recall"]["denominator"], 2)
        normalized = normalize_result("service_review", raw)
        self.assertEqual(normalized[1]["measurement_point"], "point-b")
        self.assertIsNone(normalized[1]["resource_id"])

    def test_wrong_layer_and_prohibited_premise_are_over_attribution(self):
        visible = task()
        expected = {"kind": "finding", "code": "wifi_failure", "status": None,
                    "scope": {}, "layer": "endpoint_lan", "fault_class": True,
                    "support_sets": [], "counter_refs": []}
        raw = {"status": "fault_observed", "findings": [finding("wifi_failure", (), "access"),
                                                            finding("application_failure", (), "destination_application")], "gaps": []}
        scored = self.score(visible, raw, {"claims": [expected], "prohibited_codes": ["application_failure"]})
        self.assertIsNone(scored["fault_class"]["score"])
        self.assertGreater(scored["over_attribution"]["count"], 0)

    def test_answer_normalization_must_match_raw_provider_result(self):
        visible = task()
        answer = answer_for(visible, {"status": "fault_observed", "findings": [finding("auth_reject")], "gaps": []})
        answer["jobs"][0]["normalized_claims"][0]["code"] = "dhcp_failure"
        with self.assertRaises(ContractError):
            validate_answer(answer, visible)

    def test_invalid_experiment_stages_are_not_valid_trials(self):
        record = {"schema_version": 1, "stages": {name: {"status": "passed", "evidence": [ref("run", name)],
                    "operation_scope": {"service": "s-1", "operation": "recovery-1"}} for name in STAGES}}
        record["stages"]["cleanup"]["status"] = "failed"
        validation = validate_experiment(record)
        self.assertFalse(validation["valid"])
        self.assertIn("stage_not_passed:cleanup", validation["reasons"])

    def test_strict_json_rejects_duplicate_keys_and_non_finite_numbers(self):
        for source in ('{"schema_version":1,"schema_version":1}', '{"x":NaN}'):
            with self.assertRaises(ContractError):
                loads_bounded(source)

    def test_replay_output_must_be_fresh_and_separate(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            replay = root / "baseline"
            replay.mkdir()
            (replay / "report.json").write_text("baseline", encoding="utf-8")
            with self.assertRaises((FileExistsError, ValueError)):
                _prepare_output_dir(replay, replay)
            with self.assertRaises(ValueError):
                _prepare_output_dir(replay / "nested-output", replay)
            fresh = root / "repeat"
            self.assertEqual(_prepare_output_dir(fresh, replay), fresh)


if __name__ == "__main__":
    unittest.main()
