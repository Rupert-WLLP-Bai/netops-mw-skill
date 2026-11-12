"""Independent diagnosis replay inputs and expected conclusion boundaries."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills/internet-access-triage/scripts"))
from netops.diagnosis import diagnose, validate_diagnosis
from netops.report import render_report

TARGET = "https://service.example/status"
CONTROL = "https://control.example/status"
START = "2026-11-12T00:00:00Z"
END = "2026-11-12T00:01:00Z"


def scope():
    return {"run_id": "replay-1", "window_started_at_utc": START, "window_ended_at_utc": END,
            "control_target_configured": True,
            "targets": [{"url": TARGET, "protocol": "HTTPS"}, {"url": CONTROL, "protocol": "HTTPS"}]}


def record(n, kind, observation, *, target=TARGET, family="IPv4", status="complete", measurements=None):
    return {"id": f"ev-{n:012x}", "kind": kind, "tool": {"name": "sample", "version": "1"},
            "status": status, "scope": {"target": target, "protocol": "HTTPS", "address_family": family,
                                      "run_id": "replay-1"},
            "started_at_utc": "2026-11-12T00:00:01Z", "duration_ns": 1000000,
            "measurements": measurements or [], "observation": observation,
            "sources": [{"kind": "inline"}], "failure": None}


def http(n, wait=10, *, target=TARGET, family="IPv4", outcome="response", code=0, status="complete"):
    obs = {"outcome": outcome, "curl_returncode": code,
           "http_status": 200 if outcome == "response" else None,
           "transfer_complete": outcome == "response", "address_family": family}
    return record(n, "http_probe", obs, target=target, family=family, status=status,
                  measurements=[{"name": "response_wait_ms", "value": wait, "unit": "ms", "sample_count": 1}])


def dns(n, value):
    return record(n, "dns_query", {"resolver": "192.0.2.53", "transport": "udp"},
                  measurements=[{"name": "query_elapsed_ms", "value": value, "unit": "ms", "sample_count": 1}])


def load_record():
    cycles = []
    for offset in (2, 12):
        phases = []
        for i, name in enumerate(("idle", "load", "recovery")):
            phase = {"name": name, "vantage": "client", "started_at_utc": f"2026-11-12T00:00:{offset+i*2:02}Z",
                     "ended_at_utc": f"2026-11-12T00:00:{offset+i*2+1:02}Z",
                     "rtt_ms": [10, 11, 12] if name != "load" else [100, 110, 120]}
            if name == "load":
                phase["upload_rate_bytes_per_s"] = 1000
            phases.append(phase)
        cycles.append({"phases": phases})
    result = record(9, "load_comparison", {"cycles": cycles})
    result["scope"].update({"vantage": "client", "window": {"started_at_utc": START, "ended_at_utc": END}})
    return result


class DiagnosisReplayTests(unittest.TestCase):
    def check(self, records, expected_status, expected_domains, *, mode="replay", **kwargs):
        result = diagnose(records, scope(), mode, **kwargs)
        self.assertEqual(validate_diagnosis(result, records), [])
        self.assertEqual(result["status"], expected_status)
        self.assertEqual({item["domain"] for item in result["candidates"]}, set(expected_domains))
        self.assertLessEqual(len(result["candidates"]), 2)
        return result

    def test_inet_01_dns_stage_without_cpu_attribution(self):
        requests = [http(n) for n in (4, 5, 6)]
        for item in requests:
            item["observation"]["connected_ip"] = "192.0.2.10"
            item["measurements"].append({"name": "dns_ms", "value": 4, "unit": "ms", "sample_count": 1})
        r = self.check([dns(1, 200), dns(2, 210), dns(3, 220), *requests], "not_reproduced",
                       ["name_resolution_latency"], max_dns_ms=100)
        self.assertIn("does not identify recursive-server CPU", r["candidates"][0]["basis"])
        self.assertEqual(r["candidates"][0]["evidence_ids"], ["ev-000000000001", "ev-000000000002", "ev-000000000003"])

    def test_inet_05_target_timeout_with_control(self):
        r = self.check([http(1, outcome="timeout", code=28), http(2, target=CONTROL)], "fault_observed", ["request_timeout"])
        self.assertIn("ev-000000000002", r["candidates"][0]["counterevidence_ids"])
        self.assertIn("not classified", r["candidates"][0]["basis"])

    def test_inet_06_tls_validation_failure(self):
        r = self.check([http(1, family=None, outcome="tls_error", code=60), http(2, target=CONTROL)], "fault_observed", ["tls_validation"])
        self.assertIn("retain certificate validation", r["candidates"][0]["next_step"])

    def test_inet_07_response_wait_not_proxy_handshake_attribution(self):
        records = [http(i, 250) for i in (1, 2, 3)]
        for item in records:
            item["observation"]["proxy_configured"] = True
        r = self.check(records, "fault_observed", ["response_wait"], max_response_wait_ms=100)
        self.assertTrue(any("proxy" in item for item in r["limitations"]))
        self.assertIn("not a server, proxy", r["candidates"][0]["basis"])

    def test_inet_10_two_repeated_load_cycles_are_correlation(self):
        r = self.check([load_record()], "fault_observed", ["load_related_latency"])
        self.assertIn("correlation only", r["candidates"][0]["basis"])
        stale = load_record()
        stale["scope"]["run_id"] = "different-window"
        self.check([stale], "insufficient_evidence", [])

    def test_inet_18_missing_hops_are_not_forwarding_loss(self):
        path = record(4, "path_report", {"missing_hops": [2, 3]})
        r = self.check([http(1), http(2), http(3), path], "healthy_within_scope", [], max_response_wait_ms=100)
        self.assertTrue(any("do not establish forwarding loss" in x for x in r["limitations"]))

    def test_inet_20_health_requires_complete_baseline(self):
        r = self.check([http(1, 20), http(2, 30), http(3, 40)], "healthy_within_scope", [], max_response_wait_ms=100)
        self.assertEqual(r["scope"]["health_checks"][1]["result"], "within_configured_limit")
        self.assertTrue(any("short collection window" in x for x in r["limitations"]))

    def test_inet_23_short_normal_window_does_not_disprove_history(self):
        self.check([http(1)], "not_reproduced", [])

    def test_inet_24_capture_indicators_do_not_assign_device(self):
        capture = record(1, "pcap_analysis", {"summary": {"frames": 20, "tcp_retransmission_frames": 2}})
        r = self.check([capture], "insufficient_evidence", ["captured_transport_indicators"], mode="offline_pcap")
        self.assertIn("not proof of end-to-end loss or responsibility", r["candidates"][0]["basis"])
        self.assertEqual(r["origin"], "offline_pcap")

    def test_inet_25_late_wait_does_not_assign_dns(self):
        records = [dns(1, 4), dns(2, 5), dns(3, 6), http(4, 250), http(5, 260), http(6, 270)]
        self.check(records, "fault_observed", ["response_wait"], max_response_wait_ms=100, max_dns_ms=50)

    def test_inet_26_path_permission_does_not_erase_business_failure(self):
        path = record(2, "path_trace", {}, status="permission_denied")
        r = self.check([http(1, outcome="connection_error", code=7), path], "fault_observed", ["transport_connection"])
        self.assertTrue(any("localization is reduced" in x for x in r["limitations"]))

    def test_inet_27_control_does_not_establish_internet_wide_failure(self):
        r = self.check([http(1, outcome="connection_error", code=7), http(2, target=CONTROL)], "fault_observed", ["transport_connection"])
        self.assertEqual(r["candidates"][0]["evidence_ids"], ["ev-000000000001"])
        self.assertEqual(r["candidates"][0]["counterevidence_ids"], ["ev-000000000002"])

    def test_missing_family_fault_and_strict_family_comparison(self):
        r = self.check([http(1, family=None, outcome="dns_error", code=6), http(2, target=CONTROL)], "fault_observed", ["name_resolution"])
        self.assertEqual(r["candidates"][0]["counterevidence_ids"], [])
        r = self.check([http(1, family=None, outcome="connection_error", code=7),
                        http(2, family=None, target=CONTROL)], "fault_observed", ["transport_connection"])
        self.assertEqual(r["candidates"][0]["counterevidence_ids"], [])
        r = self.check([http(1, family="IPv4", outcome="connection_error", code=7),
                        http(2, family="IPv6")], "fault_observed", ["transport_connection"])
        self.assertIsNone(r["scope"]["address_family"])
        r = self.check([http(1, family="IPv4"), http(2, family="IPv6"), http(3, family="IPv4")], "not_reproduced", [], max_response_wait_ms=100)
        self.assertIsNone(r["scope"]["address_family"])

    def test_outside_run_load_phase_cannot_support_fault(self):
        stale = load_record()
        stale["observation"]["cycles"][1]["phases"][2]["ended_at_utc"] = "2026-11-12T00:02:00Z"
        self.check([stale], "insufficient_evidence", [])

    def test_incomplete_transfer_and_budget_expiry_are_not_business_success_or_timeout(self):
        incomplete = http(1)
        incomplete["observation"].update({"transfer_complete": False, "curl_returncode": 28, "outcome": "timeout"})
        budget = http(2, outcome="budget_exhausted", code=None, status="budget_exhausted")
        self.check([incomplete, budget], "fault_observed", ["request_timeout"])
        self.check([budget], "insufficient_evidence", [])
        truncated = http(3)
        truncated["observation"]["transfer_complete"] = False
        self.check([truncated], "insufficient_evidence", [])

    def test_proxy_resolution_failure_is_observed_without_address_family(self):
        r = self.check([http(1, family=None, outcome="proxy_error", code=5)], "fault_observed", ["proxy_connection"])
        self.assertIsNone(r["scope"]["address_family"])
        self.assertIn("proxy", r["candidates"][0]["basis"])

    def test_report_does_not_pool_unmatched_families(self):
        records = [http(1, 20), http(2, 30), http(3, 300, family="IPv6")]
        result = diagnose(records, scope(), "replay", max_response_wait_ms=100)
        report = render_report(result, records, {"call_counts": {}})
        self.assertNotIn("median:", report)

    def test_invalid_nested_diagnosis_references_are_rejected(self):
        records = [http(1)]
        result = diagnose(records, scope(), "replay")
        result["scope"]["health_checks"][0]["evidence_ids"] = [None, "ev-ffffffffffff"]
        result["scope"]["http_measurement_groups"] = [{"name": "response_wait_ms", "evidence_ids": ["ev-ffffffffffff"], "median_ms": float("nan"), "range_ms": 1, "sample_count": 3}]
        result["candidates"] = [{"domain": "x", "basis": "x", "next_step": "x", "evidence_ids": {}, "counterevidence_ids": []}]
        errors = validate_diagnosis(result, records)
        self.assertTrue(any("unknown IDs" in x for x in errors))
        self.assertTrue(any("array of strings" in x for x in errors))
        self.assertTrue(any("http_measurement_groups" in x for x in errors))

    def test_report_shows_grouped_median_range_and_health_checks(self):
        records = [http(1, 20), http(2, 30), http(3, 40)]
        result = diagnose(records, scope(), "replay", max_response_wait_ms=100)
        report = render_report(result, records, {"call_counts": {}})
        self.assertIn("response_wait_ms", report)
        self.assertIn("within_configured_limit", report)
        self.assertIn("median: 30", report)
        self.assertIn("range: 20", report)


if __name__ == "__main__":
    unittest.main()
