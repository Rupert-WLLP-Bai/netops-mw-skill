from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "skills" / "internet-access-triage" / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from netops.contract import make_evidence, measurement, relative_artifact, validate_evidence
from netops.urls import parse_target, redact_url, validate_dns_endpoint


class ContractTests(unittest.TestCase):
    def test_valid_evidence_with_local_hash_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            raw.mkdir()
            artifact = raw / "body.bin"
            artifact.write_bytes(b"sample")
            record = make_evidence(
                "http_probe", "curl", "8.0", "complete",
                {"target": "https://service.example/", "protocol": "HTTPS", "window": None},
                {"http_status": 200}, "2026-11-12T00:00:00.000Z", 1,
                [measurement("total_ms", 4.2, "ms", 1, raw_values=[4.2])],
                [relative_artifact(root, artifact)],
            )
            self.assertEqual(validate_evidence([record], root), [])

    def test_invalid_nested_containers_return_errors_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = make_evidence(
                "http_probe", "curl", "8.0", "complete", {}, {},
                "2026-11-12T00:00:00.000Z", 1, [], [{"kind": "inline"}])
            record["measurements"] = None
            record["sources"] = None
            errors = validate_evidence([record], root)
            self.assertTrue(any("measurements must be an array" in error for error in errors))
            self.assertTrue(any("sources must be an array" in error for error in errors))

    def test_invalid_numbers_and_source_location_types_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = make_evidence(
                "pcap_analysis", "tshark", "4.0", "complete", {}, {},
                "2026-11-12T00:00:00.000Z", 1,
                [measurement("rtt_ms", 1, "ms", 1)],
                [{"kind": "external_input", "name": "capture.pcapng",
                  "sha256": hashlib.sha256(b"capture").hexdigest(),
                  "frame_numbers": [0, "bad"], "pointer": 17}])
            record["duration_ns"] = True
            record["measurements"][0]["value"] = float("nan")
            errors = validate_evidence([record], root)
            self.assertTrue(any("duration_ns is invalid" in error for error in errors))
            self.assertTrue(any("value must be numeric or null" in error for error in errors))
            self.assertTrue(any("frame_numbers must contain positive integers" in error for error in errors))
            self.assertTrue(any("pointer must be a string or null" in error for error in errors))

    def test_artifact_path_must_stay_inside_run_directory_and_match_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root.parent / (root.name + "-outside.bin")
            outside.write_bytes(b"outside")
            try:
                record = make_evidence(
                    "http_probe", "curl", None, "complete", {}, {},
                    "2026-11-12T00:00:00.000Z", 0, [],
                    [{"kind": "run_artifact", "path": "../" + outside.name,
                      "sha256": hashlib.sha256(b"outside").hexdigest()}])
                errors = validate_evidence([record], root)
                self.assertTrue(any("escapes the run directory" in error for error in errors))
            finally:
                outside.unlink(missing_ok=True)

    def test_url_validation_and_redaction(self) -> None:
        with self.assertRaises(ValueError):
            parse_target("ftp://service.example/")
        with self.assertRaises(ValueError):
            parse_target("https://user:secret@service.example/path")
        with self.assertRaises(ValueError):
            parse_target("http://service.example/path")
        target = parse_target("http://127.0.0.1/path?token=secret", allow_http=True)
        self.assertEqual(target["address_family"], "IPv4")
        self.assertEqual(redact_url("https://service.example/path?token=secret#part"),
                         "https://service.example/path?[redacted]")

    def test_dns_resolver_credentials_and_transport_mismatch_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_dns_endpoint("https://user:secret@resolver.example/dns-query", "https")
        with self.assertRaises(ValueError):
            validate_dns_endpoint("tls://resolver.example", "https")
        self.assertEqual(validate_dns_endpoint("resolver.example", "tls"), "tls://resolver.example")


if __name__ == "__main__":
    unittest.main()
