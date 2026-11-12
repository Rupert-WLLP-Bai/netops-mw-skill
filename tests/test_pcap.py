from __future__ import annotations

import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "skills" / "internet-access-triage" / "scripts" / "diagnose.py"
SCRIPT_DIR = CLI.parent
sys.path.insert(0, str(SCRIPT_DIR))

from netops.live import ToolBox
from netops.pcap import _summarize_events, collect_offline
from netops.runner import Deadline


def _tcp_frame(src: str, dst: str, src_port: int, dst_port: int,
               sequence: int, acknowledgement: int, flags: int, payload: bytes = b"") -> bytes:
    source = bytes(int(part) for part in src.split("."))
    destination = bytes(int(part) for part in dst.split("."))
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, sequence, acknowledgement,
                      5 << 4, flags, 65535, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, 6, 0,
                     source, destination)
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    return ethernet + ip + tcp


def make_http_capture(path: Path) -> None:
    packet_records = [
        _tcp_frame("192.0.2.10", "198.51.100.20", 50000, 80, 1000, 0, 0x02),
        _tcp_frame("198.51.100.20", "192.0.2.10", 80, 50000, 2000, 1001, 0x12),
        _tcp_frame("192.0.2.10", "198.51.100.20", 50000, 80, 1001, 2001, 0x10),
    ]
    request = b"GET /status HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    packet_records.extend([
        _tcp_frame("192.0.2.10", "198.51.100.20", 50000, 80, 1001, 2001, 0x18, request),
        _tcp_frame("198.51.100.20", "192.0.2.10", 80, 50000, 2001, 1001 + len(request), 0x10),
        _tcp_frame("198.51.100.20", "192.0.2.10", 80, 50000, 2001, 1001 + len(request), 0x18, response),
    ])
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(packet_records):
            output.write(struct.pack("<IIII", 1700000000, index * 1000, len(frame), len(frame)))
            output.write(frame)


class PcapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.capture = self.root / "small input.pcap"
        make_http_capture(self.capture)

    def tearDown(self) -> None:
        self.temp.cleanup()

    @unittest.skipUnless(shutil.which("tshark"), "TShark is optional and unavailable")
    def test_real_tshark_reads_synthetic_http_capture_offline(self) -> None:
        out = self.root / "offline-run"
        command = [sys.executable, str(CLI), "--pcap", str(self.capture), "--out", str(out)]
        result = __import__("subprocess").run(command, capture_output=True, text=True,
                                               timeout=25, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = [json.loads(line) for line in (out / "evidence.jsonl").read_text(encoding="utf-8").splitlines()]
        record = next(item for item in evidence if item["kind"] == "pcap_analysis")
        self.assertIn(record["status"], ("complete", "partial"))
        summary = record["observation"]["summary"]
        self.assertGreaterEqual(summary["frames"], 6)
        self.assertEqual(summary["http_request_messages"], 1)
        self.assertEqual(summary["http_response_messages"], 1)
        self.assertEqual(summary["http_paired_final_responses"], 1)
        self.assertEqual(record["sources"][0]["sha256"], record["observation"]["capture_sha256"])
        diagnosis = json.loads((out / "diagnosis.json").read_text(encoding="utf-8"))
        self.assertEqual(diagnosis["status"], "insufficient_evidence")

    @unittest.skipUnless(shutil.which("tshark"), "TShark is optional and unavailable")
    def test_filtered_empty_capture_remains_filter_scoped_and_insufficient(self) -> None:
        out = self.root / "filtered-empty"
        command = [sys.executable, str(CLI), "--pcap", str(self.capture), "--out", str(out),
                   "--display-filter", "tcp.port == 443"]
        result = __import__("subprocess").run(command, capture_output=True, text=True,
                                               timeout=25, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = next(json.loads(line) for line in (out / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
                      if json.loads(line)["kind"] == "pcap_analysis")
        self.assertEqual(record["observation"]["summary"]["frames"], 0)
        self.assertIn("display-filter", record["observation"]["filter_scope"])
        self.assertTrue(record["observation"]["input_scan_may_be_partial"])
        self.assertEqual(json.loads((out / "diagnosis.json").read_text(encoding="utf-8"))["status"],
                         "insufficient_evidence")

    def test_stub_tshark_missing_optional_field_is_unknown_not_zero(self) -> None:
        fake = self.root / "stub-tshark"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json,sys\n"
            "if '--version' in sys.argv: print('TShark stub 0.1'); raise SystemExit(0)\n"
            "if '-G' in sys.argv: print('F\\tFrame number\\tframe.number\\tFT_UINT32'); print('F\\tEpoch time\\tframe.time_epoch\\tFT_ABSOLUTE_TIME'); raise SystemExit(0)\n"
            "print(json.dumps({'layers': {'frame_number': ['1'], 'frame_time_epoch': ['1700000000.0']}}))\n",
            encoding="utf-8")
        fake.chmod(fake.stat().st_mode | 0o111)
        out = self.root / "stub-run"
        (out / "raw").mkdir(parents=True)
        result = collect_offline(self.capture, out, Deadline(10), str(fake))
        record = next(item for item in result["evidence"] if item["kind"] == "pcap_analysis")
        self.assertEqual(record["status"], "complete")
        self.assertIsNone(record["observation"]["summary"]["tcp_retransmission_frames"])
        metric = next(item for item in record["measurements"]
                      if item["name"] == "tcp_retransmission_indicator_frames")
        self.assertIsNone(metric["value"])
        self.assertIn("unavailable", metric["missing_reason"])

    def test_missing_tshark_is_a_distinct_unsupported_result(self) -> None:
        out = self.root / "missing-tool"
        (out / "raw").mkdir(parents=True)
        result = collect_offline(self.capture, out, Deadline(3), "tshark-that-is-not-installed")
        record = result["evidence"][0]
        self.assertEqual(record["status"], "unsupported")
        self.assertEqual(record["failure"]["kind"], "tool_missing")
        self.assertEqual(result["call_counts"]["pcap_parsers"], 0)

    def test_input_size_cap_is_recorded_without_hashing_or_parsing_input(self) -> None:
        oversized = self.root / "oversized.pcap"
        with oversized.open("wb") as output:
            output.truncate(64 * 1024 * 1024 + 1)
        out = self.root / "oversized-run"
        (out / "raw").mkdir(parents=True)
        result = collect_offline(oversized, out, Deadline(3), "tshark-that-is-not-installed")
        record = result["evidence"][0]
        self.assertEqual(record["status"], "partial")
        self.assertEqual(record["observation"]["input_status"], "input_limit")
        self.assertIsNone(record["observation"]["capture_sha256"])
        self.assertEqual(result["call_counts"]["pcap_parsers"], 0)


class DnsDirectionTests(unittest.TestCase):
    def test_dns_direction_supports_tshark_boolean_serializations_and_unknowns(self) -> None:
        # Frame 30 of the public lotsofweb capture emits the string "True".
        directions = [["False"], ["True"], ["0"], ["1"], [False], [True],
                      [0], [1], [], ["unexpected"], ["False", "True"],
                      ["True", "unexpected"]]
        records = []
        for index, values in enumerate(directions, 1):
            layers = {"frame_number": [str(index)], "dns_id": ["0x1234"]}
            if values:
                layers["dns_flags_response"] = values
            records.append(json.dumps({"layers": layers}))
        summary, error, _ = _summarize_events(
            ("\n".join(records) + "\n").encode(),
            {"frame.number", "dns.id", "dns.flags.response"},
        )
        self.assertIsNone(error)
        self.assertEqual(summary["dns_frames"], 12)
        self.assertEqual(summary["dns_queries"], 5)
        self.assertEqual(summary["dns_responses"], 6)
        self.assertEqual(summary["dns_direction_unknown_frames"], 3)
        self.assertEqual(summary["dns_mixed_direction_frames"], 1)

    def test_unavailable_dns_direction_fields_remain_unknown(self) -> None:
        raw = b'{"layers":{"frame_number":["1"],"dns_id":["0x1234"]}}\n'
        summary, _, _ = _summarize_events(raw, {"frame.number", "dns.id"})
        self.assertEqual(summary["dns_frames"], 1)
        self.assertIsNone(summary["dns_queries"])
        self.assertIsNone(summary["dns_responses"])
        self.assertIsNone(summary["dns_direction_unknown_frames"])


if __name__ == "__main__":
    unittest.main()
