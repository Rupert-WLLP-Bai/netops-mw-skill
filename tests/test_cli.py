from __future__ import annotations

import json
import concurrent.futures
import hashlib
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "skills" / "internet-access-triage" / "scripts" / "diagnose.py"
SCRIPT_DIR = CLI.parent
sys.path.insert(0, str(SCRIPT_DIR))

from netops import live
from netops.live import ToolBox, _ping_counts, _ping_samples, _probe_target, _proxy_context
from netops.runner import CommandResult, Deadline
from netops.urls import parse_target


class ProbeState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.requests: list[str] = []
        self.followed_redirects = 0

    def record(self, path: str) -> None:
        with self.lock:
            self.requests.append(path)
            if path.startswith("/next"):
                self.followed_redirects += 1


class ProbeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        state: ProbeState = self.server.probe_state  # type: ignore[attr-defined]
        state.record(self.path)
        path = self.path.split("?", 1)[0]
        if path == "/slow-ttfb":
            time.sleep(0.2)
        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/next")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/large":
            self.send_response(200)
            self.send_header("Content-Length", str(2 * 1024 * 1024))
            self.end_headers()
            return
        if path == "/stalled":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                self.wfile.write(b"1\r\nx\r\n")
                self.wfile.flush()
                time.sleep(2.0)
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            return
        body = b"safe-response"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class ProbeServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, ssl.SSLError)):
            return
        super().handle_error(request, client_address)


class CurlParsingTests(unittest.TestCase):
    def test_proxy_failures_are_distinct_from_target_dns_or_connection_failure(self) -> None:
        for code in (5, 97):
            with self.subTest(code=code):
                result = CommandResult([], code, b"", b"", 0, "complete")
                self.assertEqual(live._curl_failure_kind(result, None, False), ("proxy_error", "complete"))


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ProbeServer(("127.0.0.1", 0), ProbeHandler)
        cls.server.probe_state = ProbeState()  # type: ignore[attr-defined]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _curl_only_env(self, directory: Path, proxy: str | None = None,
                       no_proxy: str | None = None) -> dict[str, str]:
        bin_dir = directory / "bin"
        bin_dir.mkdir(exist_ok=True)
        curl = shutil.which("curl")
        if curl:
            target = bin_dir / "curl"
            try:
                target.symlink_to(curl)
            except OSError:
                shutil.copy2(curl, target)
        env = os.environ.copy()
        env["PATH"] = str(bin_dir)
        for key in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "no_proxy", "NO_PROXY"):
            env.pop(key, None)
        if proxy:
            env["HTTP_PROXY"] = proxy
        if no_proxy is not None:
            env["NO_PROXY"] = no_proxy
        return env

    def _run_live(self, path: str, out: Path, env: dict[str, str], extra: list[str] | None = None,
                  timeout: float = 15) -> subprocess.CompletedProcess[str]:
        url = f"http://127.0.0.1:{self.port}{path}"
        command = [sys.executable, str(CLI), "--url", url, "--allow-http", "--symptom", "test-only symptom",
                   "--out", str(out)] + (extra or [])
        return subprocess.run(command, capture_output=True, text=True, env=env, timeout=timeout, check=False)

    def test_help_and_version_are_usable(self) -> None:
        result = subprocess.run([sys.executable, str(CLI), "--help"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn("--pcap", result.stdout)
        self.assertIn("--allow-http", result.stdout)
        self.assertIn("Examples:", result.stdout)
        version = subprocess.run([sys.executable, str(CLI), "--version"], capture_output=True, text=True, check=False)
        self.assertEqual(version.returncode, 0)
        self.assertIn("0.1.0", version.stdout)

    def test_unreachable_ping_rows_do_not_count_as_echo_replies_or_sent_samples(self) -> None:
        text = ("From 192.0.2.1 icmp_seq=1 Destination Host Unreachable\n"
                "From 192.0.2.1 icmp_seq=2 Destination Host Unreachable\n")
        sent, received, hints = _ping_counts(text, "Linux", 10)
        self.assertIsNone(sent)
        self.assertIsNone(received)
        self.assertEqual(hints, [])
        self.assertEqual(_ping_samples(text), [])

    def test_invalid_url_and_credentials_fail_before_output_creation(self) -> None:
        out = self.root / "bad-run"
        result = subprocess.run([sys.executable, str(CLI), "--url", "ftp://service.example/",
                                 "--symptom", "test", "--out", str(out)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(out.exists())
        credentials = subprocess.run([sys.executable, str(CLI), "--url", "https://user:secret@example.test/",
                                       "--symptom", "test", "--out", str(out)],
                                     capture_output=True, text=True, check=False)
        self.assertEqual(credentials.returncode, 2)
        self.assertFalse(out.exists())
        self.assertNotIn("secret", credentials.stderr)

    def test_new_output_directory_is_required(self) -> None:
        out = self.root / "existing"
        out.mkdir()
        result = subprocess.run([sys.executable, str(CLI), "--url", "https://service.example/",
                                 "--symptom", "test", "--out", str(out)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(list(out.iterdir()), [])

    @unittest.skipUnless(shutil.which("curl"), "curl is required for local HTTP integration checks")
    def test_real_loopback_get_preserves_hashes_and_redacts_query(self) -> None:
        out = self.root / "nested" / "live-run"
        env = self._curl_only_env(self.root)
        before = len(self.server.probe_state.requests)  # type: ignore[attr-defined]
        result = self._run_live(f"/ok?token=secret-{self.root.name}", out, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        final = json.loads(result.stdout)
        self.assertEqual(final["status"], "not_reproduced")
        self.assertEqual(len(list((out / "raw").glob("http_target_1_attempt_*.body"))), 3)
        self.assertEqual(len(self.server.probe_state.requests) - before, 3)  # type: ignore[attr-defined]
        evidence_text = (out / "evidence.jsonl").read_text(encoding="utf-8")
        manifest_text = (out / "manifest.json").read_text(encoding="utf-8")
        report_text = (out / "report.md").read_text(encoding="utf-8")
        self.assertNotIn("secret-", evidence_text + manifest_text + report_text)
        evidence = [json.loads(line) for line in evidence_text.splitlines()]
        http_records = [item for item in evidence if item["kind"] == "http_probe"]
        self.assertEqual(len(http_records), 3)
        self.assertTrue(all(item["scope"]["target_role"] == "target" for item in http_records))
        self.assertTrue(all(item["observation"]["http_status"] == 200 for item in http_records))
        for item in http_records:
            source = next(source for source in item["sources"] if source.get("path", "").endswith(".body"))
            body = (out / source["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(body).hexdigest(), source["sha256"])

    @unittest.skipUnless(shutil.which("curl"), "curl is required for local HTTP integration checks")
    def test_redirect_is_observed_without_following_it(self) -> None:
        env = self._curl_only_env(self.root)
        state = self.server.probe_state  # type: ignore[attr-defined]
        before_next = state.followed_redirects
        out = self.root / "redirect-run"
        result = self._run_live("/redirect", out, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = [json.loads(line) for line in (out / "evidence.jsonl").read_text(encoding="utf-8").splitlines()]
        http_records = [item for item in evidence if item["kind"] == "http_probe"]
        self.assertEqual(len(http_records), 3)
        self.assertTrue(all(item["observation"]["http_status"] == 302 for item in http_records))
        self.assertTrue(all(not item["observation"]["redirect_followed"] for item in http_records))
        self.assertEqual(state.followed_redirects, before_next)

    @unittest.skipUnless(shutil.which("curl"), "curl is required for local HTTP integration checks")
    def test_body_limit_is_enforced_and_recorded_as_partial(self) -> None:
        env = self._curl_only_env(self.root)
        out = self.root / "large-run"
        result = self._run_live("/large", out, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = [json.loads(line) for line in (out / "evidence.jsonl").read_text(encoding="utf-8").splitlines()]
        http_records = [item for item in evidence if item["kind"] == "http_probe"]
        self.assertEqual(len(http_records), 3)
        for item in http_records:
            self.assertIn(item["status"], ("partial", "complete"))
            self.assertIn(item["observation"]["outcome"], ("body_limit", "response"))
            body_path = next(source["path"] for source in item["sources"] if source.get("path", "").endswith(".body"))
            self.assertLessEqual((out / body_path).stat().st_size, 65536)

    @unittest.skipUnless(shutil.which("curl"), "curl is required for local HTTP integration checks")
    def test_ttfb_stage_uses_pretransfer_and_keeps_three_samples_separate(self) -> None:
        env = self._curl_only_env(self.root)
        out = self.root / "ttfb-run"
        result = self._run_live("/slow-ttfb", out, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = [json.loads(line) for line in (out / "evidence.jsonl").read_text(encoding="utf-8").splitlines()]
        records = [item for item in evidence if item["kind"] == "http_probe"]
        self.assertEqual(len(records), 3)
        for record in records:
            values = {item["name"]: item for item in record["measurements"]}
            self.assertGreater(values["response_wait_ms"]["value"], 150)
            self.assertEqual(values["response_wait_ms"]["sample_count"], 1)
            self.assertEqual(values["tls_handshake_ms"]["value"], None)
            self.assertEqual(values["tls_handshake_ms"]["missing_reason"], "not applicable to plain HTTP")

    @unittest.skipUnless(shutil.which("curl"), "curl is required for local HTTP integration checks")
    def test_explicit_response_wait_limit_can_observe_a_repeatable_slow_window(self) -> None:
        env = self._curl_only_env(self.root)
        out = self.root / "slow-limit-run"
        result = self._run_live("/slow-ttfb", out, env, ["--max-response-wait-ms", "100"])
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = [json.loads(line) for line in (out / "evidence.jsonl").read_text(encoding="utf-8").splitlines()]
        records = [item for item in evidence if item["kind"] == "http_probe"]
        values = [next(item["value"] for item in record["measurements"]
                       if item["name"] == "response_wait_ms") for record in records]
        self.assertEqual(len(values), 3)
        self.assertTrue(all(value is not None and value > 100 for value in values))
        diagnosis = json.loads((out / "diagnosis.json").read_text(encoding="utf-8"))
        self.assertEqual(diagnosis["status"], "fault_observed")
        self.assertTrue(any(candidate["domain"] == "response_wait" for candidate in diagnosis["candidates"]))

    @unittest.skipUnless(shutil.which("curl"), "curl is required for local HTTP integration checks")
    def test_no_proxy_only_does_not_hide_direct_connection(self) -> None:
        with mock.patch.dict(os.environ, {"NO_PROXY": "127.0.0.1,localhost"}, clear=True):
            context = _proxy_context()
        self.assertFalse(context["configured"])
        env = self._curl_only_env(self.root, no_proxy="127.0.0.1,localhost")
        out = self.root / "no-proxy-run"
        result = self._run_live("/ok", out, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = [json.loads(line) for line in (out / "evidence.jsonl").read_text(encoding="utf-8").splitlines()]
        records = [item for item in evidence if item["kind"] == "http_probe"]
        self.assertTrue(all(not item["observation"]["proxy_configured"] for item in records))
        self.assertTrue(all(item["observation"]["connected_ip"] == "127.0.0.1" for item in records))

    @unittest.skipUnless(shutil.which("curl"), "curl is required for local HTTP integration checks")
    def test_explicit_proxy_is_reported_without_direct_stage_attribution(self) -> None:
        proxy = f"http://127.0.0.1:{self.port}"
        env = self._curl_only_env(self.root, proxy=proxy, no_proxy="")
        out = self.root / "proxy-run"
        result = self._run_live("/ok", out, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = [json.loads(line) for line in (out / "evidence.jsonl").read_text(encoding="utf-8").splitlines()]
        records = [item for item in evidence if item["kind"] == "http_probe"]
        self.assertTrue(all(item["observation"]["proxy_configured"] for item in records))
        self.assertTrue(all(item["observation"]["connected_ip"] is None for item in records))
        self.assertTrue(all(all(measurement["value"] is None for measurement in item["measurements"]
                                if measurement["name"] in ("dns_ms", "tcp_connect_ms", "response_wait_ms"))
                            for item in records))

    @unittest.skipUnless(shutil.which("curl"), "curl is required for local HTTP integration checks")
    def test_shell_metacharacters_in_url_are_passed_as_data(self) -> None:
        marker = self.root / "shell-injection-marker"
        env = self._curl_only_env(self.root)
        out = self.root / "injection-run"
        payload = f"/ok;touch {marker}"
        result = self._run_live(payload, out, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())
        calls = json.loads((out / "manifest.json").read_text(encoding="utf-8"))["subprocess_calls"]
        curl_calls = [call for call in calls if call["tool"] == "curl" and call["purpose"].startswith("HTTP attempt")]
        self.assertTrue(curl_calls)
        self.assertTrue(all(call["command"][-1].startswith("http://127.0.0.1:") for call in curl_calls))

    @unittest.skipUnless(shutil.which("curl"), "curl is required for local HTTP integration checks")
    def test_stalled_body_keeps_http_header_but_marks_transfer_incomplete(self) -> None:
        target = parse_target(f"http://127.0.0.1:{self.port}/stalled", allow_http=True)
        output = self.root / "stalled-run"
        (output / "raw").mkdir(parents=True)
        deadline = Deadline(3)
        box = ToolBox(deadline)
        evidence: list[dict[str, object]] = []
        ping_jobs: dict[str, object] = {}
        ping_lock = threading.Lock()
        original_command = live._curl_command

        def one_second_command(executable: str, url: str, http_allowed: bool, timeout: int) -> list[str]:
            command = original_command(executable, url, http_allowed, timeout)
            index = command.index("--max-time")
            command[index + 1] = "1"
            return command

        with mock.patch.object(live, "MAX_ATTEMPTS", 1), mock.patch.object(live, "_curl_command", one_second_command), \
                concurrent.futures.ThreadPoolExecutor(max_workers=1) as ping_pool:
            _probe_target(box, evidence, target, 1, output, {"configured": False}, ping_pool,
                          ping_jobs, ping_lock, True)
        records = [item for item in evidence if item["kind"] == "http_probe"]
        self.assertEqual(len(records), 1)
        observation = records[0]["observation"]
        self.assertEqual(observation["http_status"], 200)
        self.assertEqual(observation["outcome"], "timeout")
        self.assertFalse(observation["transfer_complete"])
        downloaded = next(item for item in records[0]["measurements"] if item["name"] == "download_ms")
        self.assertIsNone(downloaded["value"])
        self.assertIsNotNone(downloaded["missing_reason"])

    @unittest.skipUnless(shutil.which("openssl") and shutil.which("curl"), "OpenSSL and curl are required")
    def test_self_signed_tls_failure_is_observed_with_validation_enabled(self) -> None:
        key = self.root / "key.pem"
        cert = self.root / "cert.pem"
        subprocess.run([shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-subj", "/CN=127.0.0.1",
                        "-days", "1", "-addext", "subjectAltName=IP:127.0.0.1"],
                       capture_output=True, timeout=10, check=True)
        tls_server = ProbeServer(("127.0.0.1", 0), ProbeHandler)
        tls_server.probe_state = ProbeState()  # type: ignore[attr-defined]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        tls_server.socket = context.wrap_socket(tls_server.socket, server_side=True)
        thread = threading.Thread(target=tls_server.serve_forever, daemon=True)
        thread.start()
        try:
            env = self._curl_only_env(self.root)
            out = self.root / "tls-run"
            url = f"https://127.0.0.1:{tls_server.server_address[1]}/ok"
            command = [sys.executable, str(CLI), "--url", url, "--symptom", "TLS test", "--out", str(out)]
            result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=15, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = [json.loads(line) for line in (out / "evidence.jsonl").read_text(encoding="utf-8").splitlines()]
            records = [item for item in evidence if item["kind"] == "http_probe"]
            self.assertEqual(len(records), 3)
            self.assertTrue(all(item["observation"]["outcome"] == "tls_error" for item in records))
            diagnosis = json.loads((out / "diagnosis.json").read_text(encoding="utf-8"))
            self.assertEqual(diagnosis["status"], "fault_observed")
            self.assertTrue(any(item["domain"] == "tls_validation" for item in diagnosis["candidates"]))
        finally:
            tls_server.shutdown()
            tls_server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
