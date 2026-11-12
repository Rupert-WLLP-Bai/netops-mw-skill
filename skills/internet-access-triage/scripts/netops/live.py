"""Bounded live HTTP, DNS, ping, and local-context collection."""

from __future__ import annotations

import concurrent.futures
import json
import math
import os
import platform
import re
import shutil
import statistics
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from .contract import make_evidence, measurement, relative_artifact, utc_now
from .runner import CommandResult, Deadline, run_command
from .urls import redact_text, redact_url


MAX_ATTEMPTS = 3
BODY_LIMIT = 65536
DNS_TIMEOUT_SECONDS = 2
PING_SAMPLES = 10


def _version_line(data: bytes) -> str | None:
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line:
            return line[:180]
    return None


class ToolBox:
    """Track every child command and expose a redacted command record."""

    def __init__(self, deadline: Deadline) -> None:
        self.deadline = deadline
        self.calls: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.executables = {name: shutil.which(name) for name in ("curl", "dnslookup", "ping", "tshark")}
        self.versions: dict[str, str | None] = {name: None for name in self.executables}
        self.discovery: dict[str, dict[str, Any]] = {
            name: {"available": path is not None, "version_status": "not_queried"}
            for name, path in self.executables.items()
        }

    def run(self, tool: str, args: list[str], purpose: str, stdout_limit: int,
            stderr_limit: int, timeout_seconds: float | None = None,
            env: dict[str, str] | None = None, safe_command: list[str] | None = None,
            network_request: bool = False) -> CommandResult:
        start = time.monotonic()
        result = run_command(args, self.deadline, stdout_limit, stderr_limit,
                             timeout_seconds=timeout_seconds, env=env)
        display = safe_command or [Path(args[0]).name, *args[1:]]
        record = {
            "index": 0,
            "tool": tool,
            "purpose": purpose,
            "command": display,
            "returncode": result.returncode,
            "status": result.status,
            "duration_ns": result.duration_ns,
            "stdout_bytes_retained": len(result.stdout),
            "stderr_bytes_retained": len(result.stderr),
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
            "network_request_started": bool(network_request and result.process_started),
            "error_kind": result.error_kind,
        }
        with self.lock:
            record["index"] = len(self.calls) + 1
            self.calls.append(record)
        return result

    def discover_versions(self, live: bool = True) -> None:
        commands: list[tuple[str, list[str], str]] = []
        if live:
            if self.executables["curl"]:
                commands.append(("curl", [self.executables["curl"], "--version"], "curl version"))
            if self.executables["dnslookup"]:
                commands.append(("dnslookup", [self.executables["dnslookup"], "-v"], "dnslookup version"))
            if self.executables["ping"]:
                version_arg = "/?" if os.name == "nt" else "-V"
                commands.append(("ping", [self.executables["ping"], version_arg], "ping version"))
        if self.executables["tshark"] and not live:
            commands.append(("tshark", [self.executables["tshark"], "--version"], "TShark version"))

        def query(item: tuple[str, list[str], str]) -> tuple[str, CommandResult]:
            name, command, purpose = item
            version_env = os.environ.copy()
            version_env.pop("JSON", None)
            result = self.run(name, command, purpose, 32768, 8192, timeout_seconds=1.5,
                              env=version_env,
                              safe_command=[Path(command[0]).name, command[1]])
            return name, result

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(query, item) for item in commands]
            for future in concurrent.futures.as_completed(futures):
                name, result = future.result()
                version = _version_line(result.stdout) or _version_line(result.stderr)
                self.versions[name] = version
                self.discovery[name]["version_status"] = result.status
                self.discovery[name]["version"] = version
        for name, path in self.executables.items():
            self.discovery[name]["available"] = path is not None
            if path is None:
                self.discovery[name]["version_status"] = "unsupported"


def _append_failure(failures: list[dict[str, Any]], kind: str, target: str | None,
                    reason: str, status: str) -> None:
    failures.append({"kind": kind, "target": target, "status": status, "reason": reason})


def _new_evidence(evidence: list[dict[str, Any]], kind: str, tool: str, version: str | None,
                  status: str, scope: dict[str, Any], observation: dict[str, Any],
                  started: str, started_mono: float, measurements: list[dict[str, Any]] | None = None,
                  sources: list[dict[str, Any]] | None = None, failure: dict[str, Any] | None = None) -> dict[str, Any]:
    record = make_evidence(kind, tool, version, status, scope, observation, started,
                           int((time.monotonic() - started_mono) * 1e9), measurements, sources, failure)
    evidence.append(record)
    return record


def _proxy_context() -> dict[str, Any]:
    try:
        proxies = urllib.request.getproxies()
    except Exception:
        proxies = {}
    configured = {str(key).lower() for key, value in proxies.items()
                  if value and str(key).lower() not in ("no", "no_proxy")}
    return {
        "configured": bool(configured),
        "protocols": sorted(configured),
        "use_for_target": "unknown" if configured else "no_proxy_environment_detected",
    }


def _linux_route() -> dict[str, Any]:
    route_file = Path("/proc/net/route")
    try:
        rows = route_file.read_text(encoding="ascii", errors="replace").splitlines()[1:]
        for row in rows:
            fields = row.split()
            if len(fields) >= 4 and fields[1] == "00000000":
                gateway_raw = int(fields[2], 16)
                gateway = ".".join(str((gateway_raw >> shift) & 255) for shift in (0, 8, 16, 24))
                flags = int(fields[3], 16)
                if flags & 1:
                    return {"default_gateway": gateway, "interface": fields[0], "source": "/proc/net/route"}
    except (OSError, ValueError, IndexError):
        pass
    return {"default_gateway": None, "interface": None, "missing_reason": "default route was not readable"}


def _mac_route(box: ToolBox) -> dict[str, Any]:
    executable = shutil.which("route")
    if not executable:
        return {"default_gateway": None, "interface": None, "missing_reason": "route command unavailable"}
    result = box.run("route", [executable, "-n", "get", "default"], "read default route", 8192, 4096,
                     timeout_seconds=1.0, safe_command=["route", "-n", "get", "default"])
    text = result.stdout.decode("utf-8", "replace")
    gateway = re.search(r"^\s*gateway:\s*(\S+)", text, re.MULTILINE)
    interface = re.search(r"^\s*interface:\s*(\S+)", text, re.MULTILINE)
    return {"default_gateway": gateway.group(1) if gateway else None,
            "interface": interface.group(1) if interface else None,
            "status": result.status, "missing_reason": None if gateway else "route output was not recognized"}


def _windows_route(box: ToolBox) -> dict[str, Any]:
    executable = shutil.which("route") or shutil.which("route.exe")
    if not executable:
        return {"default_gateway": None, "interface": None, "missing_reason": "route command unavailable"}
    result = box.run("route", [executable, "PRINT", "-4"], "read default route", 65536, 8192,
                     timeout_seconds=1.5, safe_command=["route", "PRINT", "-4"])
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0] == "0.0.0.0" and fields[1] == "0.0.0.0":
            return {"default_gateway": fields[2], "interface": fields[3], "status": result.status}
    return {"default_gateway": None, "interface": None, "status": result.status,
            "missing_reason": "default route row was not recognized"}


def collect_context(box: ToolBox, evidence: list[dict[str, Any]], proxy: dict[str, Any]) -> dict[str, Any]:
    started, mono = utc_now(), time.monotonic()
    system = platform.system() or "unknown"
    route = (_linux_route() if system == "Linux" else
             _mac_route(box) if system == "Darwin" else
             _windows_route(box) if system == "Windows" else
             {"default_gateway": None, "interface": None, "missing_reason": "platform route reader unavailable"})
    context = {
        "operating_system": {"system": system, "release": platform.release(), "machine": platform.machine()},
        "default_route": route,
        "proxy": proxy,
        "vpn_state": "unknown",
    }
    _new_evidence(evidence, "local_context", "python-standard-library", platform.python_version(), "complete",
                  {"target": None, "protocol": None, "address_family": None, "window": None},
                  context, started, mono, sources=[{"kind": "inline"}])
    return context


def _curl_env(url: str) -> tuple[dict[str, str], dict[str, Any]]:
    env = os.environ.copy()
    context = _proxy_context()
    env["NO_COLOR"] = "1"
    return env, context


def _parse_writeout(stderr: bytes) -> dict[str, str] | None:
    text = stderr.decode("utf-8", "replace")
    for line in reversed(text.splitlines()):
        if line.startswith("__NETOPS_META__"):
            values = line[len("__NETOPS_META__"):].split("\t")
            keys = ("http_status", "remote_ip", "dns_seconds", "connect_seconds", "tls_seconds",
                    "pretransfer_seconds", "first_byte_seconds", "total_seconds", "download_bytes",
                    "new_connections", "http_version")
            return {key: values[index] if index < len(values) else "" for index, key in enumerate(keys)}
    return None


def _float(value: str | None) -> float | None:
    try:
        result = float(value)  # type: ignore[arg-type]
        return result if math.isfinite(result) and result >= 0 else None
    except (TypeError, ValueError):
        return None


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None


def _curl_command(executable: str, url: str, http_allowed: bool, attempt_timeout: int) -> list[str]:
    writeout = (
        "%{stderr}__NETOPS_META__%{http_code}\t%{remote_ip}\t%{time_namelookup}\t"
        "%{time_connect}\t%{time_appconnect}\t%{time_pretransfer}\t%{time_starttransfer}\t%{time_total}\t"
        "%{size_download}\t%{num_connects}\t%{http_version}\n"
    )
    return [executable, "-q", "--silent", "--show-error", "--request", "GET", "--output", "-",
            "--write-out", writeout, "--connect-timeout", "3", "--max-time", str(attempt_timeout),
            "--max-filesize", str(BODY_LIMIT), "--max-redirs", "0", "--retry", "0",
            "--proto", "=http,https", "--url", url]


def _curl_failure_kind(result: CommandResult, meta: dict[str, str] | None,
                       body_truncated: bool) -> tuple[str, str]:
    stderr = result.stderr.decode("utf-8", "replace").lower()
    if body_truncated or result.error_kind == "stdout_limit" or "maximum file size" in stderr:
        return "body_limit", "partial"
    if result.status in ("timeout", "budget_exhausted"):
        return ("collection_timeout" if result.status == "timeout" else "budget_exhausted", result.status)
    if result.status in ("unsupported", "permission_denied", "tool_error"):
        return result.status, result.status
    if result.returncode == 28:
        return "timeout", "complete"
    if result.returncode in (5, 97):
        return "proxy_error", "complete"
    if result.returncode == 60 or "certificate" in stderr or "ssl certificate" in stderr:
        return "tls_error", "complete"
    if result.returncode == 6 or "could not resolve" in stderr or "resolve host" in stderr:
        return "dns_error", "complete"
    if result.returncode == 7 or "failed to connect" in stderr or "connection refused" in stderr:
        return "connection_error", "complete"
    if result.returncode not in (0, None):
        return "curl_error", "complete" if meta else "tool_error"
    return "response", "complete"


def _stage_measurements(meta: dict[str, str], direct: bool, body_complete: bool,
                        scheme: str) -> list[dict[str, Any]]:
    if not direct:
        return [measurement("curl_stage_ms", None, "ms", 0, missing_reason="proxy or route semantics are not directly comparable")]
    dns = _float(meta.get("dns_seconds"))
    connected = _float(meta.get("connect_seconds"))
    tls = _float(meta.get("tls_seconds")) if scheme == "https" else None
    pretransfer = _float(meta.get("pretransfer_seconds"))
    first_byte = _float(meta.get("first_byte_seconds"))
    total = _float(meta.get("total_seconds"))
    connects = _int(meta.get("new_connections"))
    http_version = meta.get("http_version")
    if connects != 1 or http_version not in ("1", "1.0", "1.1", "2", "2.0"):
        return [measurement("curl_stage_ms", None, "ms", 0,
                            missing_reason="fresh direct TCP connection was not established or protocol is not comparable")]
    values: dict[str, float | None] = {
        "dns_ms": dns * 1000 if dns is not None else None,
        "tcp_connect_ms": (connected - dns) * 1000 if dns is not None and connected is not None and connected >= dns else None,
        "tls_handshake_ms": (tls - connected) * 1000 if scheme == "https" and tls is not None and connected is not None and tls >= connected else None,
        "response_wait_ms": (first_byte - pretransfer) * 1000
            if first_byte is not None and pretransfer is not None and first_byte >= pretransfer else None,
        "download_ms": (total - first_byte) * 1000 if body_complete and total is not None and first_byte is not None and total >= first_byte else None,
    }
    results = []
    for name, value in values.items():
        reason = None if value is not None else (
            "not applicable to plain HTTP" if name == "tls_handshake_ms" and scheme == "http"
            else "curl did not provide comparable stage timing")
        results.append(measurement(name, round(value, 3) if value is not None else None, "ms",
                                   1 if value is not None else 0, missing_reason=reason))
    return results


def _dns_answers(document: Any) -> tuple[int | None, list[dict[str, Any]], int | None]:
    if not isinstance(document, dict):
        return None, [], None
    rcode = document.get("Rcode")
    if isinstance(rcode, dict):
        rcode = rcode.get("Code")
    if not isinstance(rcode, int):
        rcode = None
    answers: list[dict[str, Any]] = []
    for record in document.get("Answer", []) if isinstance(document.get("Answer", []), list) else []:
        if not isinstance(record, dict):
            continue
        header = record.get("Hdr") if isinstance(record.get("Hdr"), dict) else {}
        entry = {"type": header.get("Rrtype"), "ttl_seconds": header.get("Ttl")}
        for key in ("A", "AAAA", "Target", "CNAME"):
            if key in record:
                entry["value"] = str(record[key])
                break
        answers.append(entry)
    elapsed = document.get("elapsed")
    elapsed_ns = elapsed if isinstance(elapsed, int) and elapsed >= 0 else None
    if isinstance(elapsed, str):
        match = re.fullmatch(r"([0-9.]+)(ns|us|µs|ms|s)", elapsed.strip())
        if match:
            scale = {"ns": 1, "us": 1000, "µs": 1000, "ms": 1_000_000, "s": 1_000_000_000}[match.group(2)]
            elapsed_ns = int(float(match.group(1)) * scale)
    return rcode, answers, elapsed_ns


def _dns_server(server: str | None, transport: str) -> str | None:
    if not server:
        return None
    if transport in ("udp", "tcp"):
        return ("tcp://" if transport == "tcp" else "") + server
    prefixes = {"tls": "tls://", "https": "https://", "quic": "quic://"}
    return server if server.startswith(("tls://", "https://", "quic://")) else prefixes[transport] + server


def _dns_environment(rrtype: str) -> dict[str, str]:
    env = os.environ.copy()
    for name in ("VERIFY", "SUBNET", "PAD", "DNSSEC", "HTTP3", "CLASS", "EDNSOPT", "VERBOSE"):
        env.pop(name, None)
    env.update({"JSON": "1", "RRTYPE": rrtype, "TIMEOUT": str(DNS_TIMEOUT_SECONDS)})
    return env


def _collect_dns_one(box: ToolBox, evidence: list[dict[str, Any]], target: dict[str, Any],
                     target_index: int, rrtype: str, dns_server: str | None,
                     dns_transport: str, output: Path) -> None:
    started, mono = utc_now(), time.monotonic()
    scope = {"target": redact_url(str(target["url"])), "hostname": target["hostname"],
             "address_family": "IPv4" if rrtype == "A" else "IPv6",
             "protocol": dns_transport if dns_server else "system_default_unknown", "window": None}
    executable = box.executables.get("dnslookup")
    if executable is None:
        record = _new_evidence(evidence, "dns_query", "dnslookup", None, "unsupported", scope,
                               {"rrtype": rrtype, "resolver": dns_server or "system_default_unknown",
                                "transport": dns_transport if dns_server else "system_default_unknown",
                                "answers": [], "rcode": None, "measurement": None}, started, mono,
                               measurements=[measurement("query_elapsed_ms", None, "ms", 0,
                                                         missing_reason="dnslookup executable is unavailable")],
                               sources=[{"kind": "inline"}],
                               failure={"kind": "tool_missing", "reason": "dnslookup executable is unavailable"})
        return
    if box.deadline.remaining() <= 0:
        _new_evidence(evidence, "dns_query", "dnslookup", box.versions.get("dnslookup"), "budget_exhausted", scope,
                      {"rrtype": rrtype, "resolver": dns_server or "system_default_unknown",
                       "transport": dns_transport if dns_server else "system_default_unknown",
                       "answers": [], "rcode": None}, started, mono,
                      measurements=[measurement("query_elapsed_ms", None, "ms", 0, missing_reason="shared live budget exhausted")],
                      sources=[{"kind": "inline"}], failure={"kind": "budget", "reason": "shared live budget exhausted"})
        return
    server_arg = _dns_server(dns_server, dns_transport)
    args = [executable, str(target["hostname"])]
    if server_arg:
        args.append(server_arg)
    result = box.run("dnslookup", args, f"DNS {rrtype} query", 131072, 16384,
                     timeout_seconds=DNS_TIMEOUT_SECONDS, env=_dns_environment(rrtype),
                     safe_command=[Path(executable).name, str(target["hostname"]),
                                   server_arg if server_arg else "<system-resolver>"], network_request=True)
    file = output / "raw" / f"dns_target_{target_index}_{rrtype}.json"
    file.write_bytes(result.stdout)
    source = relative_artifact(output, file)
    document = None
    parse_error = None
    try:
        document = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        parse_error = "dnslookup did not return valid JSON"
    rcode, answers, elapsed_ns = _dns_answers(document)
    status = result.status
    if result.returncode not in (0, None) and status == "complete":
        status = "tool_error"
    if parse_error and status == "complete":
        status = "parse_error"
    stderr_file = output / "raw" / f"dns_target_{target_index}_{rrtype}.stderr.txt"
    safe_stderr = redact_text(result.stderr.decode("utf-8", "replace"))
    stderr_file.write_text(safe_stderr, encoding="utf-8")
    sources.append(relative_artifact(output, stderr_file)) if (sources := [source]) else None
    observation = {
        "rrtype": rrtype,
        "resolver": dns_server or "system_default_unknown",
        "transport": dns_transport if dns_server else "system_default_unknown",
        "answers": answers,
        "rcode": rcode,
        "elapsed_ns": elapsed_ns,
        "raw_output_json": str(file.relative_to(output).as_posix()),
        "parse_error": parse_error,
    }
    _new_evidence(evidence, "dns_query", "dnslookup", box.versions.get("dnslookup"), status, scope,
                  observation, started, mono,
                  measurements=[measurement("query_elapsed_ms", round(elapsed_ns / 1_000_000, 3) if elapsed_ns is not None else None,
                                            "ms", 1 if elapsed_ns is not None else 0,
                                            missing_reason=None if elapsed_ns is not None else "elapsed time is not present in structured response")],
                  sources=sources,
                  failure={"kind": "parse_error", "reason": parse_error} if parse_error else None)


def _ping_counts(text: str, system: str, requested: int) -> tuple[int | None, int | None, list[str]]:
    sent: int | None = None
    received: int | None = None
    patterns = [
        (r"(\d+) packets transmitted,\s*(\d+) (?:packets )?received", "linux_summary"),
        (r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+)", "windows_summary"),
        (r"\u5df2\u53d1\u9001\s*[=:]\s*(\d+).*?\u5df2\u63a5\u6536\s*[=:]\s*(\d+)", "windows_chinese_summary"),
    ]
    for pattern, label in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            sent, received = int(match.group(1)), int(match.group(2))
            return sent, received, [label]
    reply_patterns = (r"bytes from", r"Reply from.*(?:bytes=|bytes )",
                      r"\u6765\u81ea.+?\u7684\u56de\u590d", r"\u6765\u81ea.+?\u5b57\u8282")
    reply_lines = [line for line in text.splitlines()
                   if any(re.search(pattern, line, re.IGNORECASE) for pattern in reply_patterns)]
    found = [pattern for pattern in reply_patterns if any(re.search(pattern, line, re.IGNORECASE) for line in reply_lines)]
    if reply_lines:
        received = len(reply_lines)
    return sent, received, found


def _ping_samples(text: str) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    sequence: int | None = None
    for line in text.splitlines():
        seq_match = re.search(r"icmp_seq[= ](\d+)", line, re.IGNORECASE)
        if seq_match:
            sequence = int(seq_match.group(1))
        is_reply = bool(re.search(r"bytes from|Reply from.*(?:bytes=|bytes )|\u6765\u81ea.+?\u7684\u56de\u590d", line, re.IGNORECASE))
        if not is_reply:
            continue
        time_match = re.search(r"(?:time|\u65f6\u95f4)\s*[=<]\s*<?\s*(\d+(?:[.,]\d+)?)\s*(ms|msec|s)?", line, re.IGNORECASE)
        rtt_ms: float | None = None
        approximate = False
        if time_match:
            try:
                rtt_ms = float(time_match.group(1).replace(",", "."))
                if (time_match.group(2) or "ms").lower() == "s":
                    rtt_ms *= 1000
                approximate = "<" in line
            except ValueError:
                rtt_ms = None
        samples.append({"sequence": sequence, "reply_observed": True,
                        "rtt_ms": rtt_ms, "rtt_is_upper_bound": approximate})
        sequence = None
    return samples


def _ping_command(executable: str, address: str, system: str) -> list[str]:
    if system == "Windows":
        return [executable, "-n", str(PING_SAMPLES), "-w", "1000", address]
    return [executable, "-n", "-c", str(PING_SAMPLES), "-i", "1", "-W", "1", address]


def _collect_ping(box: ToolBox, evidence: list[dict[str, Any]], address: str,
                  roles: list[str], output: Path) -> None:
    started, mono = utc_now(), time.monotonic()
    system = platform.system()
    scope = {"target": address, "hostname": None, "address_family": "IPv6" if ":" in address else "IPv4",
             "protocol": "ICMP", "window": None, "roles": sorted(set(roles))}
    executable = box.executables.get("ping")
    if not executable:
        _new_evidence(evidence, "ping", "ping", None, "unsupported", scope,
                      {"requested_samples": PING_SAMPLES, "sent": None, "received": None,
                       "sample_scope": "one ICMP echo request per one-second interval", "reply_lines": []},
                      started, mono,
                      measurements=[measurement("received_samples", None, "probes", 0, missing_reason="ping executable is unavailable")],
                      sources=[{"kind": "inline"}], failure={"kind": "tool_missing", "reason": "ping executable is unavailable"})
        return
    if box.deadline.remaining() <= 0:
        _new_evidence(evidence, "ping", "ping", box.versions.get("ping"), "budget_exhausted", scope,
                      {"requested_samples": PING_SAMPLES, "sent": None, "received": None,
                       "sample_scope": "one ICMP echo request per one-second interval"}, started, mono,
                      measurements=[measurement("received_samples", None, "probes", 0, missing_reason="shared live budget exhausted")],
                      sources=[{"kind": "inline"}], failure={"kind": "budget", "reason": "shared live budget exhausted"})
        return
    args = _ping_command(executable, address, system)
    result = box.run("ping", args, "finite ICMP samples", 32768, 8192,
                     timeout_seconds=min(11.5, box.deadline.remaining()),
                     safe_command=[Path(executable).name, *args[1:]], network_request=True)
    text = (result.stdout + b"\n" + result.stderr).decode("utf-8", "replace")
    sent, received, parse_hints = _ping_counts(text, system, PING_SAMPLES)
    rtt_samples = _ping_samples(text)
    parsed_replies = sum(1 for sample in rtt_samples if sample["reply_observed"])
    if received is None and parsed_replies:
        received = parsed_replies
        parse_hints.append("reply_lines_observed")
    elif received is not None:
        parse_hints.append("summary_counts")
    status = result.status
    lowered = text.lower()
    if any(word in lowered for word in ("operation not permitted", "permission denied", "requires elevation", "access denied")):
        status = "permission_denied"
    elif result.returncode not in (0, 1, None) and status == "complete":
        status = "tool_error"
    file = output / "raw" / f"ping_{re.sub(r'[^A-Za-z0-9_.-]', '_', address)}.txt"
    file.write_text(text[:32768], encoding="utf-8")
    source = relative_artifact(output, file)
    rtt_values = [sample["rtt_ms"] for sample in rtt_samples if sample.get("rtt_ms") is not None]
    if rtt_values:
        rtt_min, rtt_median, rtt_max = min(rtt_values), statistics.median(rtt_values), max(rtt_values)
        rtt_range = rtt_max - rtt_min
    else:
        rtt_min = rtt_median = rtt_max = rtt_range = None
    failure = None
    if status == "permission_denied":
        failure = {"kind": "permission_denied", "reason": "ICMP permission was not available"}
    elif status not in ("complete", "partial"):
        failure = {"kind": status, "reason": result.error_kind or status}
    _new_evidence(evidence, "ping", "ping", box.versions.get("ping"), status, scope,
                  {"requested_samples": PING_SAMPLES, "sent": sent, "received": received,
                   "sample_scope": "one ICMP echo request per one-second interval",
                   "received_count_scope": "parsed_summary" if "summary_counts" in parse_hints else "reply_lines_observed_lower_bound",
                   "rtt_samples": rtt_samples[:PING_SAMPLES],
                   "reply_parse_hints": parse_hints,
                   "returncode": result.returncode}, started, mono,
                  measurements=[
                      measurement("sent_samples", sent, "probes", sent or 0,
                                  missing_reason=None if sent is not None else "ping output did not provide an actual sent-count summary"),
                      measurement("received_samples", received, "probes", received or 0,
                                  missing_reason=None if received is not None else "ping reply count could not be parsed"),
                      measurement("rtt_min_ms", round(rtt_min, 3) if rtt_min is not None else None, "ms", len(rtt_values),
                                  raw_values=rtt_values, missing_reason=None if rtt_min is not None else "no RTT sample was parsed"),
                      measurement("rtt_median_ms", round(rtt_median, 3) if rtt_median is not None else None, "ms", len(rtt_values),
                                  raw_values=rtt_values, missing_reason=None if rtt_median is not None else "no RTT sample was parsed"),
                      measurement("rtt_max_ms", round(rtt_max, 3) if rtt_max is not None else None, "ms", len(rtt_values),
                                  raw_values=rtt_values, missing_reason=None if rtt_max is not None else "no RTT sample was parsed"),
                      measurement("rtt_range_ms", round(rtt_range, 3) if rtt_range is not None else None, "ms", len(rtt_values),
                                  raw_values=rtt_values, missing_reason=None if rtt_range is not None else "no RTT sample was parsed"),
                  ],
                  sources=[source], failure=failure)


def _probe_target(box: ToolBox, evidence: list[dict[str, Any]], target: dict[str, Any],
                  target_index: int, output: Path, proxy: dict[str, Any],
                  ping_pool: concurrent.futures.ThreadPoolExecutor,
                  ping_jobs: dict[str, dict[str, Any]],
                  ping_lock: threading.Lock, http_allowed: bool) -> None:
    safe_target = redact_url(str(target["url"]))
    role = "target" if target_index == 1 else "control"
    ping_role = "connected_target" if target_index == 1 else "connected_control"
    remote_ip_for_ping: str | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        started, mono = utc_now(), time.monotonic()
        scope = {"target": safe_target, "target_role": role, "target_index": target_index,
                 "hostname": target["hostname"], "address_family": target["address_family"],
                 "protocol": str(target["protocol"]), "window": None, "attempt": attempt}
        if box.deadline.remaining() <= 0:
            _new_evidence(evidence, "http_probe", "curl", box.versions.get("curl"), "budget_exhausted", scope,
                          {"method": "GET", "outcome": "not_executed", "reason": "shared live budget exhausted"},
                          started, mono, measurements=[measurement("total_ms", None, "ms", 0, missing_reason="request not started")],
                          sources=[{"kind": "inline"}], failure={"kind": "budget", "reason": "shared live budget exhausted"})
            continue
        executable = box.executables.get("curl")
        if not executable:
            _new_evidence(evidence, "http_probe", "curl", None, "unsupported", scope,
                          {"method": "GET", "outcome": "not_executed", "reason": "curl executable unavailable"},
                          started, mono, measurements=[measurement("total_ms", None, "ms", 0, missing_reason="curl executable unavailable")],
                          sources=[{"kind": "inline"}], failure={"kind": "tool_missing", "reason": "curl executable unavailable"})
            break
        timeout = max(1, min(6, int(box.deadline.remaining())))
        args = _curl_command(executable, str(target["url"]), http_allowed, timeout)
        env, _ = _curl_env(str(target["url"]))
        safe = [Path(executable).name, "-q", "--silent", "--show-error", "--request", "GET",
                "--connect-timeout", "3", "--max-time", str(timeout), "--max-filesize", str(BODY_LIMIT),
                "--max-redirs", "0", "--retry", "0", "--url", safe_target]
        result = box.run("curl", args, f"HTTP attempt {attempt}", BODY_LIMIT, 16384,
                         timeout_seconds=timeout + 0.25, env=env, safe_command=safe, network_request=True)
        body_path = output / "raw" / f"http_target_{target_index}_attempt_{attempt}.body"
        body_path.write_bytes(result.stdout)
        body_source = relative_artifact(output, body_path)
        safe_stderr = redact_text(result.stderr.decode("utf-8", "replace"), [str(target["url"])])
        stderr_path = output / "raw" / f"http_target_{target_index}_attempt_{attempt}.stderr.txt"
        stderr_path.write_text(safe_stderr[:16384], encoding="utf-8")
        stderr_source = relative_artifact(output, stderr_path)
        meta = _parse_writeout(result.stderr)
        outcome, status = _curl_failure_kind(result, meta, result.stdout_truncated)
        http_code = _int(meta.get("http_status")) if meta else None
        remote_ip = meta.get("remote_ip") if meta and meta.get("remote_ip") else None
        connected_ip = remote_ip if remote_ip and not proxy["configured"] else None
        if connected_ip and remote_ip_for_ping is None:
            remote_ip_for_ping = connected_ip
            with ping_lock:
                if connected_ip in ping_jobs:
                    ping_jobs[connected_ip]["roles"].add(ping_role)
                elif len(ping_jobs) < 3:
                    roles = {ping_role}
                    future = ping_pool.submit(_collect_ping, box, evidence, connected_ip, roles, output)
                    ping_jobs[connected_ip] = {"future": future, "roles": roles}
        if meta and http_code is not None and http_code >= 500:
            outcome = "http_5xx"
        elif meta and http_code is not None and 300 <= http_code < 400:
            outcome = "redirect_response_not_followed"
        new_connections = _int(meta.get("new_connections")) if meta else None
        http_version = meta.get("http_version") if meta else None
        direct = not proxy["configured"] and connected_ip is not None and new_connections == 1 and http_version != "3"
        transfer_complete = result.status == "complete" and result.returncode == 0 and not result.stdout_truncated
        body_complete = transfer_complete
        measurements = [measurement("body_bytes_retained", len(result.stdout), "bytes", 1,
                                    missing_reason=None if result.stdout else "empty body or no response body")]
        measurements.extend(_stage_measurements(meta, direct, body_complete, str(target["scheme"])) if meta else
                            [measurement("curl_stage_ms", None, "ms", 0, missing_reason="curl timing metadata unavailable")])
        timing = {
            key: _float(meta.get(name)) if meta else None
            for key, name in (("dns_seconds", "dns_seconds"), ("connect_seconds", "connect_seconds"),
                              ("tls_seconds", "tls_seconds"), ("pretransfer_seconds", "pretransfer_seconds"),
                              ("first_byte_seconds", "first_byte_seconds"),
                              ("total_seconds", "total_seconds"))
        }
        if meta and timing["total_seconds"] is not None:
            measurements.append(measurement("total_ms", round(timing["total_seconds"] * 1000, 3), "ms", 1,
                                            raw_values=[timing["total_seconds"] * 1000]))
        else:
            measurements.append(measurement("total_ms", None, "ms", 0, missing_reason="curl did not complete timing output"))
        obs = {
            "method": "GET",
            "outcome": outcome,
            "http_status": http_code,
            "remote_ip": remote_ip,
            "connected_ip": connected_ip,
            "address_family": "IPv6" if connected_ip and ":" in connected_ip else "IPv4" if connected_ip else None,
            "http_version": http_version,
            "fresh_connection": new_connections == 1 if new_connections is not None else None,
            "proxy_configured": proxy["configured"],
            "proxy_use": "unknown" if proxy["configured"] else "no_proxy_environment_detected",
            "redirect_followed": False,
            "body_bytes_retained": len(result.stdout),
            "body_truncated": result.stdout_truncated or outcome == "body_limit",
            "transfer_complete": transfer_complete,
            "timings_seconds": timing,
            "curl_returncode": result.returncode,
            "error_summary": safe_stderr.strip()[:500] or None,
        }
        failure = None
        if outcome in ("tls_error", "dns_error", "connection_error", "proxy_error", "timeout", "http_5xx"):
            failure = {"kind": outcome, "reason": safe_stderr.strip()[:400] or outcome}
        _new_evidence(evidence, "http_probe", "curl", box.versions.get("curl"), status, scope,
                      obs, started, mono, measurements, [body_source, stderr_source], failure)
    # Keep the address assigned to this target for the final run summary; pings are launched on the first response.


def _dns_task(box: ToolBox, evidence: list[dict[str, Any]], target: dict[str, Any],
              target_index: int, output: Path, dns_server: str | None,
              dns_transport: str) -> None:
    for rrtype in ("A", "AAAA"):
        _collect_dns_one(box, evidence, target, target_index, rrtype, dns_server, dns_transport, output)


def collect_live(targets: list[dict[str, Any]], output: Path,
                 deadline: Deadline, allow_http: bool,
                 dns_server: str | None = None, dns_transport: str = "udp") -> dict[str, Any]:
    """Collect live evidence under one shared deadline; this function does not diagnose."""
    run_started_at_utc = utc_now()
    evidence: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    box = ToolBox(deadline)
    box.discover_versions(live=True)
    proxy = _proxy_context()
    context = collect_context(box, evidence, proxy)
    ping_jobs: dict[str, dict[str, Any]] = {}
    ping_lock = threading.Lock()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ping_pool, \
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as http_pool, \
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as dns_pool:
        default_gateway = context.get("default_route", {}).get("default_gateway")
        if default_gateway:
            roles = {"default_gateway"}
            future = ping_pool.submit(_collect_ping, box, evidence, default_gateway, roles, output)
            ping_jobs[default_gateway] = {"future": future, "roles": roles}
        dns_futures = [dns_pool.submit(_dns_task, box, evidence, target, index, output,
                                       dns_server, dns_transport)
                       for index, target in enumerate(targets, 1)]
        http_futures = [http_pool.submit(_probe_target, box, evidence, target, index,
                                         output, proxy, ping_pool, ping_jobs, ping_lock, allow_http)
                        for index, target in enumerate(targets, 1)]
        for future in concurrent.futures.as_completed(http_futures):
            try:
                future.result()
            except Exception as error:
                _append_failure(failures, "http_collection", None, type(error).__name__, "tool_error")
        for future in concurrent.futures.as_completed(dns_futures):
            try:
                future.result()
            except Exception as error:
                _append_failure(failures, "dns_collection", None, type(error).__name__, "tool_error")
        for job in list(ping_jobs.values()):
            try:
                job["future"].result(timeout=max(0.1, deadline.remaining() + 1.0))
            except concurrent.futures.TimeoutError:
                _append_failure(failures, "ping_collection", None, "shared live budget exhausted", "budget_exhausted")
            except Exception as error:
                _append_failure(failures, "ping_collection", None, type(error).__name__, "tool_error")
    actual_http_requests = sum(1 for item in box.calls if item["tool"] == "curl" and item["purpose"].startswith("HTTP attempt") and item["network_request_started"])
    actual_dns_requests = sum(1 for item in box.calls if item["tool"] == "dnslookup" and item["purpose"].startswith("DNS") and item["network_request_started"])
    actual_ping_requests = sum(1 for item in box.calls if item["tool"] == "ping" and item["purpose"] == "finite ICMP samples" and item["network_request_started"])
    if actual_http_requests > 6 or actual_dns_requests > 4 or actual_ping_requests > 3:
        failures.append({"kind": "internal_budget", "target": None, "status": "tool_error", "reason": "configured call bound exceeded"})
    return {
        "evidence": evidence,
        "failures": failures,
        "capabilities": box.discovery,
        "tool_versions": box.versions,
        "calls": box.calls,
        "call_counts": {"subprocesses": len(box.calls), "http_requests": actual_http_requests,
                        "dns_queries": actual_dns_requests, "ping_commands": actual_ping_requests,
                        "logical_ping_probes_requested": actual_ping_requests * PING_SAMPLES},
        "context": context,
        "proxy": proxy,
        "scope": {"targets": [{"url": redact_url(str(target["url"])), "target_role": "target" if index == 1 else "control",
                                  "target_index": index, "hostname": target["hostname"],
                                  "protocol": target["protocol"], "address_family": target["address_family"]}
                                 for index, target in enumerate(targets, 1)],
                  "control_target_configured": len(targets) > 1,
                  "request_method": "GET", "max_attempts_per_target": MAX_ATTEMPTS,
                  "max_concurrent_http_requests": 2,
                  "window_started_at_utc": run_started_at_utc,
                  "window_ended_at_utc": utc_now(),
                  "window_deadline_seconds": 23, "finish_reserve_seconds": 2},
    }
