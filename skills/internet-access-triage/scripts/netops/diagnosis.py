"""Conservative four-state diagnosis from normalized observations only."""

from __future__ import annotations

import math
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any

from .contract import DIAGNOSIS_STATUSES, EVIDENCE_ID


MODES = {"live", "offline_pcap", "replay"}
HTTP_PROTOCOLS = {"HTTP", "HTTPS"}
FAMILIES = {"IPv4", "IPv6"}
FAULTS = {
    "tls_error": ("tls_validation", 60,
                  "The target request failed TLS validation (curl exit 60); this does not identify who controls the certificate path."),
    "dns_error": ("name_resolution", 6,
                  "The target request reported a name-resolution failure (curl exit 6); this does not identify resolver processing or responsibility."),
    "connection_error": ("transport_connection", 7,
                         "The target request reported a connection failure (curl exit 7); responsibility for the path remains unresolved."),
}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _safe_id(record: dict[str, Any]) -> str | None:
    value = record.get("id")
    return value if isinstance(value, str) and EVIDENCE_ID.fullmatch(value) else None


def _unique_ids(records: list[dict[str, Any]]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for record in records:
        evidence_id = _safe_id(record)
        if evidence_id is not None and evidence_id not in seen:
            result.append(evidence_id)
            seen.add(evidence_id)
    return result


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _window_bounds(scope: dict[str, Any]) -> tuple[datetime, datetime, str] | None:
    start_value = scope.get("window_started_at_utc")
    end_value = scope.get("window_ended_at_utc")
    window = _mapping(scope.get("window"))
    if start_value is None:
        start_value = window.get("started_at_utc", window.get("start_utc"))
    if end_value is None:
        end_value = window.get("ended_at_utc", window.get("end_utc"))
    start = _parse_utc(start_value)
    end = _parse_utc(end_value)
    if start is None:
        return None
    if end is None:
        duration = scope.get("window_deadline_seconds")
        if isinstance(duration, bool) or not isinstance(duration, (int, float)) or not math.isfinite(duration) or duration <= 0:
            return None
        end = start + timedelta(seconds=float(duration))
    if end < start:
        return None
    window_id = _string(scope.get("comparison_window_id")) or _string(scope.get("run_id"))
    if window_id is None:
        window_id = f"{start.isoformat()}..{end.isoformat()}"
    return start, end, window_id


def _record_interval(record: dict[str, Any]) -> tuple[datetime, datetime] | None:
    record_scope = _mapping(record.get("scope"))
    explicit = record_scope.get("window")
    if isinstance(explicit, dict):
        start = _parse_utc(explicit.get("started_at_utc", explicit.get("start_utc", explicit.get("start"))))
        end = _parse_utc(explicit.get("ended_at_utc", explicit.get("end_utc", explicit.get("end"))))
        if start is None or end is None or end < start:
            return None
        return start, end
    if isinstance(explicit, str):
        for separator in ("..", "/"):
            if separator in explicit:
                start_text, end_text = explicit.split(separator, 1)
                start, end = _parse_utc(start_text), _parse_utc(end_text)
                if start is not None and end is not None and end >= start:
                    return start, end
        return None

    start = _parse_utc(record.get("started_at_utc"))
    duration = record.get("duration_ns")
    if start is None or isinstance(duration, bool) or not isinstance(duration, int) or duration < 0:
        return None
    return start, start + timedelta(microseconds=duration / 1000)


def _in_run_window(record: dict[str, Any], run_scope: dict[str, Any], bounds: tuple[datetime, datetime, str] | None) -> bool:
    if bounds is None:
        return False
    record_scope = _mapping(record.get("scope"))
    run_id = _string(run_scope.get("comparison_window_id")) or _string(run_scope.get("run_id"))
    record_run_id = _string(record_scope.get("comparison_window_id")) or _string(record_scope.get("run_id"))
    expected_run_id = run_id or bounds[2]
    if record_run_id is not None and record_run_id != expected_run_id:
        return False
    interval = _record_interval(record)
    if interval is None:
        return False
    start, end, _ = bounds
    return interval[0] >= start and interval[1] <= end


def _target_specs(scope: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    targets = scope.get("targets")
    if not isinstance(targets, list):
        return None, None
    primary = _mapping(targets[0]) if targets else None
    control = _mapping(targets[1]) if len(targets) > 1 else None
    return primary, control


def _protocol(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value.upper()


def _family_value(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized in ("ipv4", "4"):
        return "IPv4"
    if normalized in ("ipv6", "6"):
        return "IPv6"
    return None


def _record_family(record: dict[str, Any]) -> str | None:
    record_scope = _mapping(record.get("scope"))
    observation = _mapping(record.get("observation"))
    scoped = _family_value(record_scope.get("address_family"))
    observed = _family_value(observation.get("address_family"))
    if scoped is not None and observed is not None and scoped != observed:
        return None
    return observed or scoped


def _record_role(record: dict[str, Any], target_url: str | None,
                 control_url: str | None) -> str | None:
    record_scope = _mapping(record.get("scope"))
    record_url = _string(record_scope.get("target"))
    role = record_scope.get("target_role")
    if role == "target":
        return "target" if target_url is not None and record_url == target_url else None
    if role == "control":
        return "control" if control_url is not None and record_url == control_url else None
    if target_url is not None and control_url is not None and target_url == control_url:
        return None
    if target_url is not None and record_url == target_url:
        return "target"
    if control_url is not None and record_url == control_url:
        return "control"
    return None


def _record_matches_protocol(record: dict[str, Any], expected: Any) -> bool:
    record_protocol = _protocol(_mapping(record.get("scope")).get("protocol"))
    expected_protocol = _protocol(expected)
    return record_protocol is not None and (expected_protocol is None or record_protocol == expected_protocol)


def _record_matches_family(record: dict[str, Any], expected: Any) -> bool:
    record_scope = _mapping(record.get("scope"))
    observation = _mapping(record.get("observation"))
    scoped = _family_value(record_scope.get("address_family"))
    observed = _family_value(observation.get("address_family"))
    if scoped is not None and observed is not None and scoped != observed:
        return False
    actual = observed or scoped
    expected_family = _family_value(expected)
    return actual is None or expected_family is None or actual == expected_family


def _status(record: dict[str, Any]) -> str | None:
    value = record.get("status")
    return value if isinstance(value, str) else None


def _outcome(record: dict[str, Any]) -> str | None:
    value = _mapping(record.get("observation")).get("outcome")
    return value if isinstance(value, str) else None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _finite(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _measurement_value(record: dict[str, Any], name: str) -> float | None:
    measurements = record.get("measurements")
    if not isinstance(measurements, list):
        return None
    matches = [item for item in measurements if isinstance(item, dict) and item.get("name") == name]
    if len(matches) != 1:
        return None
    measurement = matches[0]
    sample_count = measurement.get("sample_count")
    value = measurement.get("value")
    if (measurement.get("unit") != "ms" or not isinstance(sample_count, int)
            or isinstance(sample_count, bool) or sample_count < 1 or not _finite(value) or value < 0):
        return None
    return float(value)


def _http_status(record: dict[str, Any]) -> int | None:
    value = _mapping(record.get("observation")).get("http_status")
    return value if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599 else None


def _complete_http_response(record: dict[str, Any]) -> bool:
    if _status(record) != "complete" or _http_status(record) is None:
        return False
    observation = _mapping(record.get("observation"))
    if _outcome(record) not in {"response", "http_5xx", "redirect_response_not_followed"}:
        return False
    return observation.get("transfer_complete") is True or _int(observation.get("curl_returncode")) == 0


def _http_success(record: dict[str, Any]) -> bool:
    status_code = _http_status(record)
    return (_complete_http_response(record) and status_code is not None
            and 200 <= status_code < 300 and _outcome(record) == "response")


def _http_fault(record: dict[str, Any]) -> tuple[str, str] | None:
    observation = _mapping(record.get("observation"))
    outcome = _outcome(record)
    status = _status(record)
    curl_code = _int(observation.get("curl_returncode"))
    failure = _mapping(record.get("failure"))
    failure_kind = failure.get("kind")
    if failure_kind is not None and not isinstance(failure_kind, str):
        return None

    status_code = _http_status(record)
    if (status_code is not None and status_code >= 500 and _complete_http_response(record)
            and outcome == "http_5xx"):
        return "http_service_response", "The completed target request returned an HTTP 5xx response."

    if outcome == "timeout" and curl_code == 28 and status in {"complete", "timeout"}:
        if failure_kind not in (None, "timeout"):
            return None
        return "request_timeout", "Curl exit 28 records a request timeout; a collection budget expiry alone is not treated as a business failure."

    for known_outcome, (domain, expected_code, basis) in FAULTS.items():
        if outcome == known_outcome and curl_code == expected_code and status == "complete":
            if failure_kind not in (None, known_outcome):
                return None
            return domain, basis
    return None


def _context_key(record: dict[str, Any], run_window_id: str | None) -> tuple[str, str, str, str] | None:
    record_scope = _mapping(record.get("scope"))
    target = _string(record_scope.get("target"))
    protocol = _protocol(record_scope.get("protocol"))
    family = _record_family(record)
    if target is None or protocol is None or family is None or run_window_id is None:
        return None
    return target, protocol, family, run_window_id


def _fault_context_key(record: dict[str, Any], run_window_id: str | None) -> tuple[str, str, str, str] | None:
    """Keep directly observed faults even when the actual address family is unknown."""
    record_scope = _mapping(record.get("scope"))
    target = _string(record_scope.get("target"))
    protocol = _protocol(record_scope.get("protocol"))
    if target is None or protocol is None or run_window_id is None:
        return None
    family = _record_family(record) or "unknown"
    return target, protocol, family, run_window_id


def _numeric_baseline(value: Any) -> float | None:
    if not _finite(value) or value < 0:
        return None
    return float(value)


def _candidate(domain: str, basis: str, records: list[dict[str, Any]],
               counter_records: list[dict[str, Any]], next_step: str) -> dict[str, Any] | None:
    evidence_ids = _unique_ids(records)
    if not evidence_ids:
        return None
    counter_ids = [value for value in _unique_ids(counter_records) if value not in set(evidence_ids)]
    return {
        "domain": domain,
        "basis": basis,
        "evidence_ids": evidence_ids,
        "counterevidence_ids": counter_ids,
        "next_step": next_step,
    }


def _same_context_controls(control_records: list[dict[str, Any]], target_record: dict[str, Any],
                           run_window_id: str | None) -> list[dict[str, Any]]:
    target_key = _fault_context_key(target_record, run_window_id)
    if target_key is None:
        return []
    target_context = target_key[1:]
    return [record for record in control_records
            if _fault_context_key(record, run_window_id) is not None
            and _fault_context_key(record, run_window_id)[1:] == target_context]


def _group_measurements(records: list[dict[str, Any]], name: str,
                        run_window_id: str | None) -> dict[tuple[str, str, str, str], list[tuple[dict[str, Any], float]]]:
    groups: dict[tuple[str, str, str, str], list[tuple[dict[str, Any], float]]] = {}
    for record in records:
        if not _complete_http_response(record):
            continue
        key = _context_key(record, run_window_id)
        value = _measurement_value(record, name)
        if key is not None and value is not None:
            groups.setdefault(key, []).append((record, value))
    return groups


def _dns_latency_groups(records: list[dict[str, Any]], target_url: str | None,
                        run_scope: dict[str, Any], bounds: tuple[datetime, datetime, str] | None,
                        run_window_id: str | None) -> dict[tuple[str, str, str, str, str], list[tuple[dict[str, Any], float]]]:
    groups: dict[tuple[str, str, str, str, str], list[tuple[dict[str, Any], float]]] = {}
    if target_url is None or run_window_id is None:
        return groups
    for record in records:
        if not isinstance(record, dict) or record.get("kind") != "dns_query" or _status(record) != "complete":
            continue
        if not _safe_id(record) or not _in_run_window(record, run_scope, bounds):
            continue
        record_scope = _mapping(record.get("scope"))
        observation = _mapping(record.get("observation"))
        if record_scope.get("target") != target_url:
            continue
        family = _family_value(record_scope.get("address_family"))
        resolver = _string(observation.get("resolver"))
        transport = _string(observation.get("transport")) or _string(record_scope.get("protocol"))
        if family is None or resolver is None or transport is None:
            continue
        value = _measurement_value(record, "query_elapsed_ms")
        if value is None:
            continue
        key = (target_url, family, resolver.lower(), transport.lower(), run_window_id)
        groups.setdefault(key, []).append((record, value))
    return groups


def _timestamp_field(phase: dict[str, Any], name: str) -> datetime | None:
    return _parse_utc(phase.get(name))


def _phase_samples(phase: dict[str, Any], metric: str) -> list[float] | None:
    values = phase.get(metric)
    if not isinstance(values, list) or len(values) < 3:
        return None
    if any(not _finite(value) or value < 0 for value in values):
        return None
    return [float(value) for value in values]


def _load_comparison(record: dict[str, Any], target_url: str | None,
                     target_protocol: Any, target_family: Any,
                     bounds: tuple[datetime, datetime, str] | None) -> tuple[str, str] | None:
    if _status(record) != "complete" or not _safe_id(record):
        return None
    if bounds is None:
        return None
    comparison_window = _record_interval(record)
    if comparison_window is None:
        return None
    run_start, run_end, _ = bounds
    if comparison_window[0] < run_start or comparison_window[1] > run_end:
        return None
    record_scope = _mapping(record.get("scope"))
    observation = _mapping(record.get("observation"))
    vantage = _string(record_scope.get("vantage"))
    comparison_protocol = _protocol(record_scope.get("protocol"))
    comparison_family = _record_family(record)
    if (target_url is None or record_scope.get("target") != target_url or vantage is None
            or not _record_matches_protocol(record, target_protocol)
            or not _record_matches_family(record, target_family)
            or comparison_protocol is None or comparison_family is None):
        return None

    cycles = observation.get("cycles")
    if not isinstance(cycles, list) or len(cycles) != 2:
        return None
    ordered_windows: list[tuple[datetime, datetime]] = []
    all_phases: list[list[dict[str, Any]]] = []
    for cycle in cycles:
        if not isinstance(cycle, dict):
            return None
        phases = cycle.get("phases")
        if not isinstance(phases, list) or len(phases) != 3:
            return None
        phase_names = [phase.get("name") if isinstance(phase, dict) else None for phase in phases]
        if phase_names != ["idle", "load", "recovery"]:
            return None
        parsed_phases: list[dict[str, Any]] = []
        prior_end: datetime | None = None
        for phase in phases:
            assert isinstance(phase, dict)
            if phase.get("vantage") != vantage:
                return None
            if phase.get("target", target_url) != target_url:
                return None
            if _protocol(phase.get("protocol", comparison_protocol)) != comparison_protocol:
                return None
            if _family_value(phase.get("address_family", comparison_family)) != comparison_family:
                return None
            start = _timestamp_field(phase, "started_at_utc")
            end = _timestamp_field(phase, "ended_at_utc")
            if start is None or end is None or end <= start or (prior_end is not None and start < prior_end):
                return None
            if (start < comparison_window[0] or end > comparison_window[1]
                    or start < run_start or end > run_end):
                return None
            prior_end = end
            parsed_phases.append(phase)
        ordered_windows.append((_timestamp_field(parsed_phases[0], "started_at_utc"),
                                _timestamp_field(parsed_phases[2], "ended_at_utc")))  # type: ignore[arg-type]
        all_phases.append(parsed_phases)

    if ordered_windows[1][0] <= ordered_windows[0][1]:
        return None
    for phases in all_phases:
        load_phase = phases[1]
        uploaded_bytes = load_phase.get("uploaded_bytes")
        duration_ms = load_phase.get("duration_ms")
        rate = load_phase.get("upload_rate_bytes_per_s")
        byte_activity = (_int(uploaded_bytes) is not None and uploaded_bytes > 0
                         and _finite(duration_ms) and duration_ms > 0)
        rate_activity = _finite(rate) and rate > 0
        if not (byte_activity or rate_activity):
            return None

    for metric in ("response_wait_ms", "rtt_ms"):
        samples = [[_phase_samples(phase, metric) for phase in phases] for phases in all_phases]
        if any(any(phase_samples is None for phase_samples in cycle_samples) for cycle_samples in samples):
            continue
        medians = [[statistics.median(phase_samples) for phase_samples in cycle_samples
                    if phase_samples is not None] for cycle_samples in samples]
        if all(cycle[1] > cycle[0] and cycle[2] < cycle[1] for cycle in medians):
            return metric, "Both ordered idle/load/recovery cycles show the same measured latency increase during recorded upload activity and a decrease during recovery. This is correlation only; it does not confirm bufferbloat, a queue, or responsibility."
    return None


def _load_candidate(evidence: list[dict[str, Any]], target_url: str | None,
                    target_protocol: Any, target_family: Any,
                    mode: str, run_scope: dict[str, Any],
                    bounds: tuple[datetime, datetime, str] | None) -> list[dict[str, Any]]:
    if mode != "replay":
        return []
    candidates: list[dict[str, Any]] = []
    for record in evidence:
        if (not isinstance(record, dict) or record.get("kind") != "load_comparison"
                or not _in_run_window(record, run_scope, bounds)):
            continue
        finding = _load_comparison(record, target_url, target_protocol, target_family, bounds)
        if finding is None:
            continue
        metric, basis = finding
        candidate = _candidate(
            "load_related_latency",
            f"{basis} Measured metric: {metric}.",
            [record],
            [],
            "Repeat a controlled comparison from the same vantage and inspect measured queue counters; do not label the result bufferbloat without direct queue evidence.",
        )
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _offline_candidates(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for record in evidence:
        if (not isinstance(record, dict) or record.get("kind") != "pcap_analysis"
                or _status(record) not in {"complete", "partial"} or not _safe_id(record)):
            continue
        summary = _mapping(_mapping(record.get("observation")).get("summary"))
        retransmissions = _int(summary.get("tcp_retransmission_frames"))
        if retransmissions is None or retransmissions <= 0:
            continue
        frames = _int(summary.get("frames"))
        candidate = _candidate(
            "captured_transport_indicators",
            f"The selected capture contains {retransmissions} TShark TCP retransmission-indicator frame(s)"
            + (f" among {frames} selected frame(s)." if frames is not None else ".")
            + " These are capture-point observations, not proof of end-to-end loss or responsibility.",
            [record],
            [],
            "Correlate the captured flow and time with endpoint or service-side evidence before assigning responsibility.",
        )
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def diagnose(evidence: list[dict[str, Any]], scope: dict[str, Any], mode: str,
             max_response_wait_ms: float | None = None,
             max_dns_ms: float | None = None) -> dict[str, Any]:
    """Derive bounded findings from evidence; symptom text never selects a cause."""
    run_scope = _mapping(scope)
    records = [record for record in evidence if isinstance(record, dict)] if isinstance(evidence, list) else []
    primary_spec, control_spec = _target_specs(run_scope)
    target_url = _string(primary_spec.get("url")) if primary_spec is not None else None
    control_url = _string(control_spec.get("url")) if control_spec is not None else None
    target_protocol = _protocol(primary_spec.get("protocol")) if primary_spec is not None else None
    target_family = _family_value(primary_spec.get("address_family")) if primary_spec is not None else None
    bounds = _window_bounds(run_scope)
    run_window_id = bounds[2] if bounds is not None else None
    mode_name = mode if isinstance(mode, str) and mode in MODES else "live"
    window_start = _string(run_scope.get("window_started_at_utc"))
    window_end = _string(run_scope.get("window_ended_at_utc"))
    if window_start and window_end:
        time_window = f"{window_start}..{window_end}"
    else:
        time_window = _string(run_scope.get("time_window")) or window_start

    target_http: list[dict[str, Any]] = []
    control_http: list[dict[str, Any]] = []
    for record in records:
        if record.get("kind") != "http_probe" or not _safe_id(record):
            continue
        role = _record_role(record, target_url, control_url)
        if role is None or not _in_run_window(record, run_scope, bounds):
            continue
        expected_protocol = target_protocol
        if role == "control" and control_spec is not None:
            control_protocol = _protocol(control_spec.get("protocol"))
            if control_protocol is not None and control_protocol != target_protocol:
                continue
        if not _record_matches_protocol(record, expected_protocol):
            continue
        if not _record_matches_family(record, target_family):
            continue
        (target_http if role == "target" else control_http).append(record)

    target_successes = [record for record in target_http if _http_success(record)]
    control_successes = [record for record in control_http if _http_success(record)]
    successes_by_key: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for record in target_successes:
        key = _context_key(record, run_window_id)
        if key is not None:
            successes_by_key.setdefault(key, []).append(record)

    fault_groups: dict[tuple[str, tuple[str, str, str, str]], list[dict[str, Any]]] = {}
    target_fault_records: list[dict[str, Any]] = []
    for record in target_http:
        fault = _http_fault(record)
        key = _fault_context_key(record, run_window_id)
        if fault is None or key is None:
            continue
        domain, _basis = fault
        fault_groups.setdefault((domain, key), []).append(record)
        target_fault_records.append(record)

    candidates: list[dict[str, Any]] = []
    candidate_priority: dict[str, int] = {
        "tls_validation": 0,
        "name_resolution": 1,
        "transport_connection": 2,
        "request_timeout": 3,
        "http_service_response": 4,
        "response_wait": 5,
        "load_related_latency": 6,
        "name_resolution_latency": 7,
        "captured_transport_indicators": 8,
    }
    next_steps: list[str] = []
    limitations: list[str] = []
    counterevidence: list[dict[str, str]] = []

    for (domain, key), fault_records in fault_groups.items():
        outcome = _outcome(fault_records[0])
        if domain == "request_timeout":
            basis = "A target request ended with curl exit 28. Collection-budget exhaustion or cancellation without that request-level result is not classified as a business timeout."
            step = "Repeat the same target request in a fresh bounded window and compare the timing phases with a configured target baseline."
        elif domain == "http_service_response":
            basis = "The target returned a completed HTTP 5xx response; this identifies an observed service response, not responsibility for the failure."
            step = "Repeat the same request and correlate its timestamp and response status with the service owner."
        elif outcome in FAULTS:
            basis = FAULTS[outcome][2]
            if domain in {"tls_validation", "name_resolution"}:
                step = "Repeat the target check from the same vantage and compare only the reported protocol facts; retain certificate validation and resolver details."
            else:
                step = "Repeat a fresh target connection from the same vantage and compare it with a configured control in the same collection window."
        else:
            basis = "A completed target request recorded a supported failure outcome."
            step = "Repeat the same target request and correlate its timestamp with the service owner."
        first = fault_records[0]
        target_counters = [record for record in target_successes
                           if _fault_context_key(record, run_window_id) == key]
        control_counters = _same_context_controls(control_successes, first, run_window_id)
        candidate = _candidate(domain, basis, fault_records, target_counters + control_counters, step)
        if candidate is not None:
            candidates.append(candidate)
            next_steps.append(step)

    response_limit = _numeric_baseline(max_response_wait_ms)
    response_groups = _group_measurements(target_http, "response_wait_ms", run_window_id)
    response_comparable_groups = [items for items in response_groups.values() if len(items) >= 3]
    response_fault_records: list[dict[str, Any]] = []
    response_limit_exceeded = False
    for key, items in response_groups.items():
        if response_limit is None or len(items) < 3:
            continue
        values = [value for _, value in items]
        median = statistics.median(values)
        if median <= response_limit:
            continue
        response_limit_exceeded = True
        samples = [record for record, _ in items]
        response_fault_records.extend(samples)
        basis = (f"The median response-wait measurement was {median:g} ms across {len(values)} complete requests, "
                 f"above the configured {response_limit:g} ms limit. This supports a response-stage observation, "
                 "not a server, proxy, or network-responsibility claim.")
        step = "Repeat the same target request against the configured response-wait limit and correlate the stage timings with the service owner."
        counters = [record for record in target_successes
                    if _context_key(record, run_window_id) == key
                    and record not in samples
                    and (_measurement_value(record, "response_wait_ms") is not None)
                    and _measurement_value(record, "response_wait_ms") <= response_limit]
        candidate = _candidate("response_wait", basis, samples, counters, step)
        if candidate is not None:
            candidates.append(candidate)
            next_steps.append(step)

    if response_limit is not None and not response_comparable_groups:
        limitations.append("A response-wait baseline was configured, but fewer than three complete same-target, protocol, address-family, and collection-window requests had finite response-wait measurements.")
    elif response_limit is None and max_response_wait_ms is not None:
        limitations.append("The response-wait baseline was invalid and was not used for classification.")
    elif response_limit is not None and not response_limit_exceeded:
        all_groups_with_baseline = [items for items in response_groups.values() if len(items) >= 3]
        if all_groups_with_baseline:
            for items in all_groups_with_baseline:
                if any(value > response_limit for _, value in items):
                    limitations.append("At least one response-wait sample exceeded the configured limit, but the comparable-group median did not; the response check is not treated as healthy or as a repeated fault.")
                    break

    dns_limit = _numeric_baseline(max_dns_ms)
    dns_groups = _dns_latency_groups(records, target_url, run_scope, bounds, run_window_id)
    dns_comparable_groups = [items for items in dns_groups.values() if len(items) >= 3]
    dns_fault_records: list[dict[str, Any]] = []
    dns_limit_exceeded = False
    if dns_limit is not None:
        for items in dns_groups.values():
            if len(items) < 3:
                continue
            values = [value for _, value in items]
            median = statistics.median(values)
            if median <= dns_limit:
                continue
            dns_limit_exceeded = True
            samples = [record for record, _ in items]
            dns_fault_records.extend(samples)
            basis = (f"The median structured DNS query time was {median:g} ms across {len(values)} "
                     f"same-target, resolver, transport, address-family, and collection-window samples, "
                     f"above the configured {dns_limit:g} ms limit. This does not identify recursive-server CPU or responsibility.")
            step = "Repeat A and AAAA through an explicitly selected resolver and compare each query family in the same collection window."
            candidate = _candidate("name_resolution_latency", basis, samples, [], step)
            if candidate is not None:
                candidates.append(candidate)
                next_steps.append(step)
    if dns_limit is not None and not dns_comparable_groups:
        limitations.append("A DNS query-time baseline was configured, but fewer than three complete same-target, resolver, transport, address-family, and collection-window queries had finite timings.")
    elif dns_limit is None and max_dns_ms is not None:
        limitations.append("The DNS query-time baseline was invalid and was not used for classification.")

    # A DNS timing candidate remains a stage observation and never changes the
    # business-fault state by itself.
    candidates.extend(_load_candidate(records, target_url, target_protocol, target_family,
                                      mode_name, run_scope, bounds))
    if mode_name == "offline_pcap":
        candidates.extend(_offline_candidates(records))

    for record in target_successes:
        evidence_id = _safe_id(record)
        if evidence_id is not None:
            counterevidence.append({
                "evidence_id": evidence_id,
                "meaning": "The complained-of URL returned a completed HTTP 2xx response in this sample; that does not prove full page, media, or historical health.",
            })
    for record in control_successes:
        evidence_id = _safe_id(record)
        if evidence_id is not None:
            counterevidence.append({
                "evidence_id": evidence_id,
                "meaning": "The configured control URL returned a completed HTTP 2xx response; this is comparison evidence and does not establish health for the complained-of URL.",
            })

    ping_records = [record for record in records if record.get("kind") == "ping"]
    path_records = [record for record in records if record.get("kind") in {"path_trace", "path_report"}]
    if any(_status(record) == "permission_denied" for record in ping_records + path_records):
        limitations.append("ICMP or path collection was permission-limited; any observed target HTTP failure remains valid, but path localization is reduced.")
    if any(record.get("kind") in {"path_trace", "path_report"} for record in records):
        path_missing = any(_mapping(record.get("observation")).get("missing_hops")
                           or _mapping(record.get("observation")).get("nonresponding_hops")
                           for record in path_records)
        if path_missing and target_successes:
            limitations.append("Missing intermediate-hop responses with successful target HTTP responses do not establish forwarding loss.")
    if any(_mapping(record.get("observation")).get("proxy_configured") for record in target_http):
        limitations.append("A proxy was configured; response-stage timings may include proxy-path behavior and do not assign responsibility to the origin server.")
    if mode_name == "live" and any(record.get("kind") == "load_comparison" for record in records):
        limitations.append("Derived load-comparison evidence is used only in replay mode and was not treated as live evidence.")
    if mode_name == "offline_pcap":
        limitations.extend([
            "Offline PCAP observations do not establish the current live path or current business health.",
            "Capture-point coverage, direction, timing, and missing packets limit attribution.",
        ])

    health_checks: list[dict[str, Any]] = []
    success_ids = _unique_ids(target_successes)
    health_checks.append({
        "name": "http_2xx",
        "result": "observed" if target_successes else "not_established",
        "evidence_ids": success_ids,
    })
    baseline_health_records: list[dict[str, Any]] = []
    response_check_passes = False
    if response_limit is None:
        health_checks.append({"name": "response_wait_ms", "result": "not_configured", "evidence_ids": []})
    else:
        for key, items in response_groups.items():
            group_records = [record for record, _ in items]
            if len(group_records) < 3 or any(not _http_success(record) for record in group_records):
                continue
            if all(value <= response_limit for _, value in items):
                response_check_passes = True
                baseline_health_records = group_records
                break
        if response_check_passes:
            health_checks.append({
                "name": "response_wait_ms",
                "result": "within_configured_limit",
                "limit_ms": response_limit,
                "sample_count": len(baseline_health_records),
                "evidence_ids": _unique_ids(baseline_health_records),
            })
        elif response_limit_exceeded:
            health_checks.append({"name": "response_wait_ms", "result": "over_configured_limit", "limit_ms": response_limit, "evidence_ids": _unique_ids(response_fault_records)})
        else:
            health_checks.append({"name": "response_wait_ms", "result": "insufficient_evidence", "limit_ms": response_limit, "evidence_ids": []})

    dns_baseline_requested = max_dns_ms is not None
    dns_check_sufficient = not dns_baseline_requested or (dns_limit is not None and bool(dns_comparable_groups))
    dns_check_within_limit = not dns_baseline_requested or (
        dns_limit is not None and dns_check_sufficient and not dns_limit_exceeded
    )
    health_supported = (
        len(baseline_health_records) >= 3
        and not target_fault_records
        and not response_limit_exceeded
        and dns_check_sufficient
        and dns_check_within_limit
        and not any(candidate.get("domain") == "load_related_latency" for candidate in candidates)
    )

    if mode_name == "offline_pcap":
        status = "insufficient_evidence"
        next_steps.append("Collect a target-scoped live request or a service-side record for the reported time window.")
    elif target_fault_records or response_limit_exceeded:
        status = "fault_observed"
    elif mode_name == "replay" and any(candidate.get("domain") == "load_related_latency" for candidate in candidates):
        status = "fault_observed"
    elif health_supported:
        status = "healthy_within_scope"
        limitations.extend([
            "This health finding covers only the measured HTTP 2xx and configured response-wait checks in the stated target, protocol, address family, vantage, and short collection window.",
            "It does not establish page or media completeness, full Internet health, other DNS/TCP/TLS checks, other connection phases, or historical conditions.",
        ])
    elif target_successes:
        status = "not_reproduced"
        limitations.append("Successful sampled requests did not reproduce the reported failure; without a passing configured response-wait baseline and sufficient requested checks, this is not a healthy-within-scope finding.")
    else:
        status = "insufficient_evidence"
        if not target_http:
            limitations.append("No complete target HTTP response or supported target failure was observed in the stated collection window.")
        elif any(_http_status(record) is not None for record in target_http):
            limitations.append("The observed HTTP status did not establish a completed target 2xx response or a supported completed HTTP 5xx failure.")
        if any(_status(record) in {"unsupported", "permission_denied", "budget_exhausted", "timeout", "partial", "parse_error", "tool_error"}
               for record in records):
            limitations.append("One or more collection records were unavailable, incomplete, permission-limited, or budget-limited; those records were not used as business-fault evidence.")
        if not target_http or not target_successes:
            next_steps.append("Repeat a target-scoped request in a new bounded window and add a configured response-wait baseline if latency classification is needed.")

    if not any(record.get("kind") == "dns_query" and _status(record) == "complete"
               and _safe_id(record) and _in_run_window(record, run_scope, bounds)
               for record in records):
        limitations.append("Structured DNS evidence was not available; curl name resolution is implicit and is not a substitute for an optional structured DNS query measurement.")
    if not run_scope.get("control_target_configured") and mode_name == "live":
        limitations.append("No configured control URL was measured, so same-window comparison evidence is unavailable.")
    if response_limit is None and target_successes:
        limitations.append("No configured response-wait baseline was supplied; normal short-window responses support not-reproduced, not a healthy finding.")
    if dns_limit_exceeded and target_successes:
        limitations.append("The configured DNS timing threshold was exceeded as a DNS-stage observation; it does not by itself establish business unavailability or recursive-server responsibility.")

    output_protocol = target_protocol or ("PCAP/PCAPNG" if mode_name == "offline_pcap" else None)
    output_family = target_family
    if output_family is None:
        if status == "healthy_within_scope" and baseline_health_records:
            health_families = {_record_family(record) for record in baseline_health_records}
            output_family = next(iter(health_families)) if len(health_families) == 1 else None
        else:
            relevant_ids = {evidence_id for candidate in candidates for evidence_id in candidate.get("evidence_ids", [])}
            relevant_records = [record for record in records if _safe_id(record) in relevant_ids]
            candidate_families = {_record_family(record) for record in relevant_records
                                  if record.get("kind") == "http_probe"}
            if candidate_families:
                output_family = next(iter(candidate_families)) if len(candidate_families) == 1 else None
            else:
                all_families = {_record_family(record) for record in target_http}
                output_family = next(iter(all_families)) if len(all_families) == 1 else None
    observed_families = {_record_family(record) for record in target_http}
    if target_family is None and (len(observed_families) > 1 or (None in observed_families and len(observed_families) > 1)):
        limitations.append("Target observations span or omit actual address families; the diagnosis leaves address family unspecified and does not pool those samples.")
    elif target_family is None and observed_families == {None} and target_http:
        limitations.append("The target's actual address family was unavailable; no family-specific latency comparison was made.")
    if output_protocol is None:
        output_protocol = next((_protocol(_mapping(record.get("scope")).get("protocol"))
                                for record in target_http
                                if _protocol(_mapping(record.get("scope")).get("protocol")) is not None), None)

    candidates.sort(key=lambda item: (candidate_priority.get(item.get("domain", ""), 99), item.get("domain", ""), item.get("evidence_ids", [""])[0]))
    candidates = candidates[:2]
    if not next_steps:
        if status == "healthy_within_scope":
            next_steps.append("Continue monitoring the same scoped HTTP checks and compare future runs with the configured response-wait baseline.")
        elif status == "not_reproduced":
            next_steps.append("Repeat during the reported symptom window and retain the target, protocol, address family, and timestamps.")
        elif mode_name == "offline_pcap":
            next_steps.append("Correlate the observed capture facts with endpoint or service-side records before assigning responsibility.")

    diagnosis_scope: dict[str, Any] = {
        "mode": mode_name,
        "target": target_url,
        "protocol": output_protocol,
        "address_family": output_family,
        "time_window": time_window,
        "control_target_configured": bool(run_scope.get("control_target_configured", control_url is not None)),
        "health_checks": health_checks,
    }
    diagnosis = {
        "schema_version": "0.1.0",
        "status": status,
        "scope": diagnosis_scope,
        "evidence_ids": _unique_ids(records),
        "candidates": candidates,
        "counterevidence": counterevidence,
        "limitations": list(dict.fromkeys(limitations)),
        "next_steps": list(dict.fromkeys(next_steps)),
        "origin": "offline_pcap" if mode_name == "offline_pcap" else "replay" if mode_name == "replay" else "live",
    }
    return diagnosis


def _valid_reference_list(value: Any, known_ids: set[str], label: str,
                          errors: list[str], allow_empty: bool) -> None:
    if not isinstance(value, list):
        errors.append(f"{label} must be an array of strings")
        return
    if not allow_empty and not value:
        errors.append(f"{label} must not be empty")
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not EVIDENCE_ID.fullmatch(item):
            errors.append(f"{label} must contain valid evidence IDs")
            continue
        if item in seen:
            errors.append(f"{label} contains duplicate IDs")
        seen.add(item)
        if item not in known_ids:
            errors.append(f"{label} contains unknown IDs")


def validate_diagnosis(diagnosis: dict[str, Any], evidence: list[dict[str, Any]]) -> list[str]:
    """Validate the diagnosis shape and every evidence reference without raising."""
    errors: list[str] = []
    if not isinstance(diagnosis, dict):
        return ["diagnosis must be an object"]

    known_ids: set[str] = set()
    if not isinstance(evidence, list):
        evidence = []
        errors.append("evidence must be an array")
    for index, record in enumerate(evidence):
        if not isinstance(record, dict):
            errors.append(f"evidence[{index}] must be an object")
            continue
        evidence_id = record.get("id")
        if not isinstance(evidence_id, str) or not EVIDENCE_ID.fullmatch(evidence_id):
            errors.append(f"evidence[{index}].id has invalid form")
        elif evidence_id in known_ids:
            errors.append(f"evidence[{index}].id is duplicated")
        else:
            known_ids.add(evidence_id)

    if diagnosis.get("schema_version") != "0.1.0":
        errors.append("diagnosis.schema_version is unsupported")
    status = diagnosis.get("status")
    if not isinstance(status, str) or status not in DIAGNOSIS_STATUSES:
        errors.append("diagnosis.status is unsupported")
    scope = diagnosis.get("scope")
    if not isinstance(scope, dict):
        errors.append("diagnosis.scope must be an object")
    elif not all(key in scope for key in ("mode", "target", "protocol", "time_window")):
        errors.append("diagnosis.scope is incomplete")
    else:
        if not isinstance(scope.get("mode"), str) or scope["mode"] not in MODES:
            errors.append("diagnosis.scope.mode is unsupported")
        for name in ("target", "protocol", "time_window"):
            if scope.get(name) is not None and not isinstance(scope.get(name), str):
                errors.append(f"diagnosis.scope.{name} must be a string or null")
        if scope.get("address_family") is not None and _family_value(scope.get("address_family")) is None:
            errors.append("diagnosis.scope.address_family must be IPv4, IPv6, or null")
        health_checks = scope.get("health_checks", [])
        if not isinstance(health_checks, list):
            errors.append("diagnosis.scope.health_checks must be an array")
        else:
            for index, check in enumerate(health_checks):
                if not isinstance(check, dict) or not isinstance(check.get("name"), str) or not isinstance(check.get("result"), str):
                    errors.append(f"diagnosis.scope.health_checks[{index}] is invalid")
                    continue
                if "evidence_ids" in check:
                    _valid_reference_list(check.get("evidence_ids"), known_ids,
                                          f"diagnosis.scope.health_checks[{index}].evidence_ids", errors,
                                          allow_empty=True)
                if "limit_ms" in check and not _finite(check.get("limit_ms")):
                    errors.append(f"diagnosis.scope.health_checks[{index}].limit_ms must be finite")

    _valid_reference_list(diagnosis.get("evidence_ids"), known_ids,
                          "diagnosis.evidence_ids", errors, allow_empty=True)

    candidates = diagnosis.get("candidates")
    if not isinstance(candidates, list) or len(candidates) > 2:
        errors.append("diagnosis.candidates must contain at most two items")
    else:
        for index, item in enumerate(candidates):
            label = f"diagnosis.candidates[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{label} must be an object")
                continue
            for name in ("domain", "basis", "next_step"):
                if not isinstance(item.get(name), str) or not item.get(name):
                    errors.append(f"{label}.{name} must be a non-empty string")
            _valid_reference_list(item.get("evidence_ids"), known_ids,
                                  f"{label}.evidence_ids", errors, allow_empty=False)
            _valid_reference_list(item.get("counterevidence_ids"), known_ids,
                                  f"{label}.counterevidence_ids", errors, allow_empty=True)

    counterevidence = diagnosis.get("counterevidence")
    if not isinstance(counterevidence, list):
        errors.append("diagnosis.counterevidence must be an array")
    else:
        for index, item in enumerate(counterevidence):
            if not isinstance(item, dict):
                errors.append(f"diagnosis.counterevidence[{index}] must be an object")
                continue
            evidence_id = item.get("evidence_id")
            meaning = item.get("meaning")
            if not isinstance(evidence_id, str) or not EVIDENCE_ID.fullmatch(evidence_id) or evidence_id not in known_ids:
                errors.append(f"diagnosis.counterevidence[{index}].evidence_id is invalid or unknown")
            if not isinstance(meaning, str) or not meaning:
                errors.append(f"diagnosis.counterevidence[{index}].meaning must be a non-empty string")

    for name in ("limitations", "next_steps"):
        value = diagnosis.get(name)
        if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
            errors.append(f"diagnosis.{name} must be an array of non-empty strings")

    origin = diagnosis.get("origin")
    if not isinstance(origin, str) or origin not in {"live", "offline_pcap", "replay"}:
        errors.append("diagnosis.origin is unsupported")
    return errors
