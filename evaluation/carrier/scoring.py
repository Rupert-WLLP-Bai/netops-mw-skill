"""Deterministic, per-job carrier answer scoring."""

from __future__ import annotations

from typing import Any

from .contract import validate_answer, validate_oracle, validate_task


def _ratio(numerator: int, denominator: int, reason: str = "not_applicable", *, scored: bool = True) -> dict[str, Any]:
    effective_reason = (None if denominator and scored else
                        reason if denominator or reason == "not_required" else "not_applicable")
    return {"score": numerator / denominator if denominator and scored else None,
            "numerator": numerator, "denominator": denominator,
            "reason": effective_reason}


def _ref(ref: Any) -> tuple[str, str] | None:
    if isinstance(ref, dict) and isinstance(ref.get("run_id"), str) and isinstance(ref.get("evidence_id"), str):
        return ref["run_id"], ref["evidence_id"]
    return None


def _claim_key(claim: dict[str, Any]) -> tuple[Any, ...]:
    scope = claim.get("scope") if isinstance(claim.get("scope"), dict) else {}
    return (claim.get("kind"), claim.get("code"), claim.get("layer"),
            tuple(sorted(scope.items())))


def _oracle_key(claim: dict[str, Any]) -> tuple[Any, ...]:
    return (claim.get("kind"), claim.get("code"), claim.get("layer"),
            tuple(sorted((claim.get("scope") or {}).items())))


def _actual_refs(index: Any, job_id: str) -> set[tuple[str, str]]:
    if not isinstance(index, dict) or not isinstance(index.get(job_id), list):
        return set()
    return {pair for item in index[job_id] if (pair := _ref(item)) is not None}


def _refs(claim: dict[str, Any], key: str) -> set[tuple[str, str]]:
    values = claim.get(key)
    if not isinstance(values, list):
        return set()
    return {pair for item in values if (pair := _ref(item)) is not None}


def _score_job(task_job: dict[str, Any], answer_job: dict[str, Any] | None,
               oracle_job: dict[str, Any], trial_validity: str, elapsed_ms: int | None,
               visible_refs_by_job: dict[str, Any] | None) -> dict[str, Any]:
    complete = bool(answer_job and answer_job.get("completion") == "complete")
    raw = answer_job.get("raw_result") if answer_job else None
    claims = answer_job.get("normalized_claims", []) if answer_job else []
    if not isinstance(claims, list):
        claims = []
    expected_claims = oracle_job.get("claims", [])
    if not isinstance(expected_claims, list):
        expected_claims = []
    valid = trial_validity == "valid"
    class_expected = [c for c in expected_claims if c.get("fault_class") is True]
    required_keys = {_oracle_key(c) for c in expected_claims}
    membership_available = isinstance(visible_refs_by_job, dict) and isinstance(visible_refs_by_job.get(task_job["job_id"]), list)
    actual_refs = _actual_refs(visible_refs_by_job, task_job["job_id"])

    matched_expected: set[int] = set()
    grounded_expected = 0
    grounded_denominator = 0
    class_grounded = 0
    layer_correct = 0
    over = 0
    claim_matches: dict[int, int] = {}
    for i, expected in enumerate(expected_claims):
        key = _oracle_key(expected)
        candidates = [(n, claim) for n, claim in enumerate(claims)
                      if _claim_key(claim) == key and claim.get("status") == expected.get("status")]
        if candidates and complete:
            matched_expected.add(i)
            claim_matches[i] = candidates[0][0]
        sets = expected.get("support_sets", [])
        claim_grounded = False
        if sets:
            grounded_denominator += 1
            for n, claim in candidates:
                actual_support = _refs(claim, "support")
                for support_set in sets:
                    required = {_ref(ref) for ref in support_set if _ref(ref) is not None} if isinstance(support_set, list) else set()
                    if required and required <= actual_support and required <= actual_refs:
                        claim_grounded = True
                        break
                if claim_grounded:
                    break
            grounded_expected += int(claim_grounded and valid and complete)
            if expected.get("fault_class") is True:
                class_grounded += int(claim_grounded and valid and complete)
        if candidates and complete:
            # A layer claim is grounded only when its own complete evidence set is present.
            if expected.get("fault_class") is True and sets and claim_grounded and valid:
                layer_correct += int(candidates[0][1].get("layer") == expected.get("layer"))

    expected_for_actual = {actual_index: expected_index for expected_index, actual_index in claim_matches.items()}
    for actual_index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            over += 1
            continue
        key = _claim_key(claim)
        if key not in required_keys:
            over += 1
        # A resource assertion is extra specificity unless the oracle explicitly names it.
        resource = claim.get("resource_id")
        if resource is not None:
            expected_index = expected_for_actual.get(actual_index)
            expected_scope = expected_claims[expected_index].get("scope", {}) if expected_index is not None else {}
            if expected_scope.get("resource_id") != resource:
                over += 1
        if claim.get("measurement_point") is not None and claim.get("resource_id") == claim.get("measurement_point"):
            expected_index = expected_for_actual.get(actual_index)
            expected_scope = expected_claims[expected_index].get("scope", {}) if expected_index is not None else {}
            if expected_scope.get("resource_id") != claim.get("measurement_point"):
                over += 1
    prohibited = set(oracle_job.get("prohibited_codes", []))
    over += sum(1 for claim in claims if isinstance(claim, dict) and claim.get("code") in prohibited)
    if oracle_job.get("forbid_causal_links") is True and isinstance(raw, dict):
        links = raw.get("causal_links", raw.get("attributions", []))
        if isinstance(links, list):
            over += len(links)

    expected_counters = {i: {_ref(ref) for ref in c.get("counter_refs", []) if _ref(ref) is not None}
                         for i, c in enumerate(expected_claims)}
    counter_required = sum(len(refs) for refs in expected_counters.values())
    counter_found = 0
    counter_reported = 0
    counter_relevant = 0
    for actual_index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            continue
        refs = _refs(claim, "counterevidence")
        counter_reported += len(refs)
        expected_index = expected_for_actual.get(actual_index)
        expected_refs = expected_counters.get(expected_index, set()) if expected_index is not None else set()
        found = len(expected_refs & refs & actual_refs)
        counter_found += found
        counter_relevant += found

    raw_state = raw.get("status") if isinstance(raw, dict) else None
    state_axis = {"score": int(raw_state == oracle_job.get("expected_state")) if complete and valid and oracle_job.get("expected_state") is not None else None,
                  "numerator": int(raw_state == oracle_job.get("expected_state")) if complete and valid and oracle_job.get("expected_state") is not None else 0,
                  "denominator": int(complete and valid and oracle_job.get("expected_state") is not None),
                  "reason": None if complete and valid and oracle_job.get("expected_state") is not None else ("invalid_trial" if not valid else "not_applicable" if oracle_job.get("expected_state") is None else "incomplete_answer")}
    service_axes = {}
    for dimension in ("technical", "acceptance", "change"):
        expected = (oracle_job.get("service_states") or {}).get(dimension)
        key = {"technical": "technical_status", "acceptance": "acceptance_status", "change": "change_review"}[dimension]
        observed = raw.get(key) if isinstance(raw, dict) else None
        if dimension == "change" and isinstance(observed, dict):
            observed = observed.get("status")
        enabled = expected is not None
        scoreable = complete and valid and enabled
        service_axes[dimension] = {"score": int(observed == expected) if scoreable else None,
                                   "numerator": int(observed == expected) if scoreable else 0,
                                   "denominator": int(scoreable),
                                   "reason": None if scoreable else "invalid_trial" if not valid else "incomplete_answer" if not complete else "not_applicable"}

    claim_recall = len(matched_expected)
    claim_denominator = len(expected_claims)
    grounding = _ratio(grounded_expected if valid and complete else 0, grounded_denominator,
                       "invalid_trial" if not valid else "incomplete_answer" if not complete else "visible_membership_unavailable" if not membership_available else "not_applicable", scored=valid and complete and membership_available)
    layer_denominator = sum(c.get("fault_class") is True and c.get("layer") is not None
                            and bool(c.get("support_sets")) for c in expected_claims)
    localization = {
        "layer": _ratio(layer_correct if valid and complete else 0, layer_denominator, "invalid_trial" if not valid else "incomplete_answer" if not complete else "visible_membership_unavailable" if not membership_available else "not_applicable", scored=valid and complete and membership_available),
        "resource": {"score": None, "numerator": 0, "denominator": 0, "reason": "provider_contract_does_not_localize_resource"},
    }
    reported_gaps = raw.get("gaps", []) if isinstance(raw, dict) and isinstance(raw.get("gaps"), list) else []
    state_correct_abstention = bool(complete and raw_state in {"insufficient_evidence", "unverified"}
                                    and oracle_job.get("expected_state") in {"insufficient_evidence", "unverified"}
                                    and not claims and not expected_claims
                                    and set(oracle_job.get("required_gaps", [])) <= set(reported_gaps))
    return {
        "job_id": task_job["job_id"],
        "completion": answer_job.get("completion") if answer_job else "not_started",
        "state": state_axis,
        "service_states": service_axes,
        "fault_class": _ratio(class_grounded if valid and complete else 0,
                               sum(bool(c.get("support_sets")) for c in class_expected),
                               "invalid_trial" if not valid else "incomplete_answer" if not complete else "visible_membership_unavailable" if not membership_available else "not_applicable", scored=valid and complete and membership_available),
        "claim_recall": _ratio(claim_recall if valid and complete else 0, claim_denominator,
                               "invalid_trial" if not valid else "incomplete_answer" if not complete else "not_applicable", scored=valid and complete),
        "localization": localization,
        "grounding": grounding,
        "counterevidence": {"recall": _ratio(counter_found if valid and complete else 0, counter_required,
                                               "invalid_trial" if not valid else "not_required" if not counter_required else "visible_membership_unavailable" if not membership_available else "incomplete_answer", scored=valid and complete and membership_available),
                            "precision": _ratio(counter_relevant if valid and complete else 0, counter_reported,
                                                 "invalid_trial" if not valid else "visible_membership_unavailable" if not membership_available else "not_applicable", scored=valid and complete and membership_available)},
        "over_attribution": {"count": over if valid and complete else None,
                             "denominator": len(claims) if valid and complete else 0,
                             "reason": None if valid and complete else "invalid_trial" if not valid else "incomplete_answer"},
        "correct_abstention": state_correct_abstention if valid else None,
        "gaps": {"expected": list(oracle_job.get("required_gaps", [])),
                 "reported": list(raw.get("gaps", [])) if isinstance(raw, dict) and isinstance(raw.get("gaps"), list) else [],
                 "correct": _ratio(sum(g in reported_gaps for g in oracle_job.get("required_gaps", [])) if valid and complete else 0, len(oracle_job.get("required_gaps", [])), "invalid_trial" if not valid else "incomplete_answer" if not complete else "not_required", scored=valid and complete)},
        "runtime": {"elapsed_ms": elapsed_ms},
        "provider_metrics": answer_job.get("provider_metrics", {"tokens": None, "cost": None}) if answer_job else {"tokens": None, "cost": None},
    }


def score_answer(task: dict[str, Any], answer: dict[str, Any], oracle: dict[str, Any], *,
                 elapsed_ms: int | None, trial_validity: str = "valid",
                 visible_refs_by_job: dict[str, Any] | None = None) -> dict[str, Any]:
    """Score answers without collapsing independent axes into a single grade."""
    validate_task(task)
    validate_answer(answer, task)
    validate_oracle(oracle, task)
    if trial_validity not in {"valid", "invalid"}:
        raise ValueError("trial_validity must be valid or invalid")
    task_jobs = task["jobs"]
    answer_jobs = {job["job_id"]: job for job in answer["jobs"]}
    oracle_jobs = {job["job_id"]: job for job in oracle.get("jobs", []) if isinstance(job, dict)}
    jobs = [_score_job(job, answer_jobs.get(job["job_id"]), oracle_jobs.get(job["job_id"], {"claims": []}), trial_validity, elapsed_ms, visible_refs_by_job)
            for job in task_jobs]
    def aggregate(path: tuple[str, ...]) -> dict[str, Any]:
        values: list[dict[str, Any]] = []
        for job in jobs:
            value: Any = job
            for key in path:
                value = value.get(key, {}) if isinstance(value, dict) else {}
            if isinstance(value, dict) and isinstance(value.get("denominator"), int):
                values.append(value)
        numerator = sum(value.get("numerator", 0) for value in values)
        denominator = sum(value["denominator"] for value in values)
        scoreable = trial_validity == "valid" and all(value.get("score") is not None or value["denominator"] == 0 for value in values)
        reason = "invalid_trial" if trial_validity != "valid" else "not_applicable"
        return {"score": numerator / denominator if denominator and scoreable else None,
                "numerator": numerator, "denominator": denominator,
                "reason": None if denominator and scoreable else reason}
    aggregate_axes = {
        "state": aggregate(("state",)),
        "fault_class": aggregate(("fault_class",)),
        "claim_recall": aggregate(("claim_recall",)),
        "localization_layer": aggregate(("localization", "layer")),
        "grounding": aggregate(("grounding",)),
        "counterevidence_recall": aggregate(("counterevidence", "recall")),
        "counterevidence_precision": aggregate(("counterevidence", "precision")),
        "service_technical": aggregate(("service_states", "technical")),
        "service_acceptance": aggregate(("service_states", "acceptance")),
        "service_change": aggregate(("service_states", "change")),
    }
    return {
        "schema_version": 1, "task_id": task["task_id"],
        "trial_validity": trial_validity,
        "invalid_reason": oracle.get("invalid_reason") if trial_validity == "invalid" else None,
        "elapsed_ms": elapsed_ms,
        "jobs": jobs,
        "aggregate": aggregate_axes,
        "completion_counts": {state: sum(job["completion"] == state for job in jobs)
                              for state in ("complete", "timeout", "process_error", "invalid_output", "not_started")},
        "case_counts": {"jobs": len(jobs), "valid_jobs": sum(trial_validity == "valid" and job["completion"] == "complete" for job in jobs),
                        "scored_jobs": sum(trial_validity == "valid" and job["state"]["denominator"] > 0 for job in jobs)},
    }
