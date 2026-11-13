"""Resolve developer-only logical fixture row references after M2 ingestion."""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping


class FixtureReferenceError(ValueError):
    """A fixture refers to a missing or malformed logical source row."""


def resolve_row_refs(value: Any, row_ids: Mapping[str, Mapping[str, str]]) -> Any:
    """Return a copy with exact ``{"$row": "run_key/row_key"}`` markers resolved.

    The mapping must be built by the harness from each source's developer-only
    ``row_keys`` list and the evidence IDs actually emitted by M2 ingest. This
    helper does not calculate or predict evidence IDs and must run only in test
    materialization, never in the analyzer or a Skill.
    """
    if isinstance(value, dict):
        if set(value) == {"$row"}:
            marker = value["$row"]
            if not isinstance(marker, str) or marker.count("/") != 1:
                raise FixtureReferenceError("malformed logical row reference")
            run_key, row_key = marker.split("/", 1)
            try:
                evidence_id = row_ids[run_key][row_key]
            except KeyError as exc:
                raise FixtureReferenceError("unknown logical row reference") from exc
            if not isinstance(evidence_id, str) or not evidence_id.startswith("ev-"):
                raise FixtureReferenceError("invalid emitted evidence ID")
            return evidence_id
        return {key: resolve_row_refs(child, row_ids) for key, child in value.items()}
    if isinstance(value, list):
        return [resolve_row_refs(child, row_ids) for child in value]
    return deepcopy(value)


def resolve_source_tokens(
    value: Any,
    row_ids: Mapping[str, Mapping[str, str]],
    run_ids: Mapping[str, str],
) -> Any:
    """Resolve exact emitted-ID tokens in developer-only source templates.

    This supports staged equivalence records: ingest prerequisite sources,
    then resolve their actual emitted IDs before ingesting the equivalence
    source. It does not predict IDs or perform ingestion.
    """
    if isinstance(value, str):
        if value.startswith("$ID:"):
            marker = value[4:]
            if marker.count("/") != 1:
                raise FixtureReferenceError("malformed emitted-ID token")
            run_key, row_key = marker.split("/", 1)
            try:
                evidence_id = row_ids[run_key][row_key]
            except KeyError as exc:
                raise FixtureReferenceError("unknown emitted-ID token") from exc
            if not isinstance(evidence_id, str) or not evidence_id.startswith("ev-"):
                raise FixtureReferenceError("invalid emitted evidence ID")
            return evidence_id
        if value.startswith("$RUN_ID:"):
            run_key = value[8:]
            try:
                run_id = run_ids[run_key]
            except KeyError as exc:
                raise FixtureReferenceError("unknown emitted run-ID token") from exc
            if not isinstance(run_id, str) or not run_id:
                raise FixtureReferenceError("invalid emitted run ID")
            return run_id
        return value
    if isinstance(value, dict):
        return {key: resolve_source_tokens(child, row_ids, run_ids) for key, child in value.items()}
    if isinstance(value, list):
        return [resolve_source_tokens(child, row_ids, run_ids) for child in value]
    return deepcopy(value)
