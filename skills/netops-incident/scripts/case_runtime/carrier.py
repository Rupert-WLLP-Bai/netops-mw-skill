"""Validate versioned carrier metadata; comparisons report gaps, not diagnoses.

The private schema interpreter supports only keywords used in the two bundled schemas.
Cross-record constraints and comparison eligibility are checked separately.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path
from .store import CaseError, timestamp

SCHEMAS = Path(__file__).resolve().parents[2] / 'schemas'


def bounded(value):
    """Limit traversal before serialization or recursive schema validation."""
    stack = [(value, 0)]
    count = size = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if depth > 16 or count > 20000:
            raise CaseError('carrier metadata depth or count exceeded')
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise CaseError('invalid carrier metadata key')
                stack.append((key, depth + 1)); stack.append((child, depth + 1))
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > 2048:
                raise CaseError('carrier metadata string too long')
            size += len(item.encode('utf-8'))
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            try:
                if not math.isfinite(item): raise CaseError('invalid carrier number')
            except OverflowError as exc:
                raise CaseError('invalid carrier number') from exc
        elif item is not None and not isinstance(item, bool):
            raise CaseError('invalid carrier metadata value')
    if size > 1024 * 1024 or len(json.dumps(value, ensure_ascii=False).encode('utf-8')) > 1024 * 1024:
        raise CaseError('carrier metadata size exceeded')


def _schema(value, schema, root):
    if '$ref' in schema:
        name = schema['$ref'].split('/')[-1]
        return _schema(value, root['$defs'][name], root)
    if 'const' in schema and (value != schema['const'] or isinstance(value, bool)):
        raise CaseError('invalid carrier schema constant')
    if 'enum' in schema and value not in schema['enum']:
        raise CaseError('invalid carrier schema enumeration')
    types = schema.get('type')
    if types:
        if isinstance(types, str): types = [types]
        checks = {'null': value is None, 'object': isinstance(value, dict), 'array': isinstance(value, list),
                  'string': isinstance(value, str), 'number': isinstance(value, (int, float)) and not isinstance(value, bool),
                  'integer': isinstance(value, int) and not isinstance(value, bool)}
        if not any(checks[t] for t in types): raise CaseError('invalid carrier schema type')
    if isinstance(value, dict):
        props = schema.get('properties', {})
        if any(key not in value for key in schema.get('required', [])) or (schema.get('additionalProperties') is False and set(value) - set(props)):
            raise CaseError('invalid carrier schema fields')
        for key, child in value.items():
            if key in props: _schema(child, props[key], root)
    elif isinstance(value, list):
        if len(value) > schema.get('maxItems', len(value)):
            raise CaseError('invalid carrier schema array')
        if 'items' in schema:
            for child in value: _schema(child, schema['items'], root)
        if schema.get('uniqueItems') and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            raise CaseError('duplicate carrier schema array item')
    elif isinstance(value, str):
        if len(value) < schema.get('minLength', 0) or len(value) > schema.get('maxLength', 2048) or ('pattern' in schema and not re.search(schema['pattern'], value)) or not value.strip():
            raise CaseError('invalid carrier schema string')
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if ('minimum' in schema and value < schema['minimum']) or ('exclusiveMinimum' in schema and value <= schema['exclusiveMinimum']):
            raise CaseError('invalid carrier schema number')


def _validate(value, name):
    bounded(value)
    schema = json.loads((SCHEMAS / name).read_text(encoding='utf-8'))
    _schema(value, schema, schema)


def validate_context(context):
    _validate(context, 'service-context.schema.json')
    objects = {}
    for obj in context['objects']:
        if obj['id'] in objects: raise CaseError('duplicate carrier object id')
        if obj['identity_state'] != 'known' and not obj['reason']: raise CaseError('unknown identity requires reason')
        if obj['source_native_id'] is not None and obj['source'] is None: raise CaseError('native identity requires source')
        objects[obj['id']] = obj
    service_ref = context['service_ref']
    if service_ref is not None and (service_ref not in objects or objects[service_ref]['type'] != 'service'):
        raise CaseError('invalid service reference')
    links = set()
    for link in context['topology']:
        pair = (link['from_id'], link['to_id'])
        if pair in links or pair[0] == pair[1] or any(ref not in objects for ref in pair): raise CaseError('invalid carrier topology reference')
        links.add(pair)
        if link['state'] != 'verified' and not link['reason']: raise CaseError('unverified topology requires reason')
        if link['state'] == 'verified' and any(objects[ref]['identity_state'] != 'known' for ref in pair): raise CaseError('verified link requires known identities')


def validate_envelope(envelope, context, evidence):
    _validate(envelope, 'carrier-evidence.schema.json')
    if context is not None: validate_context(context)
    objects = {item['id'] for item in context['objects']} if context is not None else set()
    records = {item['id']: item for item in evidence}
    seen = set()
    for record in envelope['records']:
        eid = record['evidence_id']
        if eid in seen or eid not in records or any(ref not in objects for ref in record['object_refs']): raise CaseError('invalid carrier evidence reference')
        seen.add(eid)
        if record['source_native_id'] is not None and record['source'] is None: raise CaseError('native identity requires source')
        event = timestamp(record['event_time']) if record['event_time'] is not None else None
        collected = timestamp(record['collected_at']) if record['collected_at'] is not None else None
        if event and collected and event > collected and record['clock_quality'] == 'synchronized': raise CaseError('synchronized event after collection')
        artifact, visible = record['artifact_sha256'], record['redaction']['visible_sha256']
        if artifact and visible and artifact != visible: raise CaseError('visible artifact hash mismatch')
        hashes = {s.get('sha256') for s in records[eid].get('sources', []) if isinstance(s, dict) and s.get('sha256')}
        declared = artifact or visible
        if declared and declared not in hashes: raise CaseError('evidence source hash mismatch')
        measurement = record['measurement']
        if measurement is not None:
            if measurement['value'] is None and not measurement['missing_reason']: raise CaseError('missing measurement requires reason')
            if measurement['reset_state'] in ('reset', 'wrap') and measurement['counter_semantics'] not in ('cumulative', 'unknown'): raise CaseError('reset requires cumulative or unknown counter')


def comparison_gaps(left, right, context):
    """Return conservative comparison limitations without inferring a fault."""
    gaps = []
    a, b = left.get('measurement'), right.get('measurement')
    if not a or not b or a['value'] is None or b['value'] is None: gaps.append('value')
    if a and b:
        for key in ('unit', 'direction', 'denominator', 'sample_interval_seconds'):
            if a[key] is None or b[key] is None or a[key] == 'unknown' or b[key] == 'unknown' or a[key] != b[key]: gaps.append(key)
        if (a['denominator'] == '0' or b['denominator'] == '0') and 'denominator' not in gaps: gaps.append('denominator')
        if not a['sample_count'] or not b['sample_count']: gaps.append('sample_count')
        if any(m['counter_semantics'] == 'unknown' or m['reset_state'] != 'none' for m in (a, b)) or a['counter_semantics'] != b['counter_semantics']: gaps.append('counter_reset')
    if any(r['clock_quality'] != 'synchronized' or r['clock_uncertainty_seconds'] is None or not r['event_time'] or not r['collected_at'] for r in (left, right)): gaps.append('clock')
    if not left.get('event_time') or left.get('event_time') != right.get('event_time'): gaps.append('sample_window')
    if not left.get('source') or not left.get('source_native_id') or (left.get('source'), left.get('source_native_id')) != (right.get('source'), right.get('source_native_id')):
        gaps.append('object_scope')
    refs = set(left.get('object_refs', []) + right.get('object_refs', []))
    reachable = {context['service_ref']} if context and context['service_ref'] else set()
    if context:
        objects = {obj['id']: obj for obj in context['objects']}
        for link in context['topology']:
            if link['state'] == 'verified' and context['service_ref'] in (link['from_id'], link['to_id']):
                reachable.update((link['from_id'], link['to_id']))
    else:
        objects = {}
    if not refs or not refs.issubset(reachable) or any(ref not in objects or objects[ref]['identity_state'] != 'known' for ref in refs) or any(r['topology_mapping_confidence'] in (None, 'low') for r in (left, right)):
        gaps.append('topology')
    return gaps
