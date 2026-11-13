"""Shared bounded evidence, scope and time checks for offline analyzers."""
from __future__ import annotations

import math
import os
import tempfile
from datetime import timedelta
from pathlib import Path

from .carrier import bounded
from .evidence import read_confined, strict_json, validate_run
from .store import CaseError, timestamp, token

LIMIT = 1024 * 1024
RUN_FIELDS = {'run_id', 'run_dir', 'expected_summary_hashes'}
BINDING_FIELDS = {'record', 'topology_evidence', 'service_id', 'resource_id', 'source', 'source_native_id', 'valid_from', 'valid_until', 'authority'}
REF_FIELDS = {'run_id', 'evidence_id'}
RECORD_FIELDS = {'metric', 'value', 'unit', 'direction', 'denominator', 'sample_interval_seconds', 'sample_count', 'counter_semantics', 'reset_state', 'event_time', 'object_id'}
def _object(value, keys):
    if not isinstance(value, dict) or set(value) != keys: raise CaseError('invalid access request fields')


def _ref(value):
    _object(value, REF_FIELDS)
    return (token(value['run_id'], 'run_id'), token(value['evidence_id'], 'evidence_id'))


def _validate_base(request, request_fields):
    bounded(request)
    pending = [request]
    while pending:
        item = pending.pop()
        if isinstance(item, dict): pending.extend(item.keys()); pending.extend(item.values())
        elif isinstance(item, list): pending.extend(item)
        elif isinstance(item, str) and any(ord(char) < 32 or ord(char) == 127 for char in item): raise CaseError('control character in access request')
    _object(request, request_fields)
    if isinstance(request['schema_version'], bool) or request['schema_version'] != 1: raise CaseError('invalid access version')
    reference, start, end = (timestamp(request[key]) for key in ('reference_time', 'window_start', 'window_end'))
    if start > end or end > reference: raise CaseError('invalid access window')
    age = request['max_age_seconds']
    try:
        if isinstance(age, bool) or not isinstance(age, (int, float)) or not math.isfinite(age) or age < 0: raise CaseError('invalid freshness policy')
    except OverflowError as exc: raise CaseError('invalid freshness policy') from exc
    _object(request['service'], {'topology_run_id', 'object_id'})
    token(request['service']['topology_run_id'], 'topology run id'); token(request['service']['object_id'], 'service id')
    runs, bindings = request['runs'], request['bindings']
    if not isinstance(runs, list) or not 1 <= len(runs) <= 8 or not isinstance(bindings, list) or len(bindings) > 512: raise CaseError('analysis request count exceeded')
    run_ids = set()
    for run in runs:
        _object(run, RUN_FIELDS); rid = token(run['run_id'], 'run_id')
        if rid in run_ids or not isinstance(run['run_dir'], str) or not os.path.isabs(run['run_dir']): raise CaseError('invalid access run')
        run_ids.add(rid)
    if request['service']['topology_run_id'] not in run_ids: raise CaseError('missing topology run')
    seen = set()
    for binding in bindings:
        _object(binding, BINDING_FIELDS); key = _ref(binding['record']); _ref(binding['topology_evidence'])
        if key in seen: raise CaseError('duplicate access binding')
        seen.add(key)
        for field in ('service_id', 'resource_id', 'source', 'source_native_id', 'authority'): token(binding[field], field)
        if timestamp(binding['valid_from']) > timestamp(binding['valid_until']): raise CaseError('invalid binding interval')
    return reference, start, end


def _validate_row(row):
    """Check normalized row fields even when the M1 numeric envelope is null."""
    _object(row, RECORD_FIELDS)
    token(row['metric'], 'metric')
    value = row['value']
    if isinstance(value, str): token(value, 'enum value')
    elif value is not None:
        try:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value): raise CaseError('invalid observation value')
        except OverflowError as exc: raise CaseError('invalid observation value') from exc
    for field in ('unit', 'denominator'):
        item = row[field]
        if item is not None and (not isinstance(item, str) or not item.strip() or len(item) > 128 or not item.isprintable()): raise CaseError('invalid measurement label')
    if row['direction'] not in ('ingress','egress','bidirectional','unknown'): raise CaseError('invalid direction')
    semantics, reset = row['counter_semantics'], row['reset_state']
    if semantics not in ('gauge','delta','cumulative','unknown') or reset not in ('none','reset','wrap','unknown') or (reset in ('reset','wrap') and semantics not in ('cumulative','unknown')): raise CaseError('invalid counter metadata')
    for field in ('sample_count','sample_interval_seconds'):
        item = row[field]
        if item is None: continue
        try:
            if isinstance(item,bool) or not isinstance(item,(int,float)) or not math.isfinite(item) or item < 0: raise CaseError('invalid sampling metadata')
        except OverflowError as exc: raise CaseError('invalid sampling metadata') from exc
        if field == 'sample_count' and isinstance(item,float) and not item.is_integer(): raise CaseError('invalid sample count')
        if field == 'sample_interval_seconds' and item == 0: raise CaseError('invalid sample interval')
    if row['event_time'] is not None: timestamp(row['event_time'])
    if row['object_id'] is not None: token(row['object_id'], 'source alias')

def _load_runs(request):
    runs = {}; evidence = {}; budget = {'per_run': 2 * 1024 * 1024, 'aggregate': [16 * 1024 * 1024], 'records': [512]}
    total_links = 0
    for run in request['runs']:
        snapshots, manifest, _, _ = validate_run(run, limits=budget)
        if 'carrier-visible.json' not in snapshots: raise CaseError('missing visible carrier artifact')
        visible = strict_json(snapshots['carrier-visible.json'], True); bounded(visible)
        if not isinstance(visible, dict) or set(visible) != {'schema_version','parse_status','quality','records'} or visible['schema_version'] != 1 or not isinstance(visible['records'], list): raise CaseError('invalid carrier derivative')
        adapter = manifest['carrier_adapter']
        adapter_fields = {'format','version','parse_status','quality','warnings','source','actor','authorization_ref','collected_at','reference_time','timezone'}
        if not isinstance(adapter, dict) or set(adapter) != adapter_fields or adapter.get('parse_status') != visible['parse_status'] or adapter['quality'] != visible['quality']: raise CaseError('inconsistent carrier adapter')
        records = [strict_json(line, True) for line in snapshots['evidence.jsonl'].splitlines() if line.strip()]
        envelope = manifest.get('carrier_evidence')
        if not isinstance(envelope, dict) or len(envelope.get('records', [])) != len(records): raise CaseError('missing carrier evidence')
        indexed = {entry['evidence_id']:entry for entry in envelope['records']}
        if set(indexed) != {record['id'] for record in records}: raise CaseError('carrier record mismatch')
        if len(records) != max(1, len(visible['records'])): raise CaseError('visible record count mismatch')
        for index, record in enumerate(records):
            row = visible['records'][index] if visible['records'] else None
            observation = record.get('observation')
            expected_status = {'complete':'complete','parse_error':'parse_error','unsupported_vendor_format':'unsupported','parse_timeout':'timeout'}.get(visible['parse_status'])
            if expected_status is None or record.get('status') != expected_status or not isinstance(observation, dict) or observation.get('record') != row or observation.get('parse_status') != visible['parse_status'] or observation.get('quality') != visible['quality']: raise CaseError('visible evidence mismatch')
            carrier = indexed[record['id']]
            if carrier['source'] != adapter.get('source') or carrier['collected_at'] != adapter.get('collected_at'): raise CaseError('carrier provenance mismatch')
            if row is not None:
                if not isinstance(row, dict): raise CaseError('invalid carrier observation')
                if 'metric' in row:
                    _validate_row(row)
                    if carrier['source_native_id'] != row['object_id'] or carrier['event_time'] != row['event_time']: raise CaseError('carrier observation identity mismatch')
                    measurement = carrier['measurement']
                    if isinstance(row['value'], str):
                        if measurement is not None: raise CaseError('invalid enum measurement')
                    else:
                        if not isinstance(measurement, dict) or any(measurement[field] != row[field] for field in ('value','unit','direction','denominator','sample_interval_seconds','sample_count','counter_semantics','reset_state')): raise CaseError('carrier measurement mismatch')
                elif set(row) != {'priority','event_time'} or carrier['event_time'] != row['event_time']:
                    raise CaseError('invalid header observation')
            evidence[(run['run_id'], record['id'])] = dict(row=row, carrier=carrier, record=record, run_id=run['run_id'])
        context = manifest.get('service_context')
        if context is not None: total_links += len(context['topology'])
        if total_links > 512: raise CaseError('topology link budget exceeded')
        runs[run['run_id']] = dict(manifest=manifest, context=context, adapter=adapter)
    return runs, evidence


def _fresh(carrier, request, reference, start, end, require_event=True):
    if carrier['clock_quality'] != 'synchronized' or carrier['clock_uncertainty_seconds'] is None: return False
    collected = timestamp(carrier['collected_at']) if carrier['collected_at'] is not None else None
    if collected is None: return False
    try:
        uncertainty = timedelta(seconds=carrier['clock_uncertainty_seconds'])
        if collected + uncertainty > reference or (reference - (collected - uncertainty)).total_seconds() > request['max_age_seconds']: return False
    except (OverflowError, ValueError): return False
    event = timestamp(carrier['event_time']) if carrier['event_time'] is not None else None
    if event is None: return not require_event
    try:
        return start <= event - uncertainty and event + uncertainty <= end and event + uncertainty <= reference and (reference - (event - uncertainty)).total_seconds() <= request['max_age_seconds']
    except OverflowError: return False


def _inside_interval(carrier, start, end):
    try:
        event = timestamp(carrier['event_time'])
        uncertainty = timedelta(seconds=carrier['clock_uncertainty_seconds'])
        return start <= event - uncertainty and event + uncertainty <= end
    except (OverflowError, ValueError, TypeError):
        return False


def _binding_ok(binding, request, runs, evidence, reference, start, end):
    key, topology_key = _ref(binding['record']), _ref(binding['topology_evidence'])
    item, topology_item = evidence.get(key), evidence.get(topology_key)
    if not item or not topology_item or item['row'] is None or topology_item['row'] is not None: return False
    selected = request['service']; topology_run = selected['topology_run_id']
    if topology_key[0] != topology_run or binding['service_id'] != selected['object_id']: return False
    topology = runs.get(topology_run, {}).get('context')
    if not topology or topology['service_ref'] != binding['service_id']: return False
    objects = {obj['id']:obj for obj in topology['objects']}
    service, resource = objects.get(binding['service_id']), objects.get(binding['resource_id'])
    if not service or service['type'] != 'service' or service['identity_state'] != 'known' or not resource or resource['identity_state'] != 'known': return False
    if binding['resource_id'] != binding['service_id'] and not any(link['state'] == 'verified' and {link['from_id'],link['to_id']} == {binding['service_id'],binding['resource_id']} for link in topology['topology']): return False
    carrier = item['carrier']
    if (carrier['source'], carrier['source_native_id']) != (binding['source'], binding['source_native_id']): return False
    if not _fresh(carrier, request, reference, start, end) or not _fresh(topology_item['carrier'], request, reference, start, end, False): return False
    begin, until = timestamp(binding['valid_from']), timestamp(binding['valid_until'])
    if not _inside_interval(carrier, begin, until): return False
    if runs[key[0]]['adapter'].get('parse_status') != 'complete' or runs[topology_run]['adapter'].get('parse_status') != 'complete': return False
    return True


def _qualified(key):
    return dict(run_id=key[0], evidence_id=key[1])


def _same(left, right):
    a, b = left['row'], right['row']
    if left['resource'] != right['resource'] or (left['carrier']['source'],left['carrier']['source_native_id']) != (right['carrier']['source'],right['carrier']['source_native_id']): return False
    if a['direction'] != b['direction'] or a['direction'] not in ('ingress','egress','bidirectional') or a['unit'] in (None,'unknown') or a['unit'] != b['unit']: return False
    if a['denominator'] != b['denominator'] or a['denominator'] in ('0','unknown') or a['sample_interval_seconds'] != b['sample_interval_seconds']: return False
    if a['counter_semantics'] != b['counter_semantics']: return False
    if a['counter_semantics'] == 'cumulative' and (a['denominator'] is None or a['sample_interval_seconds'] is None): return False
    return True


def _ordered(left, right):
    a, b = left['carrier'], right['carrier']
    try:
        return timestamp(a['event_time']) + timedelta(seconds=a['clock_uncertainty_seconds']) < timestamp(b['event_time']) - timedelta(seconds=b['clock_uncertainty_seconds'])
    except (OverflowError, ValueError):
        return False


def _counter_discontinuities(left, right, observations):
    """Find declared discontinuities that overlap the candidate counter interval."""
    try:
        begin = timestamp(left['carrier']['event_time']) - timedelta(seconds=left['carrier']['clock_uncertainty_seconds'])
        end = timestamp(right['carrier']['event_time']) + timedelta(seconds=right['carrier']['clock_uncertainty_seconds'])
        for item in observations:
            row = item['row']
            if item['key'] in (left['key'], right['key']) or row['metric'] != left['row']['metric'] or not _same_scope(left, item): continue
            if row['reset_state'] == 'none' and row['counter_semantics'] == 'cumulative': continue
            event = timestamp(item['carrier']['event_time'])
            uncertainty = timedelta(seconds=item['carrier']['clock_uncertainty_seconds'])
            if event + uncertainty >= begin and event - uncertainty <= end: return True
    except (OverflowError, ValueError):
        return True
    return False


def _finding(code, layer, items, message, counters=()):
    refs = []
    for item in items:
        for ref in (item['key'], item['topology_key']):
            if ref not in refs: refs.append(ref)
    counter_refs = list(dict.fromkeys(item['key'] for item in counters))
    if len(refs) > 32 or len(counter_refs) > 32: raise CaseError('finding reference budget exceeded')
    return dict(code=code, layer=layer, resource_id=None, observation=message, hypothesis='Investigate this scoped observation with the owning team.', support=[_qualified(key) for key in refs], counterevidence=[_qualified(key) for key in counter_refs], limitations=['Source and mapping assertions are not authenticated; other layers may be unobserved.'])


def _same_scope(a, b):
    return a['resource'] == b['resource'] and (a['carrier']['source'],a['carrier']['source_native_id']) == (b['carrier']['source'],b['carrier']['source_native_id']) and a['row']['direction'] == b['row']['direction'] and a['row']['direction'] not in (None, 'unknown')


def _same_event(a, b):
    try:
        left, right = a['carrier'], b['carrier']
        uncertainty = left['clock_uncertainty_seconds'] + right['clock_uncertainty_seconds']
        return math.isfinite(uncertainty) and abs((timestamp(left['event_time']) - timestamp(right['event_time'])).total_seconds()) <= uncertainty
    except (ValueError, OverflowError):
        return False


def _collect_bound(request, runs, evidence, reference, start, end):
    usable = {}; gaps = set()
    for binding in request['bindings']:
        key = _ref(binding['record'])
        item = evidence.get(key)
        if not item:
            gaps.add('missing_evidence'); continue
        if not _fresh(item['carrier'], request, reference, start, end):
            carrier = item['carrier']
            if carrier['clock_quality'] != 'synchronized' or carrier['clock_uncertainty_seconds'] is None or carrier['event_time'] is None: gaps.add('clock_uncertain')
            else: gaps.add('stale_or_outside_window')
            continue
        topology_item = evidence.get(_ref(binding['topology_evidence']))
        if topology_item is not None and not _fresh(topology_item['carrier'], request, reference, start, end, False):
            topology_clock = topology_item['carrier']
            if topology_clock['clock_quality'] != 'synchronized' or topology_clock['clock_uncertainty_seconds'] is None: gaps.add('clock_uncertain')
            else: gaps.add('stale_or_outside_window')
            continue
        if not _binding_ok(binding, request, runs, evidence, reference, start, end):
            gaps.add('unverified_or_mismatched_mapping'); continue
        row = item['row']
        if not isinstance(row, dict) or 'metric' not in row: continue
        usable[key] = dict(item, key=key, topology_key=_ref(binding['topology_evidence']), resource=binding['resource_id'])
    return usable, gaps




def _bounded_worker(process_factory, request_bytes, timeout=5):
    """Run the caller's fixed worker with a bounded result file and watchdog."""
    if len(request_bytes) > LIMIT: raise CaseError('analysis input limit exceeded')
    with tempfile.TemporaryDirectory(prefix='analysis-') as temp:
        result_path = Path(temp)/'result.json'
        process = process_factory(request_bytes, result_path)
        process.start()
        try:
            process.join(timeout)
            if process.is_alive():
                return dict(schema_version=1,status='insufficient_evidence',service=None,findings=[],gaps=['analysis_timeout'],next_checks=['Retry with a smaller bounded evidence set.'])
            if process.exitcode != 0: raise CaseError('analysis worker failed')
            data = read_confined(Path(temp), 'result.json', LIMIT)
            result = strict_json(data, True)
            if not isinstance(result, dict) or result.get('ok') is not True: raise CaseError('invalid analysis inputs')
            return result['result']
        finally:
            if process.is_alive():
                process.terminate(); process.join(1)
                if process.is_alive(): process.kill()
            process.join()
