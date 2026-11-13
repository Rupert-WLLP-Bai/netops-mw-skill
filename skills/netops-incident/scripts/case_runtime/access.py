"""Bounded, offline access observations from checked M2 evidence bundles."""
from __future__ import annotations

import json
import math
import multiprocessing
import os
import tempfile
from datetime import timedelta
from pathlib import Path

from .carrier import bounded
from .evidence import read_confined, strict_json, validate_run
from .store import CaseError, timestamp, token

LIMIT = 1024 * 1024
REQUEST_FIELDS = {'schema_version', 'reference_time', 'window_start', 'window_end', 'max_age_seconds', 'service', 'runs', 'bindings', 'optical_profiles'}
RUN_FIELDS = {'run_id', 'run_dir', 'expected_summary_hashes'}
BINDING_FIELDS = {'record', 'topology_evidence', 'service_id', 'resource_id', 'source', 'source_native_id', 'valid_from', 'valid_until', 'authority'}
PROFILE_FIELDS = {'profile_id', 'device_model', 'source', 'valid_from', 'valid_until', 'direction', 'unit', 'limit_evidence', 'device_model_evidence'}
REF_FIELDS = {'run_id', 'evidence_id'}
RECORD_FIELDS = {'metric', 'value', 'unit', 'direction', 'denominator', 'sample_interval_seconds', 'sample_count', 'counter_semantics', 'reset_state', 'event_time', 'object_id'}
METRICS = {'optical_rx_power','optical_tx_power','optical_rx_lower_limit','optical_tx_lower_limit','device_model','los_state','lof_state','pon_session_state','fec_count','crc_count','pppoe_auth','ipoe_auth','aaa_result','dhcp_lease','dhcp_pool','service_vlan_expected','service_vlan_actual','forwarding_state','application_state','wifi_state'}
ENUMS = {'los_state':{'active','clear','unknown'}, 'lof_state':{'active','clear','unknown'}, 'pon_session_state':{'up','down','unknown'}, 'pppoe_auth':{'accept','reject','unknown'}, 'ipoe_auth':{'accept','reject','unknown'}, 'aaa_result':{'accept','reject','unknown'}, 'dhcp_lease':{'assigned','failed','unknown'}, 'dhcp_pool':{'available','exhausted','unknown'}, 'forwarding_state':{'pass','fail','unknown'}, 'application_state':{'pass','fail','unknown'}, 'wifi_state':{'pass','fail','unknown'}}


def _object(value, keys):
    if not isinstance(value, dict) or set(value) != keys: raise CaseError('invalid access request fields')


def _ref(value):
    _object(value, REF_FIELDS)
    return (token(value['run_id'], 'run_id'), token(value['evidence_id'], 'evidence_id'))


def _validate_request(request):
    bounded(request)
    pending = [request]
    while pending:
        item = pending.pop()
        if isinstance(item, dict): pending.extend(item.keys()); pending.extend(item.values())
        elif isinstance(item, list): pending.extend(item)
        elif isinstance(item, str) and any(ord(char) < 32 or ord(char) == 127 for char in item): raise CaseError('control character in access request')
    _object(request, REQUEST_FIELDS)
    if isinstance(request['schema_version'], bool) or request['schema_version'] != 1: raise CaseError('invalid access version')
    reference, start, end = (timestamp(request[key]) for key in ('reference_time', 'window_start', 'window_end'))
    if start > end or end > reference: raise CaseError('invalid access window')
    age = request['max_age_seconds']
    try:
        if isinstance(age, bool) or not isinstance(age, (int, float)) or not math.isfinite(age) or age < 0: raise CaseError('invalid freshness policy')
    except OverflowError as exc: raise CaseError('invalid freshness policy') from exc
    _object(request['service'], {'topology_run_id', 'object_id'})
    token(request['service']['topology_run_id'], 'topology run id'); token(request['service']['object_id'], 'service id')
    runs, bindings, profiles = request['runs'], request['bindings'], request['optical_profiles']
    if not isinstance(runs, list) or not 1 <= len(runs) <= 8 or not isinstance(bindings, list) or len(bindings) > 512 or not isinstance(profiles, list) or len(profiles) > 256: raise CaseError('access request count exceeded')
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
    for profile in profiles:
        _object(profile, PROFILE_FIELDS)
        for field in ('profile_id', 'device_model', 'source'): token(profile[field], field)
        if not isinstance(profile['unit'], str) or not profile['unit'] or len(profile['unit']) > 128 or not profile['unit'].isprintable(): raise CaseError('invalid profile unit')
        if profile['direction'] not in ('ingress','egress','bidirectional'): raise CaseError('invalid profile direction')
        if timestamp(profile['valid_from']) > timestamp(profile['valid_until']): raise CaseError('invalid profile interval')
        _ref(profile['limit_evidence']); _ref(profile['device_model_evidence'])
    return reference, start, end


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
                    _object(row, RECORD_FIELDS)
                    token(row['metric'], 'metric')
                    if row['direction'] not in ('ingress','egress','bidirectional','unknown') or not (row['value'] is None or isinstance(row['value'], (str,int,float))) or isinstance(row['value'], bool): raise CaseError('invalid access observation value')
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


def _coverage_eligible(item):
    row = item['row']; metric, value = row['metric'], row['value']
    if row['direction'] not in ('ingress','egress') or value is None or value == 'unknown': return False
    count = row['sample_count']
    try:
        if isinstance(count,bool) or not isinstance(count,(int,float)) or not math.isfinite(count) or count <= 0: return False
    except OverflowError:
        return False
    if metric in ENUMS: return value in ENUMS[metric] and value != 'unknown'
    if metric in ('service_vlan_expected','service_vlan_actual'): return isinstance(value,str)
    if metric not in ('optical_rx_power','optical_tx_power','fec_count','crc_count'): return False
    if not isinstance(value,(int,float)) or isinstance(value,bool) or row['unit'] in (None,'unknown'): return False
    if row['reset_state'] != 'none' or row['counter_semantics'] == 'unknown': return False
    if metric in ('optical_rx_power','optical_tx_power') and row['counter_semantics'] != 'gauge': return False
    if metric in ('fec_count','crc_count') and row['counter_semantics'] != 'gauge' and (row['denominator'] in (None,'0','unknown') or row['sample_interval_seconds'] is None): return False
    return True


def _reverse_compatible(left, right):
    a,b = left['row'],right['row']
    return (a['direction'],b['direction']) in (('ingress','egress'),('egress','ingress')) and a['metric'] == b['metric'] and left['resource'] == right['resource'] and (left['carrier']['source'],left['carrier']['source_native_id']) == (right['carrier']['source'],right['carrier']['source_native_id']) and all(a[key] == b[key] for key in ('unit','denominator','sample_interval_seconds','counter_semantics','reset_state')) and _same_event(left,right)


def _optical_pairs(usable, profiles, evidence, runs, request, reference, start, end):
    matches = []; work = 0
    for profile in profiles:
        limit_key, model_key = _ref(profile['limit_evidence']), _ref(profile['device_model_evidence'])
        limit, model = evidence.get(limit_key), usable.get(model_key)
        if not limit or not model or not limit['row'] or not model['row'] or 'metric' not in limit['row']: continue
        if model['row']['metric'] != 'device_model' or model['row']['value'] != profile['device_model']: continue
        lc = limit['carrier']; lr = limit['row']
        if (lc['source'],lc['source_native_id']) != (profile['source'],profile['profile_id']) or runs[limit_key[0]]['adapter'].get('parse_status') != 'complete' or not _fresh(lc, request, reference, start, end): continue
        if lr['metric'] not in ('optical_rx_lower_limit','optical_tx_lower_limit') or not isinstance(lr['value'], (int,float)) or isinstance(lr['value'], bool) or lr['unit'] != profile['unit'] or lr['direction'] != profile['direction']: continue
        metric = 'optical_rx_power' if lr['metric'] == 'optical_rx_lower_limit' else 'optical_tx_power'
        begin, until = timestamp(profile['valid_from']), timestamp(profile['valid_until'])
        if not _inside_interval(lc, begin, until) or not _inside_interval(model['carrier'], begin, until): continue
        samples = [item for item in usable.values() if item['row']['metric'] == metric and item['resource'] == model['resource'] and item['row']['direction'] == profile['direction'] and item['row']['unit'] == profile['unit'] and isinstance(item['row']['value'], (int,float)) and not isinstance(item['row']['value'], bool) and item['row']['counter_semantics'] == 'gauge' and item['row']['reset_state'] == 'none' and item['row']['sample_count'] and _inside_interval(item['carrier'], begin, until)]
        for first in samples:
            for second in samples:
                work += 1
                if work > 4096: raise CaseError('optical comparison budget exceeded')
                if first['key'] != second['key'] and _same(first, second) and _ordered(first, second):
                    limit_item = dict(limit, key=limit_key, topology_key=limit_key, resource=model['resource'])
                    matches.append((first, second, limit_item, model, lr['value']))
    return matches


def analyze(request):
    reference, start, end = _validate_request(request)
    runs, evidence = _load_runs(request)
    usable = {}; gaps = set()
    if any(item['row'] is not None and 'metric' in item['row'] and item['row']['metric'] not in METRICS for item in evidence.values()):
        gaps.add('unsupported_metric')
    for item in evidence.values():
        row = item['row']
        if not row or 'metric' not in row or row['metric'] not in METRICS: continue
        if row['value'] is None or row['value'] == 'unknown': gaps.add('missing_observation_value')
        elif row['metric'] in ENUMS and row['value'] not in ENUMS[row['metric']]: gaps.add('unsupported_value')
        elif row['metric'] in ('service_vlan_expected','service_vlan_actual','device_model') and not isinstance(row['value'],str): gaps.add('unsupported_value')
        elif row['metric'] in ('optical_rx_power','optical_tx_power','optical_rx_lower_limit','optical_tx_lower_limit','fec_count','crc_count') and not isinstance(row['value'],(int,float)): gaps.add('unsupported_value')
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
        entry = dict(item, key=key, topology_key=_ref(binding['topology_evidence']), resource=binding['resource_id'])
        usable[key] = entry
    observations = list(usable.values())
    coverage = [item for item in observations if _coverage_eligible(item)]
    if not coverage or any(not any(_reverse_compatible(item, other) for other in coverage) for item in coverage): gaps.add('missing_reverse_direction')
    findings = []
    def add(finding):
        if len(findings) >= 512: raise CaseError('finding budget exceeded')
        findings.append(finding)
    single_rules = {
        ('los_state','active'):('los_active','access','The source reported an active LOS condition.'),
        ('lof_state','active'):('lof_active','access','The source reported an active LOF condition.'),
        ('pppoe_auth','reject'):('auth_reject','aggregation_subscriber_edge','The source reported an authentication rejection.'),
        ('ipoe_auth','reject'):('auth_reject','aggregation_subscriber_edge','The source reported an authentication rejection.'),
        ('aaa_result','reject'):('auth_reject','aggregation_subscriber_edge','The source reported an authentication rejection.'),
        ('dhcp_lease','failed'):('dhcp_failure','aggregation_subscriber_edge','The source reported an address assignment failure.'),
        ('dhcp_pool','exhausted'):('dhcp_exhaustion','aggregation_subscriber_edge','The source reported an exhausted address pool.'),
        ('wifi_state','fail'):('wifi_failure','endpoint_lan','The source reported a Wi-Fi failure.'),
        ('forwarding_state','fail'):('forwarding_failure','access','The source reported forwarding failure.'),
        ('application_state','fail'):('application_failure','destination_application','The source reported an application failure.')}
    opposites = {'los_state':'clear','lof_state':'clear','pppoe_auth':'accept','ipoe_auth':'accept','aaa_result':'accept','dhcp_lease':'assigned','dhcp_pool':'available','wifi_state':'pass','forwarding_state':'pass','application_state':'pass'}
    optical_observations = [item for item in observations if item['row']['metric'] in ('optical_rx_power','optical_tx_power') and isinstance(item['row']['value'],(int,float)) and not isinstance(item['row']['value'],bool) and item['row']['counter_semantics'] == 'gauge' and item['row']['reset_state'] == 'none' and item['row']['sample_count'] and item['row']['unit'] is not None]
    conflicted = set()
    for index, first in enumerate(optical_observations):
        for second in optical_observations[index+1:]:
            if first['row']['metric'] == second['row']['metric'] and first['row']['value'] != second['row']['value'] and first['row']['sample_count'] == second['row']['sample_count'] and _same(first,second) and _same_event(first,second):
                conflicted.update((first['key'],second['key']))
                gaps.add('conflicting_observations')
                conflict = _finding('optical_conflict','access',[first],'Comparable optical observations disagree at the same time.',[second])
                conflict['limitations'].append('The disputed readings do not establish optical degradation.')
                add(conflict)
    optics = _optical_pairs(usable, request['optical_profiles'], evidence, runs, request, reference, start, end)
    if any(item['row']['metric'] in ('optical_rx_power','optical_tx_power') for item in observations) and not optics: gaps.add('missing_comparable_optical_profile')
    normal_optics = []
    for first, second, limit, model, threshold in optics:
        if first['key'] in conflicted or second['key'] in conflicted: continue
        if first['row']['value'] >= threshold and second['row']['value'] >= threshold:
            normal_optics.append((first,second,limit,model))
        if second['row']['value'] < first['row']['value'] and second['row']['value'] < threshold:
            add(_finding('optical_degradation','access',[first,second,limit,model],'Comparable optical readings declined below the cited profile limit.'))
    for item in observations:
        row = item['row']; metric, value = row['metric'], row['value']
        if metric in ('fec_count','crc_count'):
            semantics = row['counter_semantics']
            if semantics == 'unknown': gaps.add('unknown_counter_semantics')
            elif semantics != 'cumulative': gaps.add('counter_semantics_not_cumulative')
            if not row['sample_count']: gaps.add('missing_sample_count')
            if row['unit'] in (None,'unknown'): gaps.add('missing_counter_unit')
            if semantics != 'gauge':
                if row['sample_interval_seconds'] is None: gaps.add('missing_sample_interval')
                if row['denominator'] in (None,'0','unknown'): gaps.add('missing_counter_denominator')
            if row['reset_state'] in ('reset','wrap'): gaps.add('counter_reset')
            elif row['reset_state'] == 'unknown': gaps.add('unknown_counter_reset_state')
        if row['direction'] not in ('ingress','egress','bidirectional'):
            if metric != 'device_model': gaps.add('missing_direction')
            continue
        rule = single_rules.get((metric,value))
        if rule is None: continue
        conflicts = [other for other in observations if other['row']['metric'] == metric and other['row']['value'] == opposites[metric] and _same_scope(item,other) and _same_event(item,other)]
        if conflicts:
            gaps.add('conflicting_observations'); continue
        counters = []
        if metric == 'wifi_state':
            for first,second,limit,model in normal_optics:
                if _same_scope(item,second): counters.extend((first,second,limit,model))
        if metric == 'dhcp_lease': counters = [other for other in observations if other['row']['metric'] == 'aaa_result' and other['row']['value'] == 'accept' and _same_scope(item,other) and _same_event(item,other)]
        if metric in ('pppoe_auth','ipoe_auth','aaa_result'):
            counters = [other for other in observations if other['row']['metric'] in ('pppoe_auth','ipoe_auth','aaa_result') and other['row']['value'] == 'accept' and _same_scope(item,other) and _same_event(item,other)]
        finding = _finding(rule[0],rule[1],[item],rule[2],counters)
        if metric == 'wifi_state' and counters:
            finding['limitations'].append('Optical samples do not exclude changes between observations.')
        add(finding)
    pon = [item for item in observations if item['row']['metric'] == 'pon_session_state' and item['row']['value'] in ('up','down')]
    groups = {}
    for item in pon:
        key = (item['resource'], item['carrier']['source'], item['carrier']['source_native_id'], item['row']['direction'])
        groups.setdefault(key, []).append(item)
    for items in groups.values():
        items.sort(key=lambda item: timestamp(item['carrier']['event_time']))
        for a,b,c in zip(items,items[1:],items[2:]):
            if a['row']['value'] == c['row']['value'] != b['row']['value'] and _same_scope(a,b) and _same_scope(b,c) and _ordered(a,b) and _ordered(b,c):
                add(_finding('pon_flap','access',[a,b,c],'The source reported an ordered PON session flap.'))
    expected = [item for item in observations if item['row']['metric'] == 'service_vlan_expected']
    actual = [item for item in observations if item['row']['metric'] == 'service_vlan_actual']
    for a in expected:
        for b in actual:
            if isinstance(a['row']['value'],str) and isinstance(b['row']['value'],str) and a['row']['value'] != 'unknown' and b['row']['value'] != 'unknown' and a['row']['value'] != b['row']['value'] and a['row']['unit'] == b['row']['unit'] and a['row']['denominator'] == b['row']['denominator'] and _same_scope(a,b) and _same_event(a,b):
                add(_finding('vlan_mismatch','aggregation_subscriber_edge',[a,b],'The explicitly reported service VLAN values differ.'))
    counters = [item for item in observations if item['row']['metric'] in ('fec_count','crc_count')]
    for a in counters:
        for b in counters:
            if a['row']['metric'] == b['row']['metric'] and a['row']['counter_semantics'] == b['row']['counter_semantics'] == 'cumulative' and a['row']['reset_state'] == b['row']['reset_state'] == 'none' and a['row']['sample_count'] and b['row']['sample_count'] and isinstance(a['row']['value'], (int,float)) and not isinstance(a['row']['value'],bool) and isinstance(b['row']['value'], (int,float)) and not isinstance(b['row']['value'],bool) and 0 <= a['row']['value'] < b['row']['value'] and _same(a,b) and _ordered(a,b):
                finding = _finding('counter_increase','access',[a,b],'A comparable source-reported error counter increased.')
                finding['limitations'].append('An increase alone does not establish a fault or service impact.')
                add(finding)
    unique = []; seen = set()
    for finding in findings:
        key = json.dumps(finding,sort_keys=True,separators=(',',':'))
        if key not in seen: seen.add(key); unique.append(finding)
    if len(unique) > 512: raise CaseError('finding budget exceeded')
    has_fault_observation = any(finding['code'] not in ('counter_increase','optical_conflict') for finding in unique)
    return dict(schema_version=1, status='fault_observed' if has_fault_observation else 'insufficient_evidence', service=request['service'], findings=unique, gaps=sorted(gaps), next_checks=['Obtain scoped, current and comparable evidence for unresolved gaps.'] if gaps else [])


def _worker(path, request_bytes):
    try:
        request = strict_json(request_bytes, True)
        result = {'ok':True, 'result':analyze(request)}
        data = json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
        if len(data) > LIMIT: raise CaseError('analysis output budget exceeded')
    except Exception:
        data = b'{"ok":false}'
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as stream: stream.write(data)


def _process(request_bytes, result_path):
    return multiprocessing.get_context('spawn').Process(target=_worker, args=(str(result_path),request_bytes), daemon=True)


def analyze_bounded(request_bytes, timeout=5):
    if len(request_bytes) > LIMIT: raise CaseError('access input limit exceeded')
    with tempfile.TemporaryDirectory(prefix='access-analysis-') as temp:
        result_path = Path(temp)/'result.json'
        process = _process(request_bytes, result_path)
        process.start()
        try:
            process.join(timeout)
            if process.is_alive():
                return dict(schema_version=1,status='insufficient_evidence',service=None,findings=[],gaps=['analysis_timeout'],next_checks=['Retry with a smaller bounded evidence set.'])
            if process.exitcode != 0: raise CaseError('analysis worker failed')
            data = read_confined(Path(temp), 'result.json', LIMIT)
            result = strict_json(data, True)
            if not isinstance(result, dict) or result.get('ok') is not True: raise CaseError('invalid access inputs')
            return result['result']
        finally:
            if process.is_alive():
                process.terminate(); process.join(1)
                if process.is_alive(): process.kill()
            process.join()
