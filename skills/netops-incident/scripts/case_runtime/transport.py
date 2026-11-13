"""Offline IP transport observations with explicit scope and source evidence."""
from __future__ import annotations
import json
import math
import multiprocessing
import os
from .evidence import strict_json
from .store import CaseError, timestamp, token
from .analysis_common import (LIMIT, _object, _ref, _validate_base, _load_runs,
    _fresh, _inside_interval, _collect_bound, _same, _ordered, _finding,
    _same_scope, _same_event, _bounded_worker, _counter_discontinuities)

FIELDS = {'schema_version','reference_time','window_start','window_end','max_age_seconds','service','runs','bindings','transport_profiles','measurement_windows'}
PROFILE_FIELDS = {'profile_id','source','resource_id','direction','unit','valid_from','valid_until','aggregation','utilization_limit_evidence','aggregation_evidence'}
WINDOW_FIELDS = {'subjects','start_evidence','end_evidence','aggregation_evidence'}
ENUMS = {'bgp_peer_state':{'up','down','unknown'},'igp_adjacency_state':{'up','down','unknown'},'bgp_prefix_state':{'present','withdrawn','unknown'},'route_state':{'present','withdrawn','unknown'},'lsp_state':{'up','down','unknown'},'sr_policy_state':{'up','down','unknown'},'lag_member_state':{'up','down','degraded','unknown'},'large_payload_result':{'pass','fail','unknown'},'small_payload_result':{'pass','fail','unknown'},'forwarding_state':{'pass','fail','unknown'},'service_operation':{'pass','fail','unknown'},'fragmentation_needed':{'seen','not_seen','unknown'},'window_start':{'declared'},'window_end':{'declared'},'window_aggregation':{'mean','max','counter_delta'},'profile_aggregation':{'mean','max'}}
LABELS = {'route_prefix','service_prefix','route_vrf','service_vrf','next_hop','ecmp_path','flow_scope','qos_class','traceroute_hop'}
GAUGES = {'interface_utilization','queue_utilization','utilization_limit','configured_mtu','effective_mtu','tunnel_overhead','probe_ip_packet_size'}
COUNTERS = {'interface_crc','interface_errors','interface_discards','queue_drops','qos_class_drops'}
METRICS = set(ENUMS) | LABELS | GAUGES | COUNTERS
# Control-plane states and descriptive metadata do not prove reverse data-plane coverage.
COVERAGE = {'interface_utilization','queue_utilization','large_payload_result','small_payload_result','forwarding_state','service_operation'} | COUNTERS
NEUTRAL = {'bgp_peer_event','igp_event','igp_flap','route_event','lsp_event','sr_policy_event','lag_member_event','next_hop_event','counter_increase','traceroute_observation','ecmp_asymmetry','mtu_discrepancy','pmtud_suspected','profile_conflict'}


def _validate_request(request):
    reference,start,end = _validate_base(request,FIELDS)
    profiles,windows = request['transport_profiles'],request['measurement_windows']
    if not isinstance(profiles,list) or len(profiles)>256 or not isinstance(windows,list) or len(windows)>256: raise CaseError('transport declaration budget exceeded')
    for profile in profiles:
        _object(profile,PROFILE_FIELDS)
        for key in ('profile_id','source','resource_id'): token(profile[key],key)
        if profile['direction'] not in ('ingress','egress','bidirectional') or profile['aggregation'] not in ('mean','max'): raise CaseError('invalid transport profile')
        if not isinstance(profile['unit'],str) or not profile['unit'].strip() or len(profile['unit'])>128 or not profile['unit'].isprintable(): raise CaseError('invalid transport profile unit')
        if timestamp(profile['valid_from']) > timestamp(profile['valid_until']): raise CaseError('invalid profile validity')
        _ref(profile['utilization_limit_evidence']); _ref(profile['aggregation_evidence'])
    for window in windows:
        _object(window,WINDOW_FIELDS)
        subjects = window['subjects']
        if not isinstance(subjects,list) or len(subjects) not in (1,2): raise CaseError('invalid window subjects')
        keys = [_ref(item) for item in subjects]
        if len(set(keys)) != len(keys): raise CaseError('duplicate window subjects')
        for key in ('start_evidence','end_evidence','aggregation_evidence'): _ref(window[key])
    return reference,start,end


def _valid(item):
    row = item['row']; metric,value = row['metric'],row['value']; count = row['sample_count']
    if metric not in METRICS or value is None or value == 'unknown' or row['direction'] not in ('ingress','egress','bidirectional'): return False
    try:
        if isinstance(count,bool) or not isinstance(count,(int,float)) or not math.isfinite(count) or count <= 0: return False
    except OverflowError: return False
    if metric in ENUMS: return isinstance(value,str) and value in ENUMS[metric] and value != 'unknown'
    if metric in LABELS: return isinstance(value,str) and value != 'unknown'
    if isinstance(value,bool) or not isinstance(value,(int,float)) or value < 0: return False
    if row['unit'] in (None,'unknown'): return False
    if metric in GAUGES: return row['counter_semantics']=='gauge' and row['reset_state']=='none'
    return row['counter_semantics']=='cumulative' and row['reset_state']=='none' and row['denominator'] not in (None,'0','unknown') and row['sample_interval_seconds'] is not None


def _reverse(a,b):
    left,right = a['row'],b['row']
    return (left['direction'],right['direction']) in (('ingress','egress'),('egress','ingress')) and left['metric']==right['metric'] and a['resource']==b['resource'] and (a['carrier']['source'],a['carrier']['source_native_id'])==(b['carrier']['source'],b['carrier']['source_native_id']) and all(left[key]==right[key] for key in ('unit','denominator','sample_interval_seconds','counter_semantics','reset_state')) and _same_event(a,b)


def _identity(a,b):
    return a['resource']==b['resource'] and (a['carrier']['source'],a['carrier']['source_native_id'])==(b['carrier']['source'],b['carrier']['source_native_id'])


def _matching(items, metric, anchor):
    return [item for item in items if item['row']['metric']==metric and _same_scope(item,anchor) and _same_event(item,anchor)]


def _one(items, metric, anchor, gaps):
    found = _matching(items,metric,anchor)
    values = {(item['row']['value'],item['row']['unit'],item['row']['denominator'],item['row']['sample_interval_seconds']) for item in found}
    if len(values)>1:
        gaps.add('conflicting_observations'); return None
    return found[0] if found else None


def _evidence_item(item, key, resource):
    return dict(item,key=key,topology_key=key,resource=resource)


def _profile(profile, resource, direction, aggregation, unit, evidence, runs, request, reference, start, end):
    if profile['resource_id']!=resource or profile['direction']!=direction or profile['aggregation']!=aggregation or profile['unit']!=unit: return None
    limit_key,agg_key = _ref(profile['utilization_limit_evidence']),_ref(profile['aggregation_evidence'])
    limit,agg = evidence.get(limit_key),evidence.get(agg_key)
    if not limit or not agg or not limit['row'] or not agg['row'] or 'metric' not in limit['row'] or 'metric' not in agg['row']: return None
    begin,until = timestamp(profile['valid_from']),timestamp(profile['valid_until'])
    for item,key in ((limit,limit_key),(agg,agg_key)):
        carrier = item['carrier']
        if (carrier['source'],carrier['source_native_id']) != (profile['source'],profile['profile_id']) or runs[key[0]]['adapter'].get('parse_status')!='complete' or not _fresh(carrier,request,reference,start,end) or not _inside_interval(carrier,begin,until): return None
        if not _valid(item): return None
    if limit['row']['metric']!='utilization_limit' or limit['row']['unit']!=unit or limit['row']['direction']!=direction or agg['row']['metric']!='profile_aggregation' or agg['row']['value']!=aggregation or agg['row']['direction']!=direction: return None
    return _evidence_item(limit,limit_key,resource),_evidence_item(agg,agg_key,resource)


def _windows(request, usable, gaps):
    result = {}; seen = set()
    for declaration in request['measurement_windows']:
        subject_keys = tuple(_ref(ref) for ref in declaration['subjects'])
        key = tuple(sorted(subject_keys))
        if key in seen:
            gaps.add('ambiguous_measurement_window'); result[key] = None; continue
        seen.add(key)
        subjects = [usable.get(ref) for ref in subject_keys]
        start = usable.get(_ref(declaration['start_evidence'])); end = usable.get(_ref(declaration['end_evidence'])); agg = usable.get(_ref(declaration['aggregation_evidence']))
        if not start or not end or not agg or any(not item for item in subjects): gaps.add('incompatible_window'); result[key]=None; continue
        if any(not _valid(item) for item in subjects+[start,end,agg]): gaps.add('incompatible_window'); result[key]=None; continue
        if start['row']['metric']!='window_start' or start['row']['value']!='declared' or end['row']['metric']!='window_end' or end['row']['value']!='declared' or agg['row']['metric']!='window_aggregation' or not _ordered(start,end): gaps.add('incompatible_window'); result[key]=None; continue
        if not all(_same_scope(subjects[0],item) for item in subjects[1:]+[start,end,agg]) or not _same_event(agg,end): gaps.add('incompatible_window'); result[key]=None; continue
        aggregation = agg['row']['value']
        if len(subjects)==1:
            if aggregation not in ('mean','max') or not (_same_event(subjects[0],end) or _inside_interval(subjects[0]['carrier'],timestamp(start['carrier']['event_time']),timestamp(end['carrier']['event_time']))): gaps.add('incompatible_window'); result[key]=None; continue
        elif aggregation!='counter_delta' or not _same_event(subjects[0],start) or not _same_event(subjects[1],end): gaps.add('incompatible_window'); result[key]=None; continue
        result[key] = dict(subjects=subjects,start=start,end=end,aggregation=agg)
    return result


def _same_boundaries(first,second):
    return all(first[side]['carrier']['event_time']==second[side]['carrier']['event_time'] and first[side]['carrier']['clock_uncertainty_seconds']==second[side]['carrier']['clock_uncertainty_seconds'] for side in ('start','end'))


def _coverage_window(item, windows, gaps):
    applicable = [window for keys,window in windows.items() if item['key'] in keys]
    if not applicable: gaps.add('missing_measurement_window'); return None
    if len(applicable)>1: gaps.add('ambiguous_measurement_window'); return None
    return applicable[0]


def _profile_conflicts(profile, chosen, evidence, runs, request, reference, start, end):
    conflicts = []
    begin,until = timestamp(profile['valid_from']),timestamp(profile['valid_until'])
    for key,item in evidence.items():
        row = item['row']
        if not row or row.get('metric') not in ('utilization_limit','profile_aggregation'): continue
        selected = chosen[0] if row['metric']=='utilization_limit' else chosen[1]
        if key == selected['key'] or row['value'] == selected['row']['value']: continue
        carrier = item['carrier']
        if (carrier['source'],carrier['source_native_id']) != (profile['source'],profile['profile_id']): continue
        if row['direction'] != profile['direction'] or row['unit'] != selected['row']['unit']: continue
        if runs[key[0]]['adapter'].get('parse_status')!='complete' or not _fresh(carrier,request,reference,start,end) or not _inside_interval(carrier,begin,until) or not _valid(item): continue
        candidate = _evidence_item(item,key,profile['resource_id'])
        if _same_event(candidate,selected): conflicts.append(candidate)
    return conflicts


def _support_window(window):
    return [window['start'],window['end'],window['aggregation']]


def analyze(request):
    reference,start,end = _validate_request(request)
    runs,evidence = _load_runs(request)
    usable,gaps = _collect_bound(request,runs,evidence,reference,start,end)
    for item in evidence.values():
        row = item['row']
        if not row or 'metric' not in row: continue
        metric,value = row['metric'],row['value']
        if metric not in METRICS: gaps.add('unsupported_metric')
        elif value is None or value=='unknown': gaps.add('missing_observation_value')
        elif metric in ENUMS and value not in ENUMS[metric]: gaps.add('unsupported_value')
        elif metric in LABELS and not isinstance(value,str): gaps.add('unsupported_value')
        elif metric in GAUGES | COUNTERS and (isinstance(value,bool) or not isinstance(value,(int,float)) or value<0): gaps.add('unsupported_value')
    observations = list(usable.values()); valid = [item for item in observations if _valid(item)]
    if any(item['row']['metric'] in METRICS and item['row']['value'] not in (None,'unknown') and not item['row']['sample_count'] for item in observations): gaps.add('missing_sample_count')
    if any(item['row']['metric'] in METRICS and item['row']['value'] not in (None,'unknown') and item['row']['direction']=='unknown' for item in observations): gaps.add('missing_direction')
    windows = _windows(request,usable,gaps)
    coverage = [item for item in valid if item['row']['metric'] in COVERAGE and item['row']['direction'] in ('ingress','egress')]
    aggregate = {'interface_utilization','queue_utilization'} | COUNTERS
    coverage_windows = {item['key']:_coverage_window(item,windows,gaps) for item in coverage if item['row']['metric'] in aggregate}
    def reverse_covered(item, other):
        if not _reverse(item,other): return False
        if item['row']['metric'] not in aggregate: return True
        left,right = coverage_windows[item['key']],coverage_windows[other['key']]
        if not left or not right: return False
        if not _same_boundaries(left,right) or left['aggregation']['row']['value'] != right['aggregation']['row']['value']:
            gaps.add('incompatible_window'); return False
        return True
    if not coverage or any(not any(reverse_covered(item,other) for other in coverage) for item in coverage): gaps.add('missing_reverse_direction')
    findings = []
    def add(code,items,message,counters=(),neutral=False):
        if len(findings)>=512: raise CaseError('transport finding budget exceeded')
        finding = _finding(code,'ip_bearer_transport',items,message,counters)
        if neutral: finding['limitations'].append('This observation alone does not establish customer impact or a fault cause.')
        if code in ('queue_condition','qos_class_condition'): finding['limitations'].append('The queue condition alone does not establish customer impact.')
        findings.append(finding)
    def pass_evidence(anchor):
        return [other for other in valid if other['row']['metric'] in ('service_operation','forwarding_state') and other['row']['value']=='pass' and _same_scope(anchor,other) and _same_event(anchor,other)]
    def _conflicting(item):
        row=item['row']; opposites={'down':'up','up':'down','withdrawn':'present','present':'withdrawn','fail':'pass','pass':'fail'}
        opposite=opposites.get(row['value'])
        if opposite and any(other['row']['metric']==row['metric'] and other['row']['value']==opposite and _same_scope(item,other) and _same_event(item,other) for other in valid): return True
        if row['metric'] in GAUGES | COUNTERS:
            return any(other['key']!=item['key'] and other['row']['metric']==row['metric'] and other['row']['value']!=row['value'] and other['row']['sample_count']==row['sample_count'] and _same(item,other) and _same_event(item,other) for other in valid)
        if row['metric'] in LABELS - {'traceroute_hop'}:
            return any(other['key']!=item['key'] and other['row']['metric']==row['metric'] and other['row']['value']!=row['value'] and _same_scope(item,other) and _same_event(item,other) for other in valid)
        return False
    conflict_cache = {item['key']:_conflicting(item) for item in valid}
    def conflicting(item): return conflict_cache[item['key']]
    events = {'bgp_peer_state':('bgp_peer_event','The source reported a BGP peer state.'),'igp_adjacency_state':('igp_event','The source reported an IGP adjacency state.'),'route_state':('route_event','The source reported a route state.'),'bgp_prefix_state':('route_event','The source reported a BGP prefix state.'),'lsp_state':('lsp_event','The source reported an LSP state.'),'sr_policy_state':('sr_policy_event','The source reported a segment-routing policy state.'),'lag_member_state':('lag_member_event','The source reported a LAG member state.'),'next_hop':('next_hop_event','The source reported a next-hop label.'),'traceroute_hop':('traceroute_observation','The source reported a single-vantage traceroute hop.')}
    for item in valid:
        metric,value=item['row']['metric'],item['row']['value']
        if metric in events:
            if conflicting(item): gaps.add('conflicting_observations'); continue
            code,message=events[metric]; add(code,[item],message,pass_evidence(item),True)
        if metric in ('forwarding_state','service_operation') and value=='fail':
            if conflicting(item): gaps.add('conflicting_observations'); continue
            add('service_failure',[item],'The source reported a scoped service or forwarding failure.')
    igp = [item for item in valid if item['row']['metric']=='igp_adjacency_state']
    groups = {}
    for item in igp:
        key=(item['resource'],item['carrier']['source'],item['carrier']['source_native_id'],item['row']['direction'])
        groups.setdefault(key,[]).append(item)
    for items in groups.values():
        items.sort(key=lambda item:timestamp(item['carrier']['event_time']))
        for a,b,c in zip(items,items[1:],items[2:]):
            if a['row']['value']==c['row']['value']!=b['row']['value'] and _ordered(a,b) and _ordered(b,c) and not any(conflicting(x) for x in (a,b,c)):
                add('igp_flap',[a,b,c],'The source reported an ordered IGP adjacency flap.',pass_evidence(c),True)
    for item in valid:
        if item['row']['metric'] not in ('route_state','bgp_prefix_state') or item['row']['value']!='withdrawn' or conflicting(item): continue
        parts = [_one(valid,metric,item,gaps) for metric in ('route_prefix','service_prefix','route_vrf','service_vrf')]
        failures = [other for other in valid if other['row']['metric'] in ('service_operation','forwarding_state') and other['row']['value']=='fail' and _same_scope(item,other) and _same_event(item,other) and not conflicting(other)]
        if any(part is None for part in parts): gaps.add('missing_prefix_or_vrf'); continue
        if parts[0]['row']['value']!=parts[1]['row']['value'] or parts[2]['row']['value']!=parts[3]['row']['value']: gaps.add('missing_prefix_or_vrf'); continue
        if failures:
            flow = _one(valid,'flow_scope',item,gaps)
            if not flow: gaps.add('missing_flow_scope'); continue
            add('route_service_correlation',[item]+parts+[flow,failures[0]],'The source reported a matching route withdrawal and scoped service failure.',pass_evidence(item))
    counter_items = [item for item in observations if item['row']['metric'] in COUNTERS]
    for item in counter_items:
        row=item['row']; semantics=row['counter_semantics']
        if semantics=='unknown': gaps.add('unknown_counter_semantics')
        elif semantics!='cumulative': gaps.add('counter_semantics_not_cumulative')
        if not row['sample_count']: gaps.add('missing_sample_count')
        if row['unit'] in (None,'unknown'): gaps.add('missing_counter_unit')
        if semantics!='gauge':
            if row['sample_interval_seconds'] is None: gaps.add('missing_sample_interval')
            if row['denominator'] in (None,'0','unknown'): gaps.add('missing_counter_denominator')
        if row['reset_state'] in ('reset','wrap'): gaps.add('counter_reset')
        elif row['reset_state']=='unknown': gaps.add('unknown_counter_reset_state')
    counters = [item for item in valid if item['row']['metric'] in COUNTERS]
    increments = []; work = 0
    for a in counters:
        for b in counters:
            work += 1
            if work>262144: raise CaseError('counter comparison budget exceeded')
            if a['row']['metric']==b['row']['metric'] and _identity(a,b) and _ordered(a,b) and not _same(a,b): gaps.add('incompatible_counter_samples')
            if a['row']['metric']==b['row']['metric'] and _same(a,b) and _ordered(a,b) and b['row']['value']>a['row']['value'] and not conflicting(a) and not conflicting(b):
                if _counter_discontinuities(a,b,counter_items): gaps.add('counter_discontinuity'); continue
                increments.append((a,b)); add('counter_increase',[a,b],'A comparable source-reported counter increased.',pass_evidence(b),True)
    for a,b in increments:
        if a['row']['metric'] not in ('queue_drops','qos_class_drops'): continue
        drop_key = tuple(sorted((a['key'],b['key']))); drop_window = windows.get(drop_key)
        if drop_window is None:
            if drop_key not in windows: gaps.add('missing_measurement_window')
            continue
        if [x['key'] for x in drop_window['subjects']] != [a['key'],b['key']]: gaps.add('incompatible_window'); continue
        utils = [item for item in valid if item['row']['metric'] in ('queue_utilization','interface_utilization') and _same_scope(item,b)]
        if not utils: gaps.add('missing_transport_profile'); continue
        for util in utils:
            if conflicting(util): gaps.add('conflicting_observations'); continue
            util_key=(util['key'],); util_window=windows.get(util_key)
            if util_window is None:
                if util_key not in windows: gaps.add('missing_measurement_window')
                continue
            if not _same_boundaries(util_window,drop_window): gaps.add('incompatible_window'); continue
            agg = util_window['aggregation']['row']['value']; matches=[]; disputed=False
            for profile in request['transport_profiles']:
                chosen=_profile(profile,util['resource'],util['row']['direction'],agg,util['row']['unit'],evidence,runs,request,reference,start,end)
                if chosen and all(_inside_interval(item['carrier'],timestamp(profile['valid_from']),timestamp(profile['valid_until'])) for item in (a,b,util)):
                    conflicts = _profile_conflicts(profile,chosen,evidence,runs,request,reference,start,end)
                    if conflicts:
                        disputed=True
                        gaps.add('conflicting_observations')
                        add('profile_conflict',list(chosen),'The source reported conflicting transport profile facts.',conflicts,True)
                        continue
                    matches.append(chosen)
            if disputed: continue
            if not matches: gaps.add('missing_transport_profile'); continue
            if len({entry[0]['row']['value'] for entry in matches})>1: gaps.add('conflicting_observations'); continue
            limit,profile_agg=matches[0]
            if util['row']['value']<limit['row']['value']: continue
            support=[a,b,util]+_support_window(drop_window)+_support_window(util_window)+[limit,profile_agg]
            code='queue_condition'
            if a['row']['metric']=='qos_class_drops':
                candidates=[item for item in valid if item['row']['metric']=='qos_class' and _same_scope(item,b) and (_same_event(item,drop_window['end']) or _inside_interval(item['carrier'],timestamp(drop_window['start']['carrier']['event_time']),timestamp(drop_window['end']['carrier']['event_time'])))]
                if len({item['row']['value'] for item in candidates})>1: gaps.add('conflicting_observations'); continue
                if not candidates: gaps.add('missing_qos_class'); continue
                qos=candidates[0]
                support.append(qos); code='qos_class_condition'
            add(code,support,'The source reported a profiled queue condition with increasing drops.',pass_evidence(util))
    for item in counters:
        if conflicting(item): gaps.add('conflicting_observations')
    configured = [item for item in valid if item['row']['metric']=='configured_mtu' and item['row']['unit']=='bytes']
    completed_large = set()
    for config in configured:
        effective = _one(valid,'effective_mtu',config,gaps)
        if effective is None or effective['row']['unit']!='bytes' or config['row']['value']==effective['row']['value']: continue
        if conflicting(config) or conflicting(effective): gaps.add('conflicting_observations'); continue
        add('mtu_discrepancy',[config,effective],'The source reported different configured and effective L3 MTU values.',pass_evidence(config),True)
        overhead = _one(valid,'tunnel_overhead',config,gaps)
        if overhead is None or overhead['row']['unit']!='bytes': gaps.add('missing_mtu_evidence'); continue
        if conflicting(overhead): gaps.add('conflicting_observations'); continue
        large_results = [item for item in valid if item['row']['metric']=='large_payload_result' and item['row']['value']=='fail' and _same_scope(item,config) and _same_event(item,config) and not conflicting(item)]
        for large in large_results:
            large_size = _one(valid,'probe_ip_packet_size',large,gaps)
            small_results = [item for item in valid if item['row']['metric']=='small_payload_result' and item['row']['value']=='pass' and _same_scope(item,large) and _ordered(item,large) and not conflicting(item)]
            for small in small_results:
                small_size = _one(valid,'probe_ip_packet_size',small,gaps)
                if not large_size or not small_size or large_size['row']['unit']!='bytes' or small_size['row']['unit']!='bytes': continue
                if conflicting(large_size) or conflicting(small_size): gaps.add('conflicting_observations'); continue
                if small_size['row']['value']<=effective['row']['value']<large_size['row']['value'] and small_size['row']['value']<large_size['row']['value']:
                    feedback = _one(valid,'fragmentation_needed',large,gaps)
                    support=[config,effective,overhead,small,small_size,large,large_size]
                    if feedback: support.append(feedback)
                    if not feedback or feedback['row']['value']!='seen': gaps.add('missing_pmtud_feedback')
                    add('mtu_scoped_failure',support,'The source reported a scoped L3 MTU discrepancy and size-dependent probe failure.',pass_evidence(large))
                    completed_large.add(large['key'])
    for large in valid:
        if large['row']['metric']=='large_payload_result' and large['row']['value']=='fail' and large['key'] not in completed_large and not conflicting(large):
            gaps.add('missing_mtu_evidence')
            feedback=_one(valid,'fragmentation_needed',large,gaps)
            if not feedback or feedback['row']['value']!='seen': gaps.add('missing_pmtud_feedback')
            add('pmtud_suspected',[large]+([feedback] if feedback else []),'The source reported a large-probe failure with incomplete PMTUD evidence.',pass_evidence(large),True)
    paths = [item for item in valid if item['row']['metric']=='ecmp_path' and item['row']['direction'] in ('ingress','egress')]
    paired_path = False
    for left in paths:
        for right in paths:
            if left['row']['direction']!='ingress' or right['row']['direction']!='egress' or not _identity(left,right) or not _same_event(left,right): continue
            if conflicting(left) or conflicting(right): gaps.add('conflicting_observations'); continue
            left_flow,right_flow = _one(valid,'flow_scope',left,gaps),_one(valid,'flow_scope',right,gaps)
            if not left_flow or not right_flow or left_flow['row']['value']!=right_flow['row']['value']: gaps.add('missing_flow_scope'); continue
            paired_path = True
            if left['row']['value']!=right['row']['value']:
                add('ecmp_asymmetry',[left,right,left_flow,right_flow],'The source reported different scoped forward and reverse path labels.',neutral=True)
    if paths and not paired_path: gaps.add('missing_flow_scope')
    unique=[]; seen=set()
    for finding in findings:
        key=json.dumps(finding,sort_keys=True,separators=(',',':'))
        if key not in seen: seen.add(key); unique.append(finding)
    fault=any(item['code'] not in NEUTRAL for item in unique)
    return dict(schema_version=1,status='fault_observed' if fault else 'insufficient_evidence',service=request['service'],findings=unique,gaps=sorted(gaps),next_checks=['Obtain scoped, current and comparable evidence for unresolved gaps.'] if gaps else [])


def _worker(path, request_bytes):
    try:
        request=strict_json(request_bytes,True)
        result={'ok':True,'result':analyze(request)}
        data=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
        if len(data)>LIMIT: raise CaseError('transport output budget exceeded')
    except Exception:
        data=b'{"ok":false}'
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as stream: stream.write(data)


def _process(request_bytes,result_path):
    return multiprocessing.get_context('spawn').Process(target=_worker,args=(str(result_path),request_bytes),daemon=True)


def analyze_bounded(request_bytes,timeout=5):
    return _bounded_worker(_process,request_bytes,timeout)
