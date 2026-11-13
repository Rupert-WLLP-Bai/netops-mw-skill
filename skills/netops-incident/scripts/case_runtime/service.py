"""Bounded offline service acceptance drafts from source-qualified evidence."""
from __future__ import annotations
import json
import math
import multiprocessing
import os
from datetime import datetime, timedelta, timezone
from .evidence import strict_json
from .store import CaseError, timestamp, token
from .analysis_common import (LIMIT, _object, _ref, _qualified, _validate_base,
    _load_runs, _collect_bound, _fresh, _binding_ok, _same_scope, _same_event,
    _bounded_worker)

FIELDS={'schema_version','reference_time','window_start','window_end','max_age_seconds','service','runs','bindings','delivery_scope','static_authorities','field_inventory','fields','criterion_inventory','criteria','direction_mappings','test_results','change_review'}
INVENTORY={'run_id','source','source_native_id','approval_evidence','count_evidence','entry_evidence'}
FIELD={'field','target','required_evidence','applicability_evidence','inapplicability_reason_evidence','expected_evidence','actual_evidence','actual_target_evidence','equivalence_evidence'}
CRITERION={'criterion_id','source','source_native_id','capability_evidence','applicability_evidence','inapplicability_reason_evidence','metric_evidence','aggregation_evidence','comparator_evidence','threshold_evidence','method_evidence','minimum_samples_evidence','direction_evidence','calibration_policy_evidence','window_start_evidence','window_end_evidence'}
DIRECTION={'point_id','site_id','source','source_native_id','relative_direction','absolute_direction','mapping_evidence','valid_from','valid_until','authority'}
RESULT={'criterion_id','measurement_evidence','method_evidence','aggregation_evidence','window_start_evidence','window_end_evidence','instrument_evidence','calibration_evidence','calibration_start_evidence','calibration_end_evidence'}
AUTHORITY={'source','source_native_id','current_evidence','valid_from_evidence','valid_until_evidence'}
EQUIVALENCE={'relation','expected_run','expected_id','actual_run','actual_id'}
CHANGE={'phase','scope_evidence','impact_evidence','planned_start_evidence','planned_end_evidence','approval_evidence','approval_reference_evidence','rollback_trigger_evidence','rollback_owner_evidence','residual_risk_evidence','check_inventory','checks'}
CHECK={'check_id','required_evidence','precheck_evidence','planned_metric_evidence','planned_method_evidence','planned_criterion_evidence','planned_comparator_evidence','planned_direction_evidence','postcheck_evidence','postcheck_method_evidence','postcheck_direction_evidence','postcheck_window_start_evidence','postcheck_window_end_evidence'}
CAPABILITIES={'throughput':'measured_throughput','delay':'measured_latency','loss':'measured_loss','jitter':'measured_jitter','l3_mtu':'measured_ip_mtu'}
REQUIRED={('circuit','service'),('bandwidth','service'),('sla_profile','service')} | {(field,target) for field in ('endpoint','vlan','vrf','ip_prefix','bandwidth','mtu','qos','routing','security') for target in ('endpoint_a','endpoint_b')}


def _nullable_ref(value):
    return None if value is None else _ref(value)


def _validate(request):
    reference,start,end=_validate_base(request,FIELDS)
    _object(request['delivery_scope'],{'circuit_id','endpoint_a_id','endpoint_b_id'})
    for value in request['delivery_scope'].values(): token(value,'delivery object')
    for name,keys in (('static_authorities',AUTHORITY),('fields',FIELD),('criteria',CRITERION),('direction_mappings',DIRECTION),('test_results',RESULT)):
        values=request[name]
        if not isinstance(values,list) or len(values)>256: raise CaseError('service declaration budget exceeded')
        for value in values: _object(value,keys)
    for name in ('field_inventory','criterion_inventory'):
        if request[name] is not None: _validate_inventory(request[name])
    for authority in request['static_authorities']:
        token(authority['source'],'source'); token(authority['source_native_id'],'source identity')
        for key in ('current_evidence','valid_from_evidence','valid_until_evidence'): _nullable_ref(authority[key])
    for entry in request['fields']:
        token(entry['field'],'field'); token(entry['target'],'target')
        for key in FIELD-{'field','target','equivalence_evidence'}: _nullable_ref(entry[key])
        if entry['equivalence_evidence'] is not None:
            _object(entry['equivalence_evidence'],EQUIVALENCE)
            for value in entry['equivalence_evidence'].values(): _ref(value)
    for criterion in request['criteria']:
        for key in ('criterion_id','source','source_native_id'): token(criterion[key],key)
        for key in CRITERION-{'criterion_id','source','source_native_id'}: _nullable_ref(criterion[key])
    for mapping in request['direction_mappings']:
        for key in ('point_id','site_id','source','source_native_id','authority'): token(mapping[key],key)
        if mapping['relative_direction'] not in ('ingress','egress') or mapping['absolute_direction'] not in ('A_to_B','B_to_A') or timestamp(mapping['valid_from'])>timestamp(mapping['valid_until']): raise CaseError('invalid direction mapping')
        _nullable_ref(mapping['mapping_evidence'])
    for result in request['test_results']:
        token(result['criterion_id'],'criterion id')
        for key in RESULT-{'criterion_id'}: _nullable_ref(result[key])
    change=request['change_review']
    if change is not None:
        _object(change,CHANGE)
        if change['phase'] not in ('pre_change','post_change'): raise CaseError('invalid change phase')
        for key in CHANGE-{'phase','residual_risk_evidence','check_inventory','checks'}: _nullable_ref(change[key])
        if not isinstance(change['residual_risk_evidence'],list) or len(change['residual_risk_evidence'])>256: raise CaseError('invalid risk references')
        for ref in change['residual_risk_evidence']: _ref(ref)
        if change['check_inventory'] is not None: _validate_inventory(change['check_inventory'])
        if not isinstance(change['checks'],list) or len(change['checks'])>256: raise CaseError('invalid check list')
        for check in change['checks']:
            _object(check,CHECK); token(check['check_id'],'check id')
            for key in CHECK-{'check_id'}: _nullable_ref(check[key])
    return reference,start,end


def _validate_inventory(inventory):
    _object(inventory,INVENTORY)
    for key in ('run_id','source','source_native_id'): token(inventory[key],key)
    _nullable_ref(inventory['approval_evidence']); _nullable_ref(inventory['count_evidence'])
    if not isinstance(inventory['entry_evidence'],list) or len(inventory['entry_evidence'])>256: raise CaseError('invalid inventory')
    for ref in inventory['entry_evidence']: _ref(ref)


def _number(value):
    return not isinstance(value,bool) and isinstance(value,(int,float)) and math.isfinite(value)


def _date(item):
    if not item or item['row']['unit']!='unix_s' or not _number(item['row']['value']): return None
    try: return datetime.fromtimestamp(item['row']['value'],timezone.utc)
    except (OverflowError,OSError,ValueError): return None


def _topology(request,runs,evidence,reference,start,end):
    rid=request['service']['topology_run_id']; run=runs.get(rid,{}); context=run.get('context')
    if not context or context['service_ref']!=request['service']['object_id'] or run['adapter'].get('parse_status')!='complete': return None
    records=[item for key,item in evidence.items() if key[0]==rid and item['row'] is None and _fresh(item['carrier'],request,reference,start,end,False)]
    if not records: return None
    objects={item['id']:item for item in context['objects'] if item['identity_state']=='known'}
    scope=request['delivery_scope']; service=request['service']['object_id']
    if len({service,*scope.values()})!=4: return None
    for ident,kind in ((service,'service'),(scope['circuit_id'],'circuit'),(scope['endpoint_a_id'],'site'),(scope['endpoint_b_id'],'site')):
        if ident not in objects or objects[ident]['type']!=kind: return None
    for ident,relation in ((scope['circuit_id'],'service_to_circuit'),(scope['endpoint_a_id'],'service_to_endpoint_a'),(scope['endpoint_b_id'],'service_to_endpoint_b')):
        if not any(link['state']=='verified' and link['from_id']==service and link['to_id']==ident and link['relation']==relation for link in context['topology']): return None
    return context


def _static_binding(binding,request,runs,evidence,reference,start,end):
    key=_ref(binding['record']); topkey=_ref(binding['topology_evidence']); item=evidence.get(key); topology_item=evidence.get(topkey)
    if not item or not topology_item or not item['row'] or topology_item['row'] is not None: return None
    rid=request['service']['topology_run_id']; selected=request['service']['object_id']
    if topkey[0]!=rid or binding['service_id']!=selected or not _fresh(topology_item['carrier'],request,reference,start,end,False): return None
    context=runs[rid]['context']; objects={obj['id']:obj for obj in context['objects']}
    resource=objects.get(binding['resource_id']); service=objects.get(selected)
    if not resource or resource['identity_state']!='known' or not service or service['type']!='service' or service['identity_state']!='known': return None
    if binding['resource_id']!=selected and not any(link['state']=='verified' and {link['from_id'],link['to_id']}=={selected,binding['resource_id']} for link in context['topology']): return None
    carrier=item['carrier']
    if (carrier['source'],carrier['source_native_id'])!=(binding['source'],binding['source_native_id']) or runs[key[0]]['adapter']['parse_status']!='complete': return None
    if carrier['clock_quality']!='synchronized' or carrier['clock_uncertainty_seconds'] is None: return None
    try:
        uncertainty=timedelta(seconds=carrier['clock_uncertainty_seconds'])
        if not carrier['collected_at'] or timestamp(carrier['collected_at'])+uncertainty>reference or not timestamp(binding['valid_from'])<=reference<=timestamp(binding['valid_until']): return None
        if carrier['event_time'] is not None and timestamp(carrier['event_time'])+uncertainty>reference: return None
    except (OverflowError,ValueError): return None
    return dict(item,key=key,topology_key=topkey,resource=binding['resource_id'])


def _read(ref, pool, metric=None):
    if ref is None: return None
    item=pool.get(_ref(ref))
    if not item or not isinstance(item['row'],dict) or item['row'].get('metric')!=metric: return None
    row=item['row']
    if row['value'] is None or row['value']=='unknown' or not row['sample_count']: return None
    return item


def _source(item):
    return item['carrier']['source'],item['carrier']['source_native_id']


def _opposing(item,pool,static=False):
    if not item: return []
    row=item['row']; found=[]
    if row['metric'] in ('required_field_target','required_criterion','required_change_check','residual_risk'): return found
    for other in pool.values():
        if other['key']==item['key'] or _source(other)!=_source(item) or other['resource']!=item['resource']: continue
        candidate=other['row']
        if candidate['metric']!=row['metric'] or candidate['direction']!=row['direction'] or not candidate['sample_count']: continue
        if candidate['value'] is None or candidate['value']=='unknown': continue
        if isinstance(row['value'],str):
            if candidate['value']==row['value']: continue
        elif candidate['value']==row['value'] and candidate['unit']==row['unit']: continue
        if static or _same_event(item,other): found.append(other)
    return found


def _authority_set(request,static,reference,start,end):
    result=set(); seen=set(); conflicts=set()
    for entry in request['static_authorities']:
        identity=(entry['source'],entry['source_native_id'])
        if identity in seen: conflicts.add(identity)
        seen.add(identity)
        current=_read(entry['current_evidence'],static,'static_current')
        if not current or _source(current)!=identity or current['row']['value']!='current': continue
        first=_read(entry['valid_from_evidence'],static,'static_valid_from'); last=_read(entry['valid_until_evidence'],static,'static_valid_until')
        begin,until=_date(first),_date(last)
        interval=bool(first and last and _source(first)==identity and _source(last)==identity and begin and until and begin<=start<=end<=until)
        carrier=current['carrier']; exact=carrier['event_time'] is not None and timestamp(carrier['event_time'])==reference and carrier['clock_quality']=='synchronized' and carrier['clock_uncertainty_seconds']==0
        if (interval or (exact and end<=reference)) and not _opposing(current,static,True) and not _opposing(first,static,True) and not _opposing(last,static,True): result.add(identity)
    for item in static.values():
        if item['row']['metric']=='static_current' and item['row']['value'] in ('superseded','revoked'):
            conflicts.add(_source(item))
    return result-conflicts


def _static_read(ref,static,authorities,metric,identity=None):
    item=_read(ref,static,metric)
    if not item or _source(item) not in authorities or (identity is not None and _source(item)!=identity): return None
    return item


def _inventory(spec,kind,static,evidence,authorities,listing=False):
    if spec is None: return None
    identity=(spec['source'],spec['source_native_id']); rid=spec['run_id']
    approval=_static_read(spec['approval_evidence'],static,authorities,kind+'_inventory_approval',identity)
    count=_static_read(spec['count_evidence'],static,authorities,kind+'_inventory_count',identity)
    if not approval or approval['key'][0]!=rid or approval['row']['value']!='approved' or approval['carrier']['event_time'] is None or not count or count['key'][0]!=rid or _opposing(approval,static,True) or _opposing(count,static,True): return None
    value=count['row']['value']
    if not _number(value) or value<0 or int(value)!=value: return None
    metric={'field':'required_field_target','criterion':'required_criterion','change_check':'required_change_check'}[kind]
    found={key for key,item in evidence.items() if key[0]==rid and item['row'] and item['row'].get('metric')==metric and _source(item)==identity}
    supplied=[_ref(ref) for ref in spec['entry_evidence']]
    if len(found)!=value: return None
    if not listing and (len(supplied)!=len(set(supplied)) or set(supplied)!=found): return None
    items=[_static_read(_qualified(key),static,authorities,metric,identity) for key in sorted(found)]
    if any(item is None for item in items): return None
    values=[item['row']['value'] for item in items]
    if len(values)!=len(set(values)): return None
    return {item['row']['value']:item for item in items}


def _site_point(context,site,point):
    sites={link['from_id'] for link in context['topology'] if link['state']=='verified' and link['relation']=='site_to_point' and link['to_id']==point}
    return sites=={site}


def _same_source_resource(a,b):
    return a['resource']==b['resource'] and _source(a)==_source(b) and _same_event(a,b)


def _equivalence_relation(declaration,expected,actual,static,authorities):
    """Resolve only a scoped source assertion naming the exact evidence pair."""
    if not declaration: return None,[]
    names={'relation':'field_equivalence','expected_run':'equivalence_expected_run','expected_id':'equivalence_expected_id','actual_run':'equivalence_actual_run','actual_id':'equivalence_actual_id'}
    items={name:_static_read(declaration[name],static,authorities,metric) for name,metric in names.items()}
    if any(item is None for item in items.values()): return None,[]
    if len({_source(item) for item in items.values()})!=1 or {item['resource'] for item in items.values()}!={actual['resource']}: return None,[]
    opposing=[other for item in items.values() for other in _opposing(item,static,True)]
    if opposing: return None,opposing
    values={name:item['row']['value'] for name,item in items.items()}
    relation=values.pop('relation')
    if relation not in ('declared_equal','declared_different') or values!=dict(expected_run=expected['key'][0],expected_id=expected['key'][1],actual_run=actual['key'][0],actual_id=actual['key'][1]): return None,[]
    return relation,[]


def _field_results(request,context,static,actual,authorities,inventory,gaps):
    entries=request['fields']; targets=[(item['field'],item['target']) for item in entries]
    if len(targets)!=len(set(targets)): raise CaseError('duplicate field target')
    if inventory is None: gaps.add('missing_field_inventory')
    declared={field+'_'+target for field,target in targets}
    if inventory is None or declared!=set(inventory) or not REQUIRED.issubset(set(targets)): gaps.add('field_inventory_incomplete')
    results=[]
    for entry in entries:
        field,target=entry['field'],entry['target']; target_name=field+'_'+target; local=[]; status='unverified'
        required=inventory.get(target_name) if inventory else None
        if not required or _nullable_ref(entry['required_evidence'])!=required['key'] or field not in {'circuit','endpoint','vlan','vrf','ip_prefix','bandwidth','mtu','qos','routing','security','sla_profile'} or target not in ('service','endpoint_a','endpoint_b'): local.append('unsupported_or_missing_field_requirement')
        if entry['applicability_evidence'] is not None or entry['inapplicability_reason_evidence'] is not None: local.append('human_applicability_review')
        expected=_static_read(entry['expected_evidence'],static,authorities,'expected_'+field)
        actual_item=_read(entry['actual_evidence'],actual,'actual_'+field)
        actual_target=_read(entry['actual_target_evidence'],actual,'actual_field_target')
        if expected and (_source(expected)[1]!=target_name or not required or _source(expected)[0]!=_source(required)[0]): expected=None
        opposing=(_opposing(expected,static,True) if expected else [])+(_opposing(actual_item,actual) if actual_item else [])+(_opposing(actual_target,actual) if actual_target else [])
        if opposing: local.append('conflicting_observations')
        if not expected or not actual_item or not actual_target: local.append('missing_field_evidence')
        elif actual_target['row']['value']!=target_name or not _same_source_resource(actual_item,actual_target): local.append('field_scope_mismatch')
        elif context is None or (target=='service' and actual_item['resource'] not in (request['service']['object_id'],request['delivery_scope']['circuit_id'])) or (target in ('endpoint_a','endpoint_b') and not _site_point(context,request['delivery_scope'][target+'_id'],actual_item['resource'])): local.append('field_scope_mismatch')
        elif field in ('mtu','bandwidth') and (not _number(expected['row']['value']) or not _number(actual_item['row']['value']) or expected['row']['unit']!=actual_item['row']['unit'] or expected['row']['unit'] in (None,'unknown') or (field=='mtu' and expected['row']['unit']!='bytes')): local.append('field_unit_mismatch')
        elif field not in ('mtu','bandwidth') and (not isinstance(expected['row']['value'],str) or not isinstance(actual_item['row']['value'],str)): local.append('field_unit_mismatch')
        elif expected['row']['unit']!=actual_item['row']['unit']: local.append('field_unit_mismatch')
        elif opposing: pass
        elif isinstance(expected['row']['value'],str):
            if not isinstance(actual_item['row']['value'],str): local.append('field_unit_mismatch')
            elif _source(expected)==_source(actual_item): status='match' if expected['row']['value']==actual_item['row']['value'] else 'mismatch'
            else:
                relation,conflicts=_equivalence_relation(entry['equivalence_evidence'],expected,actual_item,static,authorities)
                opposing.extend(conflicts)
                if conflicts: local.append('conflicting_observations')
                elif relation is None: local.append('missing_field_equivalence')
                else: status='match' if relation=='declared_equal' else 'mismatch'
        elif not _number(expected['row']['value']) or not _number(actual_item['row']['value']): local.append('field_unit_mismatch')
        elif expected['row']['value']==actual_item['row']['value']: status='match'
        else: status='mismatch'
        if local: status='unverified'
        gaps.update(local)
        results.append(dict(field=field,target=target,status=status,required_ref=entry['required_evidence'],expected_ref=entry['expected_evidence'],actual_ref=entry['actual_evidence'],actual_target_ref=entry['actual_target_evidence'],equivalence_ref=entry['equivalence_evidence'],topology_ref=_qualified(actual_item['topology_key']) if actual_item else None,counterevidence=[_qualified(item['key']) for item in opposing],gaps=local))
    return results


def _mapped_direction(item,request,context,actual):
    matches=[]
    for mapping in request['direction_mappings']:
        mapping_item=_read(mapping['mapping_evidence'],actual,'direction_mapping')
        if not mapping_item or not context or not _same_source_resource(item,mapping_item): continue
        if mapping['point_id']!=item['resource'] or (mapping['source'],mapping['source_native_id'])!=_source(item): continue
        if mapping['site_id'] not in (request['delivery_scope']['endpoint_a_id'],request['delivery_scope']['endpoint_b_id']) or not _site_point(context,mapping['site_id'],mapping['point_id']): continue
        if mapping['relative_direction']!=item['row']['direction'] or mapping_item['row']['direction']!=mapping['relative_direction'] or mapping_item['row']['value']!=mapping['absolute_direction']: continue
        event=timestamp(item['carrier']['event_time']); uncertainty=timedelta(seconds=item['carrier']['clock_uncertainty_seconds'])
        if timestamp(mapping['valid_from'])<=event-uncertainty and event+uncertainty<=timestamp(mapping['valid_until']): matches.append((mapping['absolute_direction'],mapping_item))
    return matches[0] if len(matches)==1 else (None,None)


def _criterion_data(entry,static,authorities):
    identity=(entry['source'],entry['source_native_id'])
    names={'capability_evidence':'criterion_capability','metric_evidence':'criterion_metric','aggregation_evidence':'criterion_aggregation','comparator_evidence':'criterion_comparator','threshold_evidence':'criterion_threshold','method_evidence':'criterion_method','minimum_samples_evidence':'criterion_min_samples','direction_evidence':'criterion_direction','calibration_policy_evidence':'criterion_calibration_policy','window_start_evidence':'criterion_window_start','window_end_evidence':'criterion_window_end'}
    result={key:_static_read(entry[key],static,authorities,metric,identity) for key,metric in names.items()}
    if any(value is None for value in result.values()) or entry['applicability_evidence'] is not None or entry['inapplicability_reason_evidence'] is not None: return None
    if any(_opposing(item,static,True) for item in result.values()): return None
    values={key:item['row']['value'] for key,item in result.items()}
    if CAPABILITIES.get(values['capability_evidence'])!=values['metric_evidence'] or values['aggregation_evidence'] not in ('mean','min','max','p95','p99','single') or values['comparator_evidence'] not in ('gte','lte','eq') or values['direction_evidence'] not in ('A_to_B','B_to_A','both') or values['calibration_policy_evidence'] not in ('required','not_required'): return None
    count=values['minimum_samples_evidence']
    if not _number(count) or count<=0 or int(count)!=count or not _number(values['threshold_evidence']): return None
    if result['threshold_evidence']['row']['unit'] in (None,'unknown') or (values['capability_evidence']=='l3_mtu' and result['threshold_evidence']['row']['unit']!='bytes'): return None
    first,last=_date(result['window_start_evidence']),_date(result['window_end_evidence'])
    if not first or not last or first>last: return None
    return result


def _test_matrix(request,context,static,actual,authorities,inventory,gaps,start,end):
    entries=request['criteria']; ids=[entry['criterion_id'] for entry in entries]
    if len(ids)!=len(set(ids)): raise CaseError('duplicate criterion')
    if inventory is None: gaps.add('missing_criterion_inventory')
    if inventory is None or set(ids)!=set(inventory): gaps.add('criterion_inventory_incomplete')
    if any(result['criterion_id'] not in ids for result in request['test_results']): gaps.add('criterion_inventory_incomplete')
    matrix=[]; capability={name:set() for name in CAPABILITIES}
    for criterion in entries:
        cid=criterion['criterion_id']; data=_criterion_data(criterion,static,authorities)
        if inventory is None or cid not in inventory or criterion['source_native_id']!=cid or criterion['source']!=inventory[cid]['carrier']['source']:
            data=None
        if data is None:
            gaps.add('missing_criterion_evidence'); continue
        values={key:item['row']['value'] for key,item in data.items()}
        directions=('A_to_B','B_to_A') if values['direction_evidence']=='both' else (values['direction_evidence'],)
        capability[values['capability_evidence']].update(directions)
        for supplied in request['test_results']:
            if supplied['criterion_id']!=cid: continue
            observed=_read(supplied['measurement_evidence'],actual,values['metric_evidence'])
            if not observed: gaps.add('missing_test_evidence')
            elif _mapped_direction(observed,request,context,actual)[0] is None: gaps.add('missing_direction_mapping')
        for direction in directions:
            candidates=[]
            for result in request['test_results']:
                if result['criterion_id']!=cid: continue
                measurement=_read(result['measurement_evidence'],actual,values['metric_evidence'])
                if not measurement: continue
                mapped,mapping=_mapped_direction(measurement,request,context,actual)
                if mapped==direction: candidates.append((result,measurement,mapping))
            local=[]; opposing=[]; status='unverified'; chosen=candidates[0] if len(candidates)==1 else None
            if not chosen:
                local.append('missing_test_evidence' if not candidates else 'ambiguous_test_evidence')
                if not candidates: local.append('missing_direction_mapping')
                else: opposing.extend(candidate[1] for candidate in candidates)
                result=None; measurement=None; mapping=None
            else:
                result,measurement,mapping=chosen
                roles={'method_evidence':'test_method','aggregation_evidence':'test_aggregation','window_start_evidence':'test_window_start','window_end_evidence':'test_window_end'}
                parts={name:_read(result[name],actual,metric) for name,metric in roles.items()}
                if any(not item or not _same_source_resource(measurement,item) for item in parts.values()): local.append('missing_test_evidence')
                else:
                    for item in [measurement,mapping]+list(parts.values()): opposing.extend(_opposing(item,actual))
                    if opposing: local.append('conflicting_observations')
                    begin,until=_date(parts['window_start_evidence']),_date(parts['window_end_evidence'])
                    approved_begin,approved_end=_date(data['window_start_evidence']),_date(data['window_end_evidence'])
                    event=timestamp(measurement['carrier']['event_time'])
                    uncertainty=timedelta(seconds=measurement['carrier']['clock_uncertainty_seconds'])
                    if not begin or not until or not (start<=begin<=event-uncertainty and event+uncertainty<=until<=end and approved_begin<=begin<=until<=approved_end): local.append('test_window_mismatch')
                    if parts['method_evidence']['row']['value']!=values['method_evidence'] or parts['aggregation_evidence']['row']['value']!=values['aggregation_evidence']: local.append('test_method_mismatch')
                    if not _number(measurement['row']['value']) or measurement['row']['unit']!=data['threshold_evidence']['row']['unit'] or measurement['row']['sample_count']<values['minimum_samples_evidence']: local.append('test_measurement_mismatch')
                    if values['calibration_policy_evidence']=='required':
                        instrument=_read(result['instrument_evidence'],actual,'instrument_id'); calibrated=_static_read(result['calibration_evidence'],static,authorities,'calibration_status')
                        cstart=_static_read(result['calibration_start_evidence'],static,authorities,'calibration_start'); cend=_static_read(result['calibration_end_evidence'],static,authorities,'calibration_end')
                        if not all((instrument,calibrated,cstart,cend)) or not _same_source_resource(measurement,instrument) or any(item['resource']!=measurement['resource'] or _source(item)!=(measurement['carrier']['source'],instrument['row']['value']) for item in (calibrated,cstart,cend)) or calibrated['row']['value']!='valid' or not _date(cstart) or not _date(cend) or not begin or not until or not (_date(cstart)<=begin<=until<=_date(cend)): local.append('missing_calibration')
                        elif any(_opposing(item,static,True) for item in (calibrated,cstart,cend)):
                            local.append('conflicting_observations')
                            for item in (calibrated,cstart,cend): opposing.extend(_opposing(item,static,True))
                    if not local:
                        value=measurement['row']['value']; threshold=values['threshold_evidence']; comparator=values['comparator_evidence']
                        passed={'gte':value>=threshold,'lte':value<=threshold,'eq':value==threshold}[comparator]; status='pass' if passed else 'fail'
            gaps.update(local)
            matrix.append(dict(criterion_id=cid,absolute_direction=direction,status=status,measurement_point=measurement['resource'] if measurement and mapping else None,measurement_ref=result['measurement_evidence'] if result else None,criterion_refs=[_qualified(item['key']) for item in data.values()],method_ref=result['method_evidence'] if result else None,window_refs=[result['window_start_evidence'],result['window_end_evidence']] if result else [],instrument_ref=result['instrument_evidence'] if result else None,calibration_refs=[result[key] for key in ('calibration_evidence','calibration_start_evidence','calibration_end_evidence') if result and result[key]],topology_ref=_qualified(measurement['topology_key']) if measurement else None,direction_mapping_ref=_qualified(mapping['key']) if mapping else None,counterevidence=[_qualified(item['key']) for item in opposing],gaps=local))
    if any(directions!={'A_to_B','B_to_A'} for directions in capability.values()): gaps.add('criterion_inventory_incomplete')
    return matrix


def _change(request,context,static,actual,evidence,authorities,reference):
    change=request['change_review']
    if change is None: return dict(status='not_requested',checks=[],gaps=[],evidence_refs={})
    local=[]; checks=[]
    if context is None: local.append('change_review_incomplete')
    roles={'scope_evidence':'change_scope','impact_evidence':'change_impact','planned_start_evidence':'change_window_start','planned_end_evidence':'change_window_end','approval_evidence':'change_approval','approval_reference_evidence':'change_approval_reference','rollback_trigger_evidence':'rollback_trigger','rollback_owner_evidence':'rollback_owner'}
    items={name:_static_read(change[name],static,authorities,metric) for name,metric in roles.items()}
    risks=[_static_read(ref,static,authorities,'residual_risk') for ref in change['residual_risk_evidence']]
    if any(item is None for item in items.values()) or not risks or any(item is None for item in risks): local.append('change_review_incomplete')
    scope=items['scope_evidence']
    if scope and (scope['row']['value'] not in (request['service']['object_id'],request['delivery_scope']['circuit_id']) or scope['resource'] not in (request['service']['object_id'],request['delivery_scope']['circuit_id'])): local.append('change_review_incomplete')
    begin=_date(items['planned_start_evidence']); end=_date(items['planned_end_evidence'])
    if not begin or not end or begin>end: local.append('change_review_incomplete')
    change_authorities=set()
    if begin and end and begin<=end:
        change_authorities=_authority_set(request,static,reference,begin,end)
        if any(item and _source(item) not in change_authorities for item in list(items.values())+risks): local.append('change_review_incomplete')
    approval=items['approval_evidence']
    if not approval or approval['carrier']['event_time'] is None or approval['row']['value'] not in (('pending','approved') if change['phase']=='pre_change' else ('approved',)): local.append('change_review_incomplete')
    elif change['phase']=='post_change' and (not begin or timestamp(approval['carrier']['event_time'])+timedelta(seconds=approval['carrier']['clock_uncertainty_seconds'] or 0)>begin): local.append('change_review_incomplete')
    inventory=_inventory(change['check_inventory'],'change_check',static,evidence,change_authorities)
    check_ids=[entry['check_id'] for entry in change['checks']]
    if len(check_ids)!=len(set(check_ids)): raise CaseError('duplicate change check')
    if inventory is None or set(check_ids)!=set(inventory) or not check_ids: local.append('change_review_incomplete')
    plan_roles={'planned_metric_evidence':'planned_postcheck_metric','planned_method_evidence':'planned_postcheck_method','planned_criterion_evidence':'planned_postcheck_criterion','planned_comparator_evidence':'planned_postcheck_comparator','planned_direction_evidence':'planned_postcheck_direction'}
    for check in change['checks']:
        ident=check['check_id']; required=inventory.get(ident) if inventory else None; check_gaps=[]
        if not required or _nullable_ref(check['required_evidence'])!=required['key']: check_gaps.append('change_review_incomplete')
        plans={name:_static_read(check[name],static,authorities,metric) for name,metric in plan_roles.items()}
        if any(not item or _source(item)[1]!=ident or _source(item) not in change_authorities for item in plans.values()): check_gaps.append('change_review_incomplete')
        if all(plans.values()) and len({_source(item) for item in plans.values()})!=1: check_gaps.append('change_review_incomplete')
        pre=_read(check['precheck_evidence'],actual,'precheck_status')
        if not pre or pre['row']['value']!='pass' or _source(pre)[1]!=ident or not all(plans.values()) or _source(pre)!=_source(plans['planned_metric_evidence']) or not begin or timestamp(pre['carrier']['event_time'])+timedelta(seconds=pre['carrier']['clock_uncertainty_seconds'])>=begin: check_gaps.append('change_review_incomplete')
        if change['phase']=='post_change' and not check_gaps:
            metric=plans['planned_metric_evidence']['row']['value']; observed=_read(check['postcheck_evidence'],actual,metric)
            method=_read(check['postcheck_method_evidence'],actual,'postcheck_method'); direction=_read(check['postcheck_direction_evidence'],actual,'postcheck_direction')
            left=_read(check['postcheck_window_start_evidence'],actual,'postcheck_window_start'); right=_read(check['postcheck_window_end_evidence'],actual,'postcheck_window_end')
            if not all((observed,method,direction,left,right)) or not all(_same_source_resource(observed,item) for item in (method,direction,left,right)) or _source(observed)[1]!=ident: check_gaps.append('change_review_incomplete')
            else:
                value=observed['row']['value']; expected=plans['planned_criterion_evidence']['row']['value']; cmp=plans['planned_comparator_evidence']['row']['value']
                lo,hi=_date(left),_date(right); actual_event=timestamp(observed['carrier']['event_time'])
                mapped,_=_mapped_direction(observed,request,context,actual)
                compatible=method['row']['value']==plans['planned_method_evidence']['row']['value'] and direction['row']['value']==plans['planned_direction_evidence']['row']['value']==mapped and observed['row']['unit']==plans['planned_criterion_evidence']['row']['unit'] and _same_scope(pre,observed)
                if not end or not lo or not hi or not end<lo<=actual_event<=hi or lo<timestamp(request['window_start']) or hi>timestamp(request['window_end']) or actual_event-timedelta(seconds=observed['carrier']['clock_uncertainty_seconds'])<=end or not compatible or cmp not in ('eq','gte','lte'): check_gaps.append('change_review_incomplete')
                elif cmp=='eq' and value!=expected: check_gaps.append('change_review_incomplete')
                elif cmp in ('gte','lte') and (not _number(value) or not _number(expected) or (cmp=='gte' and value<expected) or (cmp=='lte' and value>expected)): check_gaps.append('change_review_incomplete')
        local.extend(check_gaps)
        checks.append(dict(check_id=ident,status='unverified' if check_gaps else 'ready_for_human_review',required_ref=check['required_evidence'],precheck_ref=check['precheck_evidence'],postcheck_ref=check['postcheck_evidence'],plan_refs=[check[key] for key in plan_roles if check[key]],postcheck_method_ref=check['postcheck_method_evidence'],postcheck_direction_ref=check['postcheck_direction_evidence'],postcheck_window_refs=[check[key] for key in ('postcheck_window_start_evidence','postcheck_window_end_evidence') if check[key]],gaps=sorted(set(check_gaps))))
    evidence_refs={key:change[key] for key in roles}; evidence_refs['residual_risk_evidence']=change['residual_risk_evidence']
    return dict(status='blocked' if local else 'ready_for_human_review',checks=checks,gaps=sorted(set(local)),evidence_refs=evidence_refs)


def _report(result,scope):
    def ref(value):
        return value['run_id']+'/'+value['evidence_id'] if value else 'unavailable'
    def refs(values):
        return ', '.join(ref(value) for value in values if value) or 'unavailable'
    lines=['# Service acceptance and handover draft','',
        'Service: '+result['service']['object_id'],
        'Circuit: '+scope['circuit_id']+'; endpoint A: '+scope['endpoint_a_id']+'; endpoint B: '+scope['endpoint_b_id'],
        'Technical status: '+result['technical_status']+'; acceptance: '+result['acceptance_status']+'; human signoff: pending.',
        '', '## Field comparisons']
    for item in result['field_results']:
        lines.append('- '+item['field']+' / '+item['target']+': '+item['status']+'; required '+ref(item['required_ref'])+'; expected '+ref(item['expected_ref'])+'; actual '+ref(item['actual_ref'])+'; target '+ref(item['actual_target_ref'])+'; topology '+ref(item['topology_ref'])+'.')
        if item['equivalence_ref']: lines.append('  Equivalence evidence: '+refs(item['equivalence_ref'].values())+'.')
    if not result['field_results']: lines.append('- No field comparisons supplied.')
    lines.extend(['','## Acceptance tests'])
    for item in result['test_matrix']:
        lines.append('- '+item['criterion_id']+' / '+item['absolute_direction']+': '+item['status']+'; mapped measurement point '+(item['measurement_point'] or 'unavailable')+'; measurement '+ref(item['measurement_ref'])+'; criterion '+refs(item['criterion_refs'])+'; method '+ref(item['method_ref'])+'; window '+refs(item['window_refs'])+'; direction mapping '+ref(item['direction_mapping_ref'])+'; instrument '+ref(item['instrument_ref'])+'; calibration '+refs(item['calibration_refs'])+'.')
    if not result['test_matrix']: lines.append('- No comparable acceptance tests supplied.')
    change=result['change_review']; lines.extend(['','## Change review','Status: '+change['status']+'.'])
    for name,value in sorted(change['evidence_refs'].items()):
        lines.append('- '+name+': '+(refs(value) if isinstance(value,list) else ref(value))+'.')
    for item in change['checks']:
        lines.append('- Check '+item['check_id']+': '+item['status']+'; precheck '+ref(item['precheck_ref'])+'; plan '+refs(item['plan_refs'])+'; postcheck '+ref(item['postcheck_ref'])+'.')
    lines.extend(['','## Outstanding evidence and signoff'])
    lines.append('Gaps: '+(', '.join(result['gaps']) if result['gaps'] else 'none reported')+'.')
    for item in result['missing_requirements']:
        lines.append('- Missing '+item['kind']+' requirement '+item['id']+'; required '+ref(item['required_ref'])+'.')
    if result['counterevidence']: lines.append('Conflicting evidence: '+refs(result['counterevidence'])+'.')
    lines.append('A human must review the supplied evidence and record any acceptance decision separately. No change or recovery was executed.')
    return '\n'.join(lines)+'\n'


def analyze(request):
    reference,start,end=_validate(request); runs,evidence=_load_runs(request)
    context=_topology(request,runs,evidence,reference,start,end)
    actual,actual_gaps=_collect_bound(request,runs,evidence,reference,start,end)
    static={}
    if context is not None:
        for binding in request['bindings']:
            item=_static_binding(binding,request,runs,evidence,reference,start,end)
            if item: static[item['key']]=item
    authorities=_authority_set(request,static,reference,start,end)
    gaps=set()
    def conflicts(value):
        found=set(); pending=[value]
        while pending:
            part=pending.pop()
            if isinstance(part,dict):
                if set(part)=={'run_id','evidence_id'}:
                    key=_ref(part)
                    for pool,is_static in ((static,True),(actual,False)):
                        selected=pool.get(key)
                        if selected: found.update(item['key'] for item in _opposing(selected,pool,is_static))
                else: pending.extend(part.values())
            elif isinstance(part,list): pending.extend(part)
        return found
    counterevidence=conflicts({key:value for key,value in request.items() if key!='change_review'})
    if counterevidence: gaps.add('conflicting_observations')
    if context is None: gaps.add('invalid_delivery_scope')
    field_inventory=_inventory(request['field_inventory'],'field',static,evidence,authorities)
    criteria_inventory=_inventory(request['criterion_inventory'],'criterion',static,evidence,authorities)
    fields=_field_results(request,context,static,actual,authorities,field_inventory,gaps)
    matrix=_test_matrix(request,context,static,actual,authorities,criteria_inventory,gaps,start,end)
    change=_change(request,context,static,actual,evidence,authorities,reference)
    missing=[]
    field_names={item['field']+'_'+item['target'] for item in request['fields']}
    field_listing=field_inventory or _inventory(request['field_inventory'],'field',static,evidence,authorities,True)
    for name,item in (field_listing or {}).items():
        if name not in field_names: missing.append(dict(kind='field',id=name,required_ref=_qualified(item['key'])))
    criterion_names={item['criterion_id'] for item in request['criteria']}
    criterion_listing=criteria_inventory or _inventory(request['criterion_inventory'],'criterion',static,evidence,authorities,True)
    for name,item in (criterion_listing or {}).items():
        if name not in criterion_names: missing.append(dict(kind='criterion',id=name,required_ref=_qualified(item['key'])))
    if request['change_review']:
        change_inventory=_inventory(request['change_review']['check_inventory'],'change_check',static,evidence,authorities,True)
        check_names={item['check_id'] for item in request['change_review']['checks']}
        for name,item in (change_inventory or {}).items():
            if name not in check_names: missing.append(dict(kind='change_check',id=name,required_ref=_qualified(item['key'])))
    change_conflicts=conflicts(request['change_review'])
    if change_conflicts:
        change['status']='blocked'; change['gaps']=sorted(set(change['gaps']) | {'conflicting_observations'}); counterevidence.update(change_conflicts)
    # Static rows may legitimately be old or undated; report freshness gaps only for actual rows.
    actual_refs=set()
    for field in request['fields']:
        actual_refs.update(_nullable_ref(field[key]) for key in ('actual_evidence','actual_target_evidence') if field[key])
    for result in request['test_results']:
        actual_refs.update(_nullable_ref(result[key]) for key in RESULT-{'criterion_id','calibration_evidence','calibration_start_evidence','calibration_end_evidence'} if result[key])
    for mapping in request['direction_mappings']:
        if mapping['mapping_evidence']: actual_refs.add(_ref(mapping['mapping_evidence']))
    if any(ref not in actual for ref in actual_refs): gaps.update(actual_gaps)
    bad=any(item['status']=='mismatch' for item in fields) or any(item['status']=='fail' for item in matrix)
    complete=not gaps and len(fields)>=len(REQUIRED) and matrix and all(item['status']=='match' for item in fields) and all(item['status']=='pass' for item in matrix)
    technical='nonconformant' if bad else 'conformant' if complete else 'unverified'
    acceptance='awaiting_human_signoff' if technical=='conformant' and change['status'] in ('not_requested','ready_for_human_review') else 'blocked'
    gaps.update(change['gaps'])
    result=dict(schema_version=1,service=request['service'],technical_status=technical,human_signoff='pending',acceptance_status=acceptance,field_results=fields,test_matrix=matrix,change_review=change,gaps=sorted(gaps),counterevidence=[_qualified(key) for key in sorted(counterevidence)],missing_requirements=missing)
    result['draft_report']=_report(result,request['delivery_scope'])
    return result


def _worker(path,request_bytes):
    try:
        request=strict_json(request_bytes,True); result={'ok':True,'result':analyze(request)}
        data=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
        if len(data)>LIMIT: raise CaseError('service output budget exceeded')
    except Exception:
        data=b'{"ok":false}'
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as stream: stream.write(data)


def _process(request_bytes,result_path):
    return multiprocessing.get_context('spawn').Process(target=_worker,args=(str(result_path),request_bytes),daemon=True)


def analyze_bounded(request_bytes,timeout=5):
    result=_bounded_worker(_process,request_bytes,timeout)
    if result.get('gaps')==['analysis_timeout']:
        return dict(schema_version=1,service=None,technical_status='unverified',human_signoff='pending',acceptance_status='blocked',field_results=[],test_matrix=[],change_review=dict(status='blocked',checks=[],gaps=['analysis_timeout'],evidence_refs={}),gaps=['analysis_timeout'],counterevidence=[],missing_requirements=[],draft_report='Local draft: analysis timed out; human signoff is pending.')
    return result
