"""Public offline service review and acceptance boundary tests."""
import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT/'skills/netops-incident/scripts/review_service.py'
INGEST = ROOT/'skills/netops-incident/scripts/ingest.py'
CASE = ROOT/'skills/netops-incident/scripts/case.py'
FIXTURES = ROOT/'tests/fixtures/carrier-m5'
SUMMARIES = ('manifest.json','evidence.jsonl','diagnosis.json','report.md')


class ServiceReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.cache={}
        spec=importlib.util.spec_from_file_location('service_fixture_refs',FIXTURES/'materialize_refs.py')
        self.refs=importlib.util.module_from_spec(spec); spec.loader.exec_module(self.refs)

    def materialize(self,scenario,overrides=None,config_overrides=None):
        self.assertNotIn('case_id',scenario['request'],'scenario metadata must not enter provider requests')
        row_ids={}; run_ids={}; runs={}
        for source in scenario['sources']:
            key=source['run_key']; config_path=(FIXTURES/source['config_path']).resolve(); input_path=(FIXTURES/source['input_path']).resolve()
            self.assertTrue(config_path.is_relative_to(FIXTURES.resolve()) and input_path.is_relative_to(FIXTURES.resolve()))
            config=self.refs.resolve_source_tokens(json.loads(config_path.read_text()),row_ids,run_ids)
            data=self.refs.resolve_source_tokens(json.loads(input_path.read_text()),row_ids,run_ids)
            if overrides and key in overrides: data=overrides[key](copy.deepcopy(data))
            if config_overrides and key in config_overrides: config=config_overrides[key](copy.deepcopy(config))
            cache_key=hashlib.sha256(json.dumps([config,data],sort_keys=True).encode()).hexdigest()
            if cache_key not in self.cache:
                attempt=Path(tempfile.mkdtemp(prefix='ingest-',dir=self.root))
                try:
                    folder=attempt/'source'; folder.mkdir()
                    if isinstance(data,dict) and isinstance(data.get('records'),list):
                        header={key:value for key,value in data.items() if key!='records'}
                        source_text=json.dumps(header)[:-1]+',"records":[\n'+',\n'.join(json.dumps(row,separators=(',',':')) for row in data['records'])+'\n]}'
                    else: source_text=json.dumps(data)
                    (folder/'input.json').write_text(source_text)
                    config_file=attempt/'config.json'; config_file.write_text(json.dumps(config)); out=attempt/'run'
                    result=subprocess.run([sys.executable,'-B',str(INGEST),'--source-root',str(folder),'--source','input.json','--config',str(config_file),'--out',str(out),'--private-out',str(attempt/'private')],capture_output=True,text=True)
                    self.assertEqual(result.returncode,0,result.stderr); self.assertEqual(json.loads(result.stdout)['parse_status'],'complete')
                    self.cache[cache_key]=out
                except BaseException:
                    shutil.rmtree(attempt)
                    raise
            out=self.cache[cache_key]
            evidence=[json.loads(line) for line in (out/'evidence.jsonl').read_text().splitlines() if line.strip()]
            keys=source['row_keys']; self.assertEqual(len(keys),len(evidence)); self.assertEqual(len(keys),len(set(keys)))
            row_ids[key]={label:record['id'] for label,record in zip(keys,evidence)}; run_ids[key]=config['run_id']
            runs[config['run_id']]=dict(run_id=config['run_id'],run_dir=str(out),expected_summary_hashes={name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in SUMMARIES})
        request=self.refs.resolve_row_refs(copy.deepcopy(scenario['request']),row_ids)
        request['runs']=[runs[run['run_id']] for run in request['runs']]
        return request,row_ids

    def test_failed_ingest_retry_is_isolated_and_scenario_metadata_stays_out(self):
        full=json.loads((FIXTURES/'cases/case-009/scenario.json').read_text())
        source=next(item for item in full['sources'] if item['run_key']=='topology')
        topology_run=next(item for item in full['request']['runs'] if item['run_id']==full['request']['service']['topology_run_id'])
        scenario=dict(case_id='developer-only',sources=[source],request=dict(runs=[topology_run]))
        sentinel=self.root/'untouched'; sentinel.write_text('preserve')
        def rejected(args,**kwargs):
            Path(args[args.index('--out')+1]).mkdir()
            Path(args[args.index('--private-out')+1]).mkdir()
            return subprocess.CompletedProcess(args,0,stdout=json.dumps({'parse_status':'parse_error'}),stderr='')
        with mock.patch.object(subprocess,'run',side_effect=rejected):
            with self.assertRaises(AssertionError): self.materialize(scenario)
        self.assertEqual(sentinel.read_text(),'preserve')
        self.assertEqual(set(self.root.iterdir()),{sentinel}); self.assertFalse(self.cache)
        request,rows=self.materialize(scenario)
        self.assertNotIn('case_id',request); self.assertIn('topology',rows)
        leaked=copy.deepcopy(scenario); leaked['request']['case_id']='developer-only'
        with self.assertRaisesRegex(AssertionError,'scenario metadata'): self.materialize(leaked)

    def review(self,request):
        path=self.root/'review.json'; path.write_text(json.dumps(request))
        result=subprocess.run([sys.executable,'-B',str(REVIEW),'--input',str(path)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        return json.loads(result.stdout)

    def test_complete_control_and_blocked_change_stay_separate(self):
        scenario=json.loads((FIXTURES/'cases/case-009/scenario.json').read_text()); request,_=self.materialize(scenario)
        result=self.review(request)
        self.assertEqual(result['technical_status'],'conformant'); self.assertEqual(result['acceptance_status'],'awaiting_human_signoff'); self.assertEqual(result['human_signoff'],'pending')
        unexpected=copy.deepcopy(request); unexpected['case_id']='developer-only'
        bad_input=self.root/'unexpected-field.json'; bad_input.write_text(json.dumps(unexpected))
        rejected=subprocess.run([sys.executable,'-B',str(REVIEW),'--input',str(bad_input)],capture_output=True,text=True)
        self.assertNotEqual(rejected.returncode,0); self.assertEqual(rejected.stdout,'')
        report=result['draft_report']
        for heading in ('# Service acceptance and handover draft','## Field comparisons','## Acceptance tests','## Change review','## Outstanding evidence and signoff'):
            self.assertIn(heading,report)
        self.assertNotIn(str(self.root),report); self.assertIn('human signoff: pending',report)
        changed=copy.deepcopy(request)
        changed['change_review']=dict(phase='post_change',scope_evidence=None,impact_evidence=None,planned_start_evidence=None,planned_end_evidence=None,approval_evidence=None,approval_reference_evidence=None,rollback_trigger_evidence=None,rollback_owner_evidence=None,residual_risk_evidence=[],check_inventory=None,checks=[])
        result=self.review(changed)
        self.assertEqual(result['technical_status'],'conformant'); self.assertEqual(result['change_review']['status'],'blocked'); self.assertEqual(result['acceptance_status'],'blocked')
        wrong=copy.deepcopy(request); wrong['criteria'][0]['source_native_id']='other-criterion'
        self.assertNotEqual(self.review(wrong)['technical_status'],'conformant')
        one_way=copy.deepcopy(request); one_way['direction_mappings']=[item for item in one_way['direction_mappings'] if item['absolute_direction']!='B_to_A']
        self.assertNotEqual(self.review(one_way)['technical_status'],'conformant')
        missing_method=copy.deepcopy(request); missing_method['criteria'][0]['method_evidence']=None
        self.assertIn('missing_criterion_evidence',self.review(missing_method)['gaps'])
        missing_field=copy.deepcopy(request); omitted=missing_field['fields'].pop()
        missing=self.review(missing_field)['missing_requirements']
        self.assertIn(dict(kind='field',id=omitted['field']+'_'+omitted['target'],required_ref=omitted['required_evidence']),missing)
        missing_criterion=copy.deepcopy(request); omitted_criterion=missing_criterion['criteria'].pop()
        missing=self.review(missing_criterion)['missing_requirements']
        self.assertTrue(any(item['kind']=='criterion' and item['id']==omitted_criterion['criterion_id'] and item['required_ref'] for item in missing))
        missing_calibration=copy.deepcopy(request); missing_calibration['test_results'][0]['calibration_evidence']=None
        self.assertIn('missing_calibration',self.review(missing_calibration)['gaps'])
        bad_mapping=copy.deepcopy(request); bad_mapping['direction_mappings'][0]['point_id']=bad_mapping['delivery_scope']['endpoint_b_id']
        self.assertIn('missing_direction_mapping',self.review(bad_mapping)['gaps'])
        forged=copy.deepcopy(request); forged['runs'][0]['expected_summary_hashes']['manifest.json']='0'*64
        path=self.root/'forged.json'; path.write_text(json.dumps(forged))
        proc=subprocess.run([sys.executable,'-B',str(REVIEW),'--input',str(path)],capture_output=True,text=True)
        self.assertNotEqual(proc.returncode,0); self.assertEqual(proc.stdout,'')

        case=self.root/'case'; eventpath=self.root/'case-event.json'
        def call(command,payload):
            eventpath.write_text(json.dumps(payload))
            proc=subprocess.run([sys.executable,'-B',str(CASE),command,'--case',str(case),'--input',str(eventpath)],capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr); return json.loads(proc.stdout)
        scope={key:None for key in ('vantage','identity','operation','target','protocol','address_family','proxy','workload','original_window')}
        plan={key:None for key in ('criterion','unit','window_seconds','cadence_seconds','maximum_gap_seconds','freshness_seconds','minimum_checks','minimum_coverage','owner','agreement_ref')}
        state=call('create',dict(case_id='servicecase',event_id='create',actor='operator',occurred_at='2026-11-13T00:00:00Z',symptom='service review',business_impact='unknown',scope=scope,verification_plan=plan))
        for index,run in enumerate(request['runs']):
            state=call('import-run',dict(event_id='import'+str(index),actor='operator',occurred_at='2026-11-13T00:10:00Z',expected_revision=state['revision'],**run))
        support=[result['test_matrix'][0]['measurement_ref'],result['test_matrix'][0]['topology_ref']]
        state=call('decision',dict(event_id='decision',actor='operator',occurred_at='2026-11-13T00:10:00Z',expected_revision=state['revision'],observations=['A scoped acceptance measurement was reviewed.'],hypotheses=['Human review remains pending.'],support=support,counterevidence=[],confidence='low',limitations=['Operator assertions are unauthenticated.'],next_test=None,expected_support=None,expected_counterevidence=None,changed_condition=None))
        self.assertEqual(state['decisions'][-1]['support'],support)

    def test_visible_scenarios_against_separate_oracle(self):
        oracle=json.loads((FIXTURES/'oracle/expected.json').read_text())['cases']
        self.assertGreaterEqual(len(oracle),13)
        for expected in oracle:
            with self.subTest(case=expected['case_id']):
                scenario=json.loads((FIXTURES/'cases'/expected['case_id']/'scenario.json').read_text())
                request,row_ids=self.materialize(scenario); result=self.review(request)
                oracle_case=self.refs.resolve_row_refs(expected,row_ids)
                for name in ('technical_status','acceptance_status'):
                    self.assertEqual(result[name],oracle_case[name])
                self.assertEqual(result['human_signoff'],'pending'); self.assertEqual(result['change_review']['status'],oracle_case['change_status'])
                self.assertTrue(set(oracle_case['required_gaps']).issubset(result['gaps']))
                for oracle_key,result_key in (('required_field_results','field_results'),('required_test_results','test_matrix')):
                    for required in oracle_case[oracle_key]:
                        self.assertTrue(any(all(item.get(key)==value for key,value in required.items()) for item in result[result_key]),required)
                for required in oracle_case.get('required_missing_requirements',[]): self.assertIn(required,result['missing_requirements'])
                serialized=json.dumps(result)
                for ref in oracle_case.get('required_support',[]):
                    self.assertIn(json.dumps(ref,sort_keys=True),json.dumps(result,sort_keys=True))
                self.assertNotIn(str(self.root),serialized); self.assertNotIn('accepted',result['acceptance_status'])

    def test_future_change_requires_validity_covering_planned_interval(self):
        scenario=json.loads((FIXTURES/'cases/case-010/scenario.json').read_text())
        request,_=self.materialize(scenario); baseline=self.review(request)
        self.assertEqual(baseline['change_review']['status'],'ready_for_human_review')
        missing_check=copy.deepcopy(request); omitted=missing_check['change_review']['checks'].pop()
        result=self.review(missing_check)
        self.assertIn(dict(kind='change_check',id=omitted['check_id'],required_ref=omitted['required_evidence']),result['missing_requirements'])
        self.assertEqual(result['change_review']['status'],'blocked')
        def expire_before_plan(data):
            planned=next(row['value'] for row in data['records'] if row['metric']=='change_window_start')
            for row in data['records']:
                if row['metric']=='static_valid_until': row['value']=planned-1
            return data
        variant,_=self.materialize(scenario,{'change':expire_before_plan}); result=self.review(variant)
        self.assertEqual(result['change_review']['status'],'blocked')
        self.assertEqual(result['acceptance_status'],'blocked'); self.assertIn('change_review_incomplete',result['gaps'])

    def test_checked_source_conflicts_and_incompatible_units_are_retained(self):
        original=json.loads((FIXTURES/'cases/case-009/scenario.json').read_text())
        request,_=self.materialize(original); self.assertEqual(self.review(request)['technical_status'],'conformant')
        scenario=copy.deepcopy(original); source=next(item for item in scenario['sources'] if item['run_key']=='actual-fields')
        index=source['row_keys'].index('target_vlan_endpoint_a'); source['row_keys'].append('conflicting_vlan_target')
        marker={'$row':'actual-fields/target_vlan_endpoint_a'}
        binding=next(item for item in scenario['request']['bindings'] if item['record']['run_id']=='m5-actual-fields' and item['record']['evidence_id']==marker)
        extra=copy.deepcopy(binding); extra['record']['evidence_id']={'$row':'actual-fields/conflicting_vlan_target'}; scenario['request']['bindings'].append(extra)
        def add_conflict(data):
            data['records'].append(dict(data['records'][index],value='vlan_endpoint_b',unit='%'))
            return data
        changed,ids=self.materialize(scenario,{'actual-fields':add_conflict}); result=self.review(changed)
        self.assertNotEqual(result['technical_status'],'conformant'); self.assertIn('conflicting_observations',result['gaps'])
        self.assertIn(dict(run_id='m5-actual-fields',evidence_id=ids['actual-fields']['conflicting_vlan_target']),result['counterevidence'])
        field=next(item for item in result['field_results'] if item['field']=='vlan' and item['target']=='endpoint_a')
        self.assertEqual(field['status'],'unverified'); self.assertTrue(field['counterevidence'])
        source=next(item for item in original['sources'] if item['run_key']=='actual-fields')
        bandwidth_index=source['row_keys'].index('actual_bandwidth_endpoint_a')
        def wrong_unit(data): data['records'][bandwidth_index]['unit']='bytes'; return data
        changed,_=self.materialize(original,{'actual-fields':wrong_unit}); result=self.review(changed)
        self.assertIn('field_unit_mismatch',result['gaps']); self.assertNotEqual(result['technical_status'],'conformant')

    def test_source_criteria_cannot_make_every_capability_one_way(self):
        scenario=json.loads((FIXTURES/'cases/case-009/scenario.json').read_text())
        def one_way(data):
            for row in data['records']:
                if row['metric']=='criterion_direction': row['value']='A_to_B'
            return data
        def allow(config): config['value_allowlists']['criterion_direction'].append('A_to_B'); return config
        request,_=self.materialize(scenario,{'criteria':one_way},{'criteria':allow})
        result=self.review(request)
        self.assertEqual(result['technical_status'],'unverified'); self.assertEqual(result['acceptance_status'],'blocked')
        self.assertIn('criterion_inventory_incomplete',result['gaps'])

    def test_postchange_approval_requires_known_ordered_time(self):
        scenario=json.loads((FIXTURES/'cases/case-011/scenario.json').read_text())
        request,_=self.materialize(scenario); self.assertEqual(self.review(request)['change_review']['status'],'ready_for_human_review')
        for name,event,uncertainty in [('unknown',None,0),('after','2026-11-13T00:04:30Z',0),('uncertain','2026-11-13T00:03:59Z',2)]:
            with self.subTest(name=name):
                def mutate(data):
                    for row in data['records']:
                        if row['metric']=='change_approval': row['event_time']=event
                    return data
                def clock(config): config['clock_uncertainty_seconds']=uncertainty; return config
                variant,_=self.materialize(scenario,{'change':mutate},{'change':clock})
                result=self.review(variant)
                self.assertEqual(result['change_review']['status'],'blocked'); self.assertEqual(result['acceptance_status'],'blocked')

    def test_strict_input_and_public_file_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name,content in [('duplicate',b'{"schema_version":1,"schema_version":1}'),('nonfinite',b'{"schema_version":NaN}'),('utf16','{}'.encode('utf-16'))]:
                path=root/(name+'.json'); path.write_bytes(content)
                result=subprocess.run([sys.executable,'-B',str(REVIEW),'--input',str(path)],capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0); self.assertEqual(result.stdout,'')
            large=root/'large.json'
            with large.open('wb') as stream: stream.truncate(1024*1024+1)
            result=subprocess.run([sys.executable,'-B',str(REVIEW),'--input',str(large)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0); self.assertEqual(result.stdout,'')
            link=root/'link.json'
            try: link.symlink_to(large)
            except (OSError,NotImplementedError): return
            result=subprocess.run([sys.executable,'-B',str(REVIEW),'--input',str(link)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0); self.assertEqual(result.stdout,'')
