"""Offline access analyzer contract and public integration tests."""
import copy
import hashlib
import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT/'skills/netops-incident/scripts'
INGEST = SCRIPTS/'ingest.py'
ANALYZER = SCRIPTS/'diagnose_access.py'
CASE = SCRIPTS/'case.py'
SUMMARIES = ('manifest.json','evidence.jsonl','diagnosis.json','report.md')
sys.path.insert(0, str(SCRIPTS))
from case_runtime import access
from case_runtime import evidence as evidence_runtime

def blocked_access_test_worker():
    time.sleep(30)

class AccessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scope = {key:None for key in ('vantage','identity','operation','target','protocol','address_family','proxy','workload','original_window')}
        self.plan = {key:None for key in ('criterion','unit','window_seconds','cadence_seconds','maximum_gap_seconds','freshness_seconds','minimum_checks','minimum_coverage','owner','agreement_ref')}

    def create_run(self, name, data, fmt, aliases, metrics=None, values=None):
        source = self.root/(name+'-src'); source.mkdir()
        (source/'input.json').write_text(json.dumps(data))
        cfg = dict(format=fmt, run_id=name, source='source1' if name != 'topo1' else 'topology-source', actor='operator', authorization_ref='auth1', collected_at='2026-01-01T00:09:00Z', reference_time='2026-01-01T00:10:00Z', max_age_seconds=600, timezone='UTC', clock_quality='synchronized', clock_uncertainty_seconds=0, metric_allowlist=metrics or [], unit_allowlist=['dBm','packets'], relation_allowlist=['serves'], value_allowlists=values or {}, pseudonyms=aliases)
        config = self.root/(name+'-config.json'); config.write_text(json.dumps(cfg))
        out = self.root/name
        args = [sys.executable,'-B',str(INGEST),'--source-root',str(source),'--source','input.json','--config',str(config),'--out',str(out),'--private-out',str(self.root/(name+'-private'))]
        proc = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['parse_status'], 'complete')
        return dict(run_id=name, run_dir=str(out), expected_summary_hashes={item:hashlib.sha256((out/item).read_bytes()).hexdigest() for item in SUMMARIES})

    def base(self, metric='pppoe_auth', value='reject'):
        topology = dict(format='topology-json-v1', version=1, service_id='svc-raw', objects=[dict(id='svc-raw',type='service',layer='access'),dict(id='dev-raw',type='device',layer='access')], links=[dict(from_id='svc-raw',to_id='dev-raw',relation='serves',state='verified',confidence='high')])
        topo = self.create_run('topo1', topology, 'topology-json-v1', {'svc-raw':'service1','dev-raw':'device1'})
        record = dict(metric=metric,value=value,unit=None,direction='ingress',denominator=None,sample_interval_seconds=60,sample_count=1,counter_semantics='gauge',reset_state='none',event_time='2026-01-01T00:08:00Z',object_id='raw-id')
        data = dict(format='telemetry-json-v1',version=1,records=[record])
        run = self.create_run('run1',data,'telemetry-json-v1',{'raw-id':'source-alias'},[metric],{metric:[value]} if isinstance(value,str) else {})
        binding = dict(record=dict(run_id='run1',evidence_id='ev-000000000001'),topology_evidence=dict(run_id='topo1',evidence_id='ev-000000000001'),service_id='service1',resource_id='device1',source='source1',source_native_id='source-alias',valid_from='2026-01-01T00:00:00Z',valid_until='2026-01-01T00:09:00Z',authority='operator-map')
        request = dict(schema_version=1,reference_time='2026-01-01T00:10:00Z',window_start='2026-01-01T00:00:00Z',window_end='2026-01-01T00:09:00Z',max_age_seconds=600,service=dict(topology_run_id='topo1',object_id='service1'),runs=[run,topo],bindings=[binding],optical_profiles=[])
        return request

    def analyze(self, request, ok=True):
        path = self.root/'request.json'; path.write_text(json.dumps(request))
        result = subprocess.run([sys.executable,'-B',str(ANALYZER),'--input',str(path)],capture_output=True,text=True)
        if ok: self.assertEqual(result.returncode,0,result.stderr); return json.loads(result.stdout)
        self.assertNotEqual(result.returncode,0,result.stdout); return result

    def test_authentication_finding_has_real_qualified_references(self):
        result = self.analyze(self.base())
        self.assertEqual(result['status'], 'fault_observed')
        finding = next(item for item in result['findings'] if item['code'] == 'auth_reject')
        self.assertIn(dict(run_id='run1',evidence_id='ev-000000000001'),finding['support'])
        self.assertIn(dict(run_id='topo1',evidence_id='ev-000000000001'),finding['support'])
        self.assertIn('missing_reverse_direction',result['gaps'])
        self.assertNotIn(str(self.root),json.dumps(result))

    def test_stale_wrong_source_wrong_scope_and_forged_refs_abstain(self):
        request = self.base()
        variants = []
        stale = copy.deepcopy(request); stale['reference_time'] = '2026-01-02T00:10:00Z'; variants.append(stale)
        wrong_source = copy.deepcopy(request); wrong_source['bindings'][0]['source'] = 'another-source'; variants.append(wrong_source)
        wrong_scope = copy.deepcopy(request); wrong_scope['bindings'][0]['service_id'] = 'wrong-service'; variants.append(wrong_scope)
        forged = copy.deepcopy(request); forged['bindings'][0]['record']['evidence_id'] = 'ev-000000000099'; variants.append(forged)
        for variant in variants:
            with self.subTest(variant=variant):
                outcome = self.analyze(variant)
                self.assertEqual(outcome['status'],'insufficient_evidence')
                self.assertFalse(any(item['code'] == 'auth_reject' for item in outcome['findings']))

    def test_unknown_request_field_and_hash_tampering_rejected(self):
        request = self.base(); request['extra'] = 'secret'
        self.analyze(request,ok=False)
        del request['extra']; request['runs'][0]['expected_summary_hashes']['manifest.json'] = '0'*64
        self.analyze(request,ok=False)

    def test_control_characters_in_request_are_rejected_without_echo(self):
        request = self.base(); request['bindings'][0]['authority'] = 'operator\nSECRET'
        result = self.analyze(request,ok=False)
        self.assertNotIn('SECRET',result.stderr)
        self.assertNotIn(str(self.root),result.stderr)

    def test_public_oversized_and_symlink_requests_are_rejected(self):
        oversized = self.root/'oversized-request.json'
        with oversized.open('wb') as stream: stream.truncate(1024 * 1024 + 1)
        result = subprocess.run([sys.executable,'-B',str(ANALYZER),'--input',str(oversized)],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stdout,'')
        regular = self.root/'regular-request.json'; regular.write_text('{}')
        link = self.root/'request-link.json'
        try: link.symlink_to(regular)
        except (OSError, NotImplementedError): return
        result = subprocess.run([sys.executable,'-B',str(ANALYZER),'--input',str(link)],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stdout,'')

    def test_correctly_rehashed_oversized_run_is_rejected(self):
        request = self.base()
        run = request['runs'][0]; directory = Path(run['run_dir'])
        report = directory/'report.md'; report.write_bytes(b'x' * (2 * 1024 * 1024 + 1))
        manifest_path = directory/'manifest.json'; manifest = json.loads(manifest_path.read_text())
        report_hash = hashlib.sha256(report.read_bytes()).hexdigest()
        manifest['artifact_hashes']['report.md'] = report_hash
        manifest_path.write_text(json.dumps(manifest))
        run['expected_summary_hashes']['report.md'] = report_hash
        run['expected_summary_hashes']['manifest.json'] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        result = self.analyze(request,ok=False)
        self.assertEqual(result.stdout,'')
        self.assertNotIn(str(self.root),result.stderr)

    def test_bounded_run_reads_shared_visible_artifact_once(self):
        record = dict(metric='pppoe_auth',value='reject',unit=None,direction='ingress',denominator=None,sample_interval_seconds=60,sample_count=1,counter_semantics='gauge',reset_state='none',event_time='2026-01-01T00:08:00Z',object_id='raw-id')
        run = self.create_run('many1',dict(format='telemetry-json-v1',version=1,records=[record]*5),'telemetry-json-v1',{'raw-id':'source-alias'},['pppoe_auth'],{'pppoe_auth':['reject']})
        calls = []
        original = evidence_runtime.read_confined
        def observed_read(root, relative, maximum):
            calls.append(relative)
            return original(root, relative, maximum)
        limits = dict(per_run=2 * 1024 * 1024,aggregate=[16 * 1024 * 1024],records=[512])
        with mock.patch.object(evidence_runtime,'read_confined',side_effect=observed_read):
            snapshots, _, _, ids = evidence_runtime.validate_run(run,limits=limits)
        self.assertEqual(len(ids),5)
        self.assertIn('carrier-visible.json',snapshots)
        self.assertEqual(calls.count('carrier-visible.json'),1)

    def test_single_optical_sample_cannot_identify_optical_fault(self):
        request = self.base(metric='optical_rx_power',value=-21.0)
        result = self.analyze(request)
        self.assertEqual(result['status'],'insufficient_evidence')
        self.assertFalse(result['findings'])
        self.assertIn('missing_comparable_optical_profile',result['gaps'])

    def test_unknown_metric_is_an_explicit_coverage_gap(self):
        result = self.analyze(self.base(metric='custom_metric',value='unknown'))
        self.assertEqual(result['status'],'insufficient_evidence')
        self.assertIn('unsupported_metric',result['gaps'])
        self.assertFalse(result['findings'])

    def test_normal_fec_increment_is_neutral_not_a_fault(self):
        request = self.base(metric='fec_count',value=1)
        common = dict(metric='fec_count',unit='packets',direction='ingress',denominator='packets',sample_interval_seconds=60,sample_count=1,counter_semantics='cumulative',reset_state='none',object_id='raw-id')
        first = dict(common,value=100,event_time='2026-01-01T00:06:00Z')
        second = dict(common,value=120,event_time='2026-01-01T00:08:00Z')
        data = dict(format='telemetry-json-v1',version=1,records=[first,second])
        counter_run = self.create_run('counter1',data,'telemetry-json-v1',{'raw-id':'source-alias'},['fec_count'])
        request['runs'] = [request['runs'][1],counter_run]
        template = request['bindings'][0]
        request['bindings'] = [dict(template,record=dict(run_id='counter1',evidence_id='ev-000000000001')),dict(template,record=dict(run_id='counter1',evidence_id='ev-000000000002'))]
        result = self.analyze(request)
        self.assertEqual(result['status'],'insufficient_evidence')
        finding = next(item for item in result['findings'] if item['code'] == 'counter_increase')
        self.assertIn('does not establish a fault', ' '.join(finding['limitations']))

    def test_strict_request_json_rejects_duplicate_keys_and_nonfinite(self):
        path = self.root/'malformed-request.json'
        for data in (b'{"schema_version":1,"schema_version":1}',b'{"schema_version":NaN}'):
            path.write_bytes(data)
            result = subprocess.run([sys.executable,'-B',str(ANALYZER),'--input',str(path)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertNotIn(str(self.root),result.stderr)

    def test_worker_timeout_terminates_and_reaps_real_child(self):
        children = []; output_paths = []
        def blocked_factory(request_bytes, result_path):
            process = multiprocessing.get_context('spawn').Process(target=blocked_access_test_worker)
            children.append(process); output_paths.append(result_path)
            return process
        with mock.patch.object(access,'_process',side_effect=blocked_factory):
            result = access.analyze_bounded(b'{}',timeout=.2)
        self.assertEqual(result['status'],'insufficient_evidence')
        self.assertIn('analysis_timeout',result['gaps'])
        self.assertFalse(children[0].is_alive())
        self.assertIsNotNone(children[0].exitcode)
        self.assertFalse(output_paths[0].exists())

    def optical_request(self, second_direction='ingress'):
        request = self.base()
        common = dict(unit='dBm',direction='ingress',denominator=None,sample_interval_seconds=None,sample_count=1,counter_semantics='gauge',reset_state='none',object_id='raw-id')
        records = [dict(common,metric='optical_rx_power',value=-19.0,event_time='2026-01-01T00:06:00Z'),dict(common,metric='optical_rx_power',value=-23.0,direction=second_direction,event_time='2026-01-01T00:08:00Z'),dict(common,metric='optical_rx_lower_limit',value=-20.0,event_time='2026-01-01T00:05:00Z'),dict(common,metric='device_model',value='model1',unit=None,direction='unknown',event_time='2026-01-01T00:05:00Z')]
        data = dict(format='telemetry-json-v1',version=1,records=records)
        run = self.create_run('opt1',data,'telemetry-json-v1',{'raw-id':'source-alias'},['optical_rx_power','optical_rx_lower_limit','device_model'],{'device_model':['model1']})
        request['runs'] = [request['runs'][1],run]
        template = request['bindings'][0]
        request['bindings'] = [dict(template,record=dict(run_id='opt1',evidence_id='ev-'+format(index,'012x'))) for index in range(1,5)]
        request['optical_profiles'] = [dict(profile_id='source-alias',device_model='model1',source='source1',valid_from='2026-01-01T00:00:00Z',valid_until='2026-01-01T00:09:00Z',direction='ingress',unit='dBm',limit_evidence=dict(run_id='opt1',evidence_id='ev-000000000003'),device_model_evidence=dict(run_id='opt1',evidence_id='ev-000000000004'))]
        return request

    def add_observations(self, request, name, rows, alias='source-alias'):
        metrics = sorted({row['metric'] for row in rows})
        enum_values = {metric: sorted({row['value'] for row in rows if row['metric'] == metric and isinstance(row['value'],str)}) for metric in metrics}
        enum_values = {metric: values for metric, values in enum_values.items() if values}
        run = self.create_run(name,dict(format='telemetry-json-v1',version=1,records=rows),'telemetry-json-v1',{'raw-id':alias},metrics,enum_values)
        result = copy.deepcopy(request); result['runs'].append(run)
        template = request['bindings'][0]
        result['bindings'].extend(dict(template,source_native_id=alias,record=dict(run_id=name,evidence_id='ev-'+format(index,'012x'))) for index in range(1,len(rows)+1))
        return result

    def test_conflicting_optical_samples_are_cited_and_do_not_establish_fault(self):
        request = self.optical_request()
        row = dict(metric='optical_rx_power',value=-18.0,unit='dBm',direction='ingress',denominator=None,sample_interval_seconds=None,sample_count=1,counter_semantics='gauge',reset_state='none',event_time='2026-01-01T00:08:00Z',object_id='raw-id')
        result = self.analyze(self.add_observations(request,'normal2',[row]))
        self.assertEqual(result['status'],'insufficient_evidence')
        self.assertIn('conflicting_observations',result['gaps'])
        self.assertNotIn('optical_degradation',{item['code'] for item in result['findings']})
        conflict = next(item for item in result['findings'] if item['code'] == 'optical_conflict')
        self.assertIn(dict(run_id='normal2',evidence_id='ev-000000000001'),conflict['counterevidence'])
        row['direction'] = 'egress'
        result = self.analyze(self.add_observations(request,'normal3',[row]))
        self.assertIn('optical_degradation',{item['code'] for item in result['findings']})
        self.assertNotIn('optical_conflict',{item['code'] for item in result['findings']})
        row.update(direction='ingress',event_time='2026-01-01T00:07:30Z')
        result = self.analyze(self.add_observations(request,'normal4',[row]))
        self.assertIn('optical_degradation',{item['code'] for item in result['findings']})
        self.assertNotIn('optical_conflict',{item['code'] for item in result['findings']})
        row.update(event_time='2026-01-01T00:08:00Z',sample_count=2)
        result = self.analyze(self.add_observations(request,'normal5',[row]))
        self.assertIn('optical_degradation',{item['code'] for item in result['findings']})
        self.assertNotIn('optical_conflict',{item['code'] for item in result['findings']})

    def test_reverse_direction_requires_same_supported_operation_and_scope(self):
        request = self.base(metric='application_state',value='fail')
        row = dict(metric='unsupported_metric',value=None,unit=None,direction='egress',denominator=None,sample_interval_seconds=None,sample_count=None,counter_semantics='unknown',reset_state='unknown',event_time='2026-01-01T00:08:00Z',object_id='raw-id')
        unsupported = self.analyze(self.add_observations(request,'reverse-unknown',[row]))
        self.assertIn('missing_reverse_direction',unsupported['gaps'])
        row.update(metric='wifi_state',value='pass',counter_semantics='gauge',reset_state='none',sample_count=1)
        unrelated = self.analyze(self.add_observations(request,'reverse-unrelated',[row]))
        self.assertIn('missing_reverse_direction',unrelated['gaps'])
        row.update(metric='application_state',sample_interval_seconds=60)
        wrong_scope = self.analyze(self.add_observations(request,'reverse-other',[row],alias='other-alias'))
        self.assertIn('missing_reverse_direction',wrong_scope['gaps'])
        row['event_time'] = '2026-01-01T00:07:00Z'
        wrong_window = self.analyze(self.add_observations(request,'reverse-time',[row]))
        self.assertIn('missing_reverse_direction',wrong_window['gaps'])
        row['event_time'] = '2026-01-01T00:08:00Z'
        row['sample_interval_seconds'] = 30
        wrong_interval = self.analyze(self.add_observations(request,'reverse-interval',[row]))
        self.assertIn('missing_reverse_direction',wrong_interval['gaps'])
        row['sample_interval_seconds'] = 60
        compatible = self.analyze(self.add_observations(request,'reverse-good',[row]))
        self.assertNotIn('missing_reverse_direction',compatible['gaps'])

    def test_counter_missingness_and_known_gauge_remain_distinct(self):
        request = self.base(metric='fec_count',value=100)
        base_request = copy.deepcopy(request)
        common = dict(metric='fec_count',unit=None,direction='ingress',denominator=None,sample_interval_seconds=None,sample_count=None,counter_semantics='unknown',reset_state='unknown',object_id='raw-id')
        rows = [dict(common,value=100,event_time='2026-01-01T00:06:00Z'),dict(common,value=120,event_time='2026-01-01T00:08:00Z',sample_count=0)]
        request = self.add_observations(request,'counter-unknown',rows)
        request['runs'] = [run for run in request['runs'] if run['run_id'] != 'run1']
        request['bindings'] = [binding for binding in request['bindings'] if binding['record']['run_id'] != 'run1']
        result = self.analyze(request)
        expected = {'unknown_counter_semantics','missing_sample_count','missing_sample_interval','missing_counter_unit','missing_counter_denominator','unknown_counter_reset_state'}
        self.assertTrue(expected.issubset(result['gaps']))
        self.assertNotIn('counter_increase',{item['code'] for item in result['findings']})
        review_rows = [dict(row,counter_semantics='unknown',reset_state='none',sample_count=1,unit='packets',denominator='packets') for row in rows]
        review_case = self.add_observations(base_request,'counter-review',review_rows)
        review_case['runs'] = [run for run in review_case['runs'] if run['run_id'] != 'run1']
        review_case['bindings'] = [binding for binding in review_case['bindings'] if binding['record']['run_id'] != 'run1']
        review_result = self.analyze(review_case)
        self.assertTrue({'unknown_counter_semantics','missing_sample_interval'}.issubset(review_result['gaps']))
        self.assertNotIn('counter_increase',{item['code'] for item in review_result['findings']})
        rows = [dict(row,counter_semantics='gauge',reset_state='none',sample_count=1,unit='packets') for row in rows]
        gauge_case = self.add_observations(base_request,'counter-gauge',rows)
        gauge_case['runs'] = [run for run in gauge_case['runs'] if run['run_id'] != 'run1']
        gauge_case['bindings'] = [binding for binding in gauge_case['bindings'] if binding['record']['run_id'] != 'run1']
        gauge = self.analyze(gauge_case)
        self.assertIn('counter_semantics_not_cumulative',gauge['gaps'])
        self.assertNotIn('unknown_counter_semantics',gauge['gaps'])
        self.assertNotIn('missing_sample_interval',gauge['gaps'])
        self.assertNotIn('missing_counter_denominator',gauge['gaps'])
        wrapped_rows = [dict(row,counter_semantics='cumulative',reset_state='wrap',sample_count=1,unit='packets',denominator='packets',sample_interval_seconds=60) for row in rows]
        wrapped_case = self.add_observations(base_request,'counter-wrap',wrapped_rows)
        wrapped_case['runs'] = [run for run in wrapped_case['runs'] if run['run_id'] != 'run1']
        wrapped_case['bindings'] = [binding for binding in wrapped_case['bindings'] if binding['record']['run_id'] != 'run1']
        wrapped = self.analyze(wrapped_case)
        self.assertIn('counter_reset',wrapped['gaps'])
        self.assertNotIn('counter_increase',{item['code'] for item in wrapped['findings']})

    def test_utf16_and_utf32_request_are_rejected(self):
        request = self.base(); path = self.root/'encoded-request.json'
        for encoding in ('utf-16','utf-32'):
            path.write_bytes(json.dumps(request).encode(encoding))
            result = subprocess.run([sys.executable,'-B',str(ANALYZER),'--input',str(path)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stdout,'')
        self.assertEqual(self.analyze(request)['status'],'fault_observed')

    def test_both_ordered_pon_flap_sequences_and_nonflap(self):
        request = self.base()
        common = dict(metric='pon_session_state',unit=None,direction='ingress',denominator=None,sample_interval_seconds=None,sample_count=1,counter_semantics='gauge',reset_state='none',object_id='raw-id')
        for suffix, sequence, expected in [('down-up-down',['down','up','down'],True),('up-down-up',['up','down','up'],True),('no-flap',['up','up','down'],False)]:
            rows = [dict(common,value=value,event_time='2026-01-01T00:0'+str(index+5)+':00Z') for index,value in enumerate(sequence)]
            case = self.add_observations(request,suffix,rows)
            case['runs'] = [run for run in case['runs'] if run['run_id'] != 'run1']
            case['bindings'] = [binding for binding in case['bindings'] if binding['record']['run_id'] != 'run1']
            result = self.analyze(case)
            self.assertEqual('pon_flap' in {item['code'] for item in result['findings']},expected)

    def test_optical_profile_provenance_and_model_are_required(self):
        request = self.optical_request()
        result = self.analyze(request)
        self.assertIn('optical_degradation',{item['code'] for item in result['findings']})
        for field, value in (('source','wrong-source'),('device_model','other-model'),('profile_id','wrong-profile')):
            variant = copy.deepcopy(request); variant['optical_profiles'][0][field] = value
            result = self.analyze(variant)
            self.assertEqual(result['status'],'insufficient_evidence')
            self.assertNotIn('optical_degradation',{item['code'] for item in result['findings']})

    def test_incompatible_optical_direction_blocks_trend(self):
        result = self.analyze(self.optical_request(second_direction='egress'))
        self.assertEqual(result['status'],'insufficient_evidence')
        self.assertNotIn('optical_degradation',{item['code'] for item in result['findings']})

    def test_public_case_decision_accepts_real_output_references(self):
        request = self.base(); result = self.analyze(request)
        case = self.root/'case'; eventpath = self.root/'case-event.json'
        def call(command, payload):
            eventpath.write_text(json.dumps(payload))
            proc = subprocess.run([sys.executable,'-B',str(CASE),command,'--case',str(case),'--input',str(eventpath)],capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr); return json.loads(proc.stdout)
        state = call('create',dict(case_id='case1',event_id='create',actor='operator',occurred_at='2026-01-01T00:00:00Z',symptom='access unavailable',business_impact='unknown',scope=self.scope,verification_plan=self.plan))
        for index, run in enumerate(request['runs']):
            state = call('import-run',dict(event_id='import'+str(index),actor='operator',occurred_at='2026-01-01T00:10:00Z',expected_revision=state['revision'],**run))
        finding = result['findings'][0]
        state = call('decision',dict(event_id='decision',actor='operator',occurred_at='2026-01-01T00:10:00Z',expected_revision=state['revision'],observations=[finding['observation']],hypotheses=[finding['hypothesis']],support=finding['support'],counterevidence=finding['counterevidence'],confidence='low',limitations=finding['limitations'],next_test=None,expected_support=None,expected_counterevidence=None,changed_condition=None))
        self.assertEqual(state['decisions'][-1]['support'],finding['support'])

    def test_twelve_visible_cases_against_separate_oracle(self):
        fixture_root = (ROOT/'tests/fixtures/carrier-m3').resolve()
        oracle = json.loads((fixture_root/'oracle/expected.json').read_text())
        cases = oracle['cases']
        self.assertGreaterEqual(len(cases),12)
        for spec in cases:
            with self.subTest(case=spec['case_id']):
                case_root = fixture_root/'cases'/spec['case_id']
                scenario = json.loads((case_root/'scenario.json').read_text())
                temp = self.root/('fixture-'+spec['case_id']); temp.mkdir()
                runs = {}
                for source in scenario['sources']:
                    config_path = (fixture_root/source['config_path']).resolve()
                    input_path = (fixture_root/source['input_path']).resolve()
                    self.assertTrue(config_path.is_relative_to(fixture_root) and input_path.is_relative_to(fixture_root))
                    config = json.loads(config_path.read_text())
                    source_dir = temp/(source['run_key']+'-source'); source_dir.mkdir()
                    (source_dir/'input').write_bytes(input_path.read_bytes())
                    out = temp/(source['run_key']+'-out')
                    proc = subprocess.run([sys.executable,'-B',str(INGEST),'--source-root',str(source_dir),'--source','input','--config',str(config_path),'--out',str(out),'--private-out',str(temp/(source['run_key']+'-private'))],capture_output=True,text=True)
                    self.assertEqual(proc.returncode,0,proc.stderr)
                    runs[config['run_id']] = dict(run_id=config['run_id'],run_dir=str(out),expected_summary_hashes={name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in SUMMARIES})
                request = scenario['request']
                request['runs'] = [runs[run['run_id']] for run in request['runs']]
                result = self.analyze(request)
                self.assertEqual(result['status'],spec['status'])
                codes = {finding['code'] for finding in result['findings']}
                self.assertTrue(set(spec['required_codes']).issubset(codes))
                self.assertTrue(set(spec['prohibited_codes']).isdisjoint(codes))
                self.assertTrue({finding['layer'] for finding in result['findings']}.issubset(set(spec['allowed_layers'])))
                for key, expected in (('support','required_support'),('counterevidence','required_counterevidence')):
                    actual = {(ref['run_id'],ref['evidence_id']) for finding in result['findings'] for ref in finding[key]}
                    self.assertTrue({(ref['run_id'],ref['evidence_id']) for ref in spec[expected]}.issubset(actual))
                self.assertTrue(all(finding['resource_id'] is None for finding in result['findings']))

if __name__ == '__main__': unittest.main()
