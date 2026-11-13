"""Public offline transport analysis, safety, and shared M2 loader tests."""
import copy
import hashlib
import json
import multiprocessing
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_access as access_tests
from case_runtime import transport

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT/'skills/netops-incident/scripts'
INGEST = SCRIPTS/'ingest.py'
ANALYZER = SCRIPTS/'diagnose_transport.py'
SUMMARIES = ('manifest.json','evidence.jsonl','diagnosis.json','report.md')

class TransportTests(unittest.TestCase):
    def setUp(self):
        self.helper = access_tests.AccessTests(); self.helper.setUp(); self.addCleanup(self.helper.doCleanups)
        self.root = self.helper.root

    def base(self):
        access = self.helper.base()
        access['runs'] = [access['runs'][1]]
        access['bindings'] = []
        del access['optical_profiles']
        access['transport_profiles'] = []
        access['measurement_windows'] = []
        return access

    def add_run(self, request, name, rows, aliases=None):
        aliases = aliases or {'raw-id':'source-alias'}
        metrics = sorted({row['metric'] for row in rows})
        values = {metric:sorted({row['value'] for row in rows if row['metric']==metric and isinstance(row['value'],str)}) for metric in metrics}
        values = {metric: permitted for metric,permitted in values.items() if permitted}
        source = self.root/(name+'-src'); source.mkdir(); (source/'input.json').write_text(json.dumps(dict(format='telemetry-json-v1',version=1,records=rows)))
        cfg = dict(format='telemetry-json-v1',run_id=name,source='source1',actor='operator',authorization_ref='auth1',collected_at='2026-01-01T00:09:00Z',reference_time='2026-01-01T00:10:00Z',max_age_seconds=600,timezone='UTC',clock_quality='synchronized',clock_uncertainty_seconds=0,metric_allowlist=metrics,unit_allowlist=['bytes','packets','percent'],relation_allowlist=['serves'],value_allowlists=values,pseudonyms=aliases)
        config = self.root/(name+'-config.json'); config.write_text(json.dumps(cfg)); out = self.root/name
        result = subprocess.run([sys.executable,'-B',str(INGEST),'--source-root',str(source),'--source','input.json','--config',str(config),'--out',str(out),'--private-out',str(self.root/(name+'-private'))],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr); self.assertEqual(json.loads(result.stdout)['parse_status'],'complete')
        request = copy.deepcopy(request)
        request['runs'].append(dict(run_id=name,run_dir=str(out),expected_summary_hashes={key:hashlib.sha256((out/key).read_bytes()).hexdigest() for key in SUMMARIES}))
        for index in range(1,len(rows)+1):
            request['bindings'].append(dict(record=dict(run_id=name,evidence_id='ev-'+format(index,'012x')),topology_evidence=dict(run_id='topo1',evidence_id='ev-000000000001'),service_id='service1',resource_id='device1',source='source1',source_native_id=aliases['raw-id'],valid_from='2026-01-01T00:00:00Z',valid_until='2026-01-01T00:09:00Z',authority='operator-map'))
        return request

    def row(self, metric, value, **changes):
        row = dict(metric=metric,value=value,unit=None,direction='ingress',denominator=None,sample_interval_seconds=60,sample_count=1,counter_semantics='gauge',reset_state='none',event_time='2026-01-01T00:08:00Z',object_id='raw-id')
        row.update(changes); return row

    def analyze(self, request, ok=True):
        path = self.root/'transport-request.json'; path.write_text(json.dumps(request))
        result = subprocess.run([sys.executable,'-B',str(ANALYZER),'--input',str(path)],capture_output=True,text=True)
        if ok: self.assertEqual(result.returncode,0,result.stderr); return json.loads(result.stdout)
        self.assertNotEqual(result.returncode,0,result.stdout); return result

    def materialize_fixture(self, case_id, suffix=''):
        root = (ROOT/'tests/fixtures/carrier-m4').resolve()
        scenario = json.loads((root/'cases'/case_id/'scenario.json').read_text())
        temp = self.root/(case_id+suffix); temp.mkdir(); runs = {}
        for source in scenario['sources']:
            config_path=(root/source['config_path']).resolve(); input_path=(root/source['input_path']).resolve()
            self.assertTrue(config_path.is_relative_to(root) and input_path.is_relative_to(root))
            config=json.loads(config_path.read_text())
            source_dir=temp/(source['run_key']+'-source'); source_dir.mkdir()
            (source_dir/'input').write_bytes(input_path.read_bytes())
            out=temp/(source['run_key']+'-out')
            proc=subprocess.run([sys.executable,'-B',str(INGEST),'--source-root',str(source_dir),'--source','input','--config',str(config_path),'--out',str(out),'--private-out',str(temp/(source['run_key']+'-private'))],capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertEqual(json.loads(proc.stdout)['parse_status'],'complete')
            runs[config['run_id']]=dict(run_id=config['run_id'],run_dir=str(out),expected_summary_hashes={name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in SUMMARIES})
        request=scenario['request']; request['runs']=[runs[run['run_id']] for run in request['runs']]
        return request

    def test_bgp_event_is_neutral_and_preserves_real_service_pass(self):
        request = self.add_run(self.base(),'events1',[self.row('bgp_peer_state','down'),self.row('service_operation','pass')])
        result = self.analyze(request)
        self.assertEqual(result['status'],'insufficient_evidence')
        event = next(item for item in result['findings'] if item['code']=='bgp_peer_event')
        self.assertIn(dict(run_id='events1',evidence_id='ev-000000000002'),event['counterevidence'])
        self.assertTrue(all(item['resource_id'] is None for item in result['findings']))
        self.assertNotIn(str(self.root),json.dumps(result))

    def test_route_correlation_requires_matching_prefix_vrf_and_failure(self):
        rows = [self.row('route_state','withdrawn'),self.row('route_prefix','prefix-a'),self.row('service_prefix','prefix-a'),self.row('route_vrf','vrf-a'),self.row('service_vrf','vrf-a'),self.row('forwarding_state','fail')]
        request = self.add_run(self.base(),'route1',rows)
        result = self.analyze(request)
        self.assertEqual(result['status'],'fault_observed')
        finding = next(item for item in result['findings'] if item['code']=='route_service_correlation')
        self.assertTrue({('route1','ev-'+format(n,'012x')) for n in range(1,7)}.issubset({(r['run_id'],r['evidence_id']) for r in finding['support']}))
        altered = copy.deepcopy(request); altered['bindings'][2]['source_native_id'] = 'other-alias'
        result = self.analyze(altered)
        self.assertNotIn('route_service_correlation',{item['code'] for item in result['findings']})

    def test_unknown_control_reverse_and_utf8_are_bounded(self):
        request = self.add_run(self.base(),'unknown1',[self.row('bgp_peer_state','down'),self.row('unlisted_metric',None,direction='egress',sample_count=0)])
        result = self.analyze(request)
        self.assertIn('unsupported_metric',result['gaps']); self.assertIn('missing_reverse_direction',result['gaps'])
        bad = copy.deepcopy(request); bad['untrusted'] = 'secret'; self.analyze(bad,ok=False)
        path = self.root/'utf16.json'; path.write_bytes(json.dumps(request).encode('utf-16'))
        proc = subprocess.run([sys.executable,'-B',str(ANALYZER),'--input',str(path)],capture_output=True,text=True)
        self.assertNotEqual(proc.returncode,0); self.assertEqual(proc.stdout,'')

    def test_reverse_metadata_cannot_supply_operation_coverage(self):
        base=self.base()
        request = self.add_run(base,'metadata1',[self.row('service_operation','fail'),self.row('window_aggregation','mean',direction='egress')])
        result = self.analyze(request)
        self.assertIn('missing_reverse_direction',result['gaps'])
        self.assertIn('service_failure',{item['code'] for item in result['findings']})
        request = self.add_run(base,'metadata2',[self.row('service_operation','fail'),self.row('bgp_peer_state','up',direction='egress')])
        self.assertIn('missing_reverse_direction',self.analyze(request)['gaps'])

    def test_reverse_coverage_requires_supported_positive_samples(self):
        base=self.base()
        for index,count in enumerate((None,0,0.0,1,1.0)):
            with self.subTest(count=count):
                request=self.add_run(base,'reverse'+str(index),[self.row('service_operation','fail'),self.row('service_operation','pass',direction='egress',sample_count=count)])
                result=self.analyze(request)
                if count is None or count==0: self.assertIn('missing_reverse_direction',result['gaps'])
                else: self.assertNotIn('missing_reverse_direction',result['gaps'])

    def test_stale_control_does_not_become_current_evidence(self):
        request = self.add_run(self.base(),'stale1',[self.row('bgp_peer_state','down')])
        request['reference_time'] = '2026-01-02T00:10:00Z'
        result = self.analyze(request)
        self.assertEqual(result['status'],'insufficient_evidence')
        self.assertNotIn('bgp_peer_event',{item['code'] for item in result['findings']})
        self.assertIn('stale_or_outside_window',result['gaps'])

    def test_rehashed_malformed_enum_sampling_metadata_is_rejected_by_both_providers(self):
        request = self.add_run(self.base(),'forged1',[self.row('bgp_peer_state','down')])
        run = request['runs'][-1]; directory = Path(run['run_dir'])
        visible_path = directory/'carrier-visible.json'; visible = json.loads(visible_path.read_text())
        visible['records'][0]['sample_count'] = 'not-a-number'
        visible_path.write_text(json.dumps(visible))
        visible_hash = hashlib.sha256(visible_path.read_bytes()).hexdigest()
        evidence_path = directory/'evidence.jsonl'; record = json.loads(evidence_path.read_text())
        record['observation']['record']['sample_count'] = 'not-a-number'
        record['sources'][0]['sha256'] = visible_hash
        evidence_path.write_text(json.dumps(record)+'\n')
        manifest_path = directory/'manifest.json'; manifest = json.loads(manifest_path.read_text())
        manifest['artifact_hashes']['carrier-visible.json'] = visible_hash
        manifest['artifact_hashes']['evidence.jsonl'] = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        carrier = manifest['carrier_evidence']['records'][0]
        carrier['artifact_sha256'] = visible_hash; carrier['redaction']['visible_sha256'] = visible_hash
        manifest_path.write_text(json.dumps(manifest))
        run['expected_summary_hashes']['evidence.jsonl'] = manifest['artifact_hashes']['evidence.jsonl']
        run['expected_summary_hashes']['manifest.json'] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        self.analyze(request,ok=False)
        access_request = copy.deepcopy(request)
        del access_request['transport_profiles']; del access_request['measurement_windows']
        access_request['optical_profiles'] = []
        self.helper.analyze(access_request,ok=False)

    def test_worker_timeout_terminates_and_reaps_real_child(self):
        children=[]; outputs=[]
        def blocked_factory(request_bytes,result_path):
            process=multiprocessing.get_context('spawn').Process(target=access_tests.blocked_access_test_worker)
            children.append(process); outputs.append(result_path); return process
        with mock.patch.object(transport,'_process',side_effect=blocked_factory):
            result=transport.analyze_bounded(b'{}',timeout=.2)
        self.assertEqual(result['status'],'insufficient_evidence')
        self.assertIn('analysis_timeout',result['gaps'])
        self.assertFalse(children[0].is_alive()); self.assertIsNotNone(children[0].exitcode)
        self.assertFalse(outputs[0].exists())

    def test_oversized_and_symlink_input_rejected_without_output(self):
        large=self.root/'large.json'
        with large.open('wb') as stream: stream.truncate(1024 * 1024 + 1)
        result=subprocess.run([sys.executable,'-B',str(ANALYZER),'--input',str(large)],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0); self.assertEqual(result.stdout,'')
        source=self.root/'normal.json'; source.write_text('{}'); link=self.root/'input-link.json'
        try: link.symlink_to(source)
        except (OSError,NotImplementedError): return
        result=subprocess.run([sys.executable,'-B',str(ANALYZER),'--input',str(link)],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0); self.assertEqual(result.stdout,'')

    def test_rehashed_oversized_run_exceeds_shared_budget(self):
        request=self.add_run(self.base(),'large1',[self.row('bgp_peer_state','down')])
        run=request['runs'][-1]; directory=Path(run['run_dir']); report=directory/'report.md'
        report.write_bytes(b'x' * (2 * 1024 * 1024 + 1))
        manifest_path=directory/'manifest.json'; manifest=json.loads(manifest_path.read_text())
        report_hash=hashlib.sha256(report.read_bytes()).hexdigest()
        manifest['artifact_hashes']['report.md']=report_hash; manifest_path.write_text(json.dumps(manifest))
        run['expected_summary_hashes']['report.md']=report_hash
        run['expected_summary_hashes']['manifest.json']=hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        result=self.analyze(request,ok=False)
        self.assertEqual(result.stdout,''); self.assertNotIn(str(self.root),result.stderr)

    def test_twelve_visible_cases_against_separate_oracle(self):
        root = ROOT/'tests/fixtures/carrier-m4'
        cases = json.loads((root/'oracle/expected.json').read_text())['cases']
        self.assertGreaterEqual(len(cases),12)
        for spec in cases:
            with self.subTest(case=spec['case_id']):
                result=self.analyze(self.materialize_fixture(spec['case_id']))
                self.assertEqual(result['status'],spec['status'])
                codes={item['code'] for item in result['findings']}
                self.assertTrue(set(spec['required_codes']).issubset(codes))
                self.assertTrue(set(spec['prohibited_codes']).isdisjoint(codes))
                self.assertTrue({item['layer'] for item in result['findings']}.issubset(set(spec['allowed_layers'])))
                self.assertTrue(set(spec['required_gaps']).issubset(set(result['gaps'])))
                for key,expected in (('support','required_support'),('counterevidence','required_counterevidence')):
                    actual={(ref['run_id'],ref['evidence_id']) for item in result['findings'] for ref in item[key]}
                    self.assertTrue({(ref['run_id'],ref['evidence_id']) for ref in spec[expected]}.issubset(actual))
                self.assertTrue(all(item['resource_id'] is None for item in result['findings']))

    def test_queue_requires_source_supported_windows_and_profile(self):
        request=self.materialize_fixture('case-005')
        initial=self.analyze(request)
        condition=next(item for item in initial['findings'] if item['code']=='queue_condition')
        self.assertIn('does not establish customer impact',' '.join(condition['limitations']))
        self.assertIn(dict(run_id='m4-observations',evidence_id='ev-000000000010'),condition['counterevidence'])
        missing=copy.deepcopy(request); missing['measurement_windows']=[]
        result=self.analyze(missing)
        self.assertNotIn('queue_condition',{item['code'] for item in result['findings']})
        self.assertIn('missing_measurement_window',result['gaps'])
        wrong=copy.deepcopy(request); wrong['transport_profiles'][0]['aggregation']='max'
        result=self.analyze(wrong)
        self.assertNotIn('queue_condition',{item['code'] for item in result['findings']})
        self.assertIn('missing_transport_profile',result['gaps'])
        bad_end=copy.deepcopy(request); bad_end['measurement_windows'][0]['end_evidence']=bad_end['measurement_windows'][0]['start_evidence']
        result=self.analyze(bad_end)
        self.assertNotIn('queue_condition',{item['code'] for item in result['findings']})
        self.assertIn('incompatible_window',result['gaps'])

    def test_missing_qos_class_blocks_class_condition(self):
        request=self.materialize_fixture('case-006')
        request['bindings']=[binding for binding in request['bindings'] if binding['record'] != dict(run_id='m4-observations',evidence_id='ev-000000000010')]
        result=self.analyze(request)
        self.assertNotIn('qos_class_condition',{item['code'] for item in result['findings']})
        self.assertIn('missing_qos_class',result['gaps'])

    def test_mtu_requires_explicit_l3_size_and_overhead(self):
        request=self.materialize_fixture('case-007')
        self.assertIn('mtu_scoped_failure',{item['code'] for item in self.analyze(request)['findings']})
        for evidence_id in ('ev-000000000003','ev-000000000006'):
            with self.subTest(missing=evidence_id):
                variant=copy.deepcopy(request)
                variant['bindings']=[binding for binding in variant['bindings'] if binding['record'] != dict(run_id='m4-observations',evidence_id=evidence_id)]
                result=self.analyze(variant)
                self.assertNotIn('mtu_scoped_failure',{item['code'] for item in result['findings']})
                self.assertIn('missing_mtu_evidence',result['gaps'])

    def test_ecmp_asymmetry_requires_both_matching_flow_facts(self):
        request=self.materialize_fixture('case-009')
        self.assertIn('ecmp_asymmetry',{item['code'] for item in self.analyze(request)['findings']})
        request['bindings']=[binding for binding in request['bindings'] if binding['record'] != dict(run_id='m4-observations',evidence_id='ev-000000000003')]
        result=self.analyze(request)
        self.assertNotIn('ecmp_asymmetry',{item['code'] for item in result['findings']})
        self.assertIn('missing_flow_scope',result['gaps'])

    def test_missing_route_prefix_blocks_route_correlation_not_observed_failure(self):
        request=self.materialize_fixture('case-002')
        request['bindings']=[binding for binding in request['bindings'] if binding['record'] != dict(run_id='m4-observations',evidence_id='ev-000000000002')]
        result=self.analyze(request)
        codes={item['code'] for item in result['findings']}
        self.assertNotIn('route_service_correlation',codes)
        self.assertIn('service_failure',codes)
        self.assertIn('missing_prefix_or_vrf',result['gaps'])

    def test_lsp_and_sr_states_are_neutral_and_cite_service_pass(self):
        rows=[self.row('lsp_state','down'),self.row('sr_policy_state','down'),self.row('service_operation','pass')]
        result=self.analyze(self.add_run(self.base(),'control1',rows))
        self.assertEqual(result['status'],'insufficient_evidence')
        for code in ('lsp_event','sr_policy_event'):
            finding=next(item for item in result['findings'] if item['code']==code)
            self.assertIn(dict(run_id='control1',evidence_id='ev-000000000003'),finding['counterevidence'])
            self.assertIsNone(finding['resource_id'])

    def test_interface_counters_are_neutral_and_require_no_reset(self):
        rows=[]
        for metric in ('interface_crc','interface_errors','interface_discards'):
            rows.extend([self.row(metric,100,unit='packets',denominator='packets',counter_semantics='cumulative',event_time='2026-01-01T00:06:00Z'),self.row(metric,120,unit='packets',denominator='packets',counter_semantics='cumulative',event_time='2026-01-01T00:08:00Z')])
        base=self.base()
        result=self.analyze(self.add_run(base,'counter1',rows))
        self.assertEqual(result['status'],'insufficient_evidence')
        self.assertEqual(sum(item['code']=='counter_increase' for item in result['findings']),3)
        wrapped=copy.deepcopy(rows)
        for row in wrapped: row['reset_state']='wrap'
        result=self.analyze(self.add_run(base,'counter2',wrapped))
        self.assertEqual(result['status'],'insufficient_evidence')
        self.assertIn('counter_reset',result['gaps'])
        self.assertNotIn('counter_increase',{item['code'] for item in result['findings']})
        unknown=[dict(row,counter_semantics='unknown',reset_state='unknown',sample_interval_seconds=None) for row in rows]
        result=self.analyze(self.add_run(base,'counter3',unknown))
        self.assertTrue({'unknown_counter_semantics','unknown_counter_reset_state','missing_sample_interval'}.issubset(result['gaps']))
        self.assertNotIn('counter_increase',{item['code'] for item in result['findings']})
        mismatched=[self.row('interface_crc',100,unit='packets',denominator='packets',counter_semantics='cumulative',event_time='2026-01-01T00:06:00Z'),self.row('interface_crc',120,unit='bytes',denominator='packets',counter_semantics='cumulative',event_time='2026-01-01T00:08:00Z')]
        result=self.analyze(self.add_run(base,'counter4',mismatched))
        self.assertIn('incompatible_counter_samples',result['gaps'])
        self.assertNotIn('counter_increase',{item['code'] for item in result['findings']})

    def test_public_transport_refs_are_accepted_by_existing_case_decision(self):
        request=self.add_run(self.base(),'decision1',[self.row('service_operation','fail')])
        result=self.analyze(request); finding=next(item for item in result['findings'] if item['code']=='service_failure')
        case=self.root/'case'; event_path=self.root/'case-event.json'
        def call(command,payload):
            event_path.write_text(json.dumps(payload))
            proc=subprocess.run([sys.executable,'-B',str(access_tests.CASE),command,'--case',str(case),'--input',str(event_path)],capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr); return json.loads(proc.stdout)
        state=call('create',dict(case_id='case1',event_id='create',actor='operator',occurred_at='2026-01-01T00:00:00Z',symptom='unavailable',business_impact='unknown',scope=self.helper.scope,verification_plan=self.helper.plan))
        for index,run in enumerate(request['runs']):
            state=call('import-run',dict(event_id='import'+str(index),actor='operator',occurred_at='2026-01-01T00:10:00Z',expected_revision=state['revision'],**run))
        state=call('decision',dict(event_id='decision',actor='operator',occurred_at='2026-01-01T00:10:00Z',expected_revision=state['revision'],observations=[finding['observation']],hypotheses=[finding['hypothesis']],support=finding['support'],counterevidence=finding['counterevidence'],confidence='low',limitations=finding['limitations'],next_test=None,expected_support=None,expected_counterevidence=None,changed_condition=None))
        self.assertEqual(state['decisions'][-1]['support'],finding['support'])

if __name__ == '__main__': unittest.main()
