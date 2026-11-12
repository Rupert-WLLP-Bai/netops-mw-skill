from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone
from unittest import mock

CLI = Path(__file__).resolve().parents[1] / 'skills/netops-incident/scripts/case.py'
SCOPE = {key: None for key in ('vantage', 'identity', 'operation', 'target', 'protocol', 'address_family', 'proxy', 'workload', 'original_window')}
PLAN = {key: None for key in ('criterion', 'unit', 'window_seconds', 'cadence_seconds', 'maximum_gap_seconds', 'freshness_seconds', 'minimum_checks', 'minimum_coverage', 'owner', 'agreement_ref')}

class CaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.case = self.root / 'case'
        self.create = dict(case_id='case1', actor='operator', event_id='create1', occurred_at='2026-01-01T00:00:00Z', symptom='unavailable', business_impact='cannot work', scope=SCOPE, verification_plan=PLAN)

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, command, data=None, ok=True):
        args = [sys.executable, '-B', str(CLI), command, '--case', str(self.case)]
        if data is not None:
            path = self.root / 'input.json'
            path.write_text(json.dumps(data), encoding='utf-8')
            args += ['--input', str(path)]
        result = subprocess.run(args, capture_output=True, text=True)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def event(self, event_id, revision):
        return dict(event_id=event_id, actor='operator', occurred_at='2026-01-01T00:01:00Z', expected_revision=revision)

    def test_create_get_and_permissions(self):
        created = self.call('create', self.create)
        self.assertEqual(created['revision'], 1)
        self.assertEqual(self.call('get'), created)
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(self.case.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((self.case / 'case.sqlite3').stat().st_mode), 0o600)

    def test_scope_update_from_null_and_policy_revision(self):
        before = self.call('create', self.create)
        scope = dict(SCOPE, vantage='branch')
        event = dict(self.event('scope1', 1), scope=scope, verification_plan=PLAN, reason='known vantage')
        after = self.call('scope', event)
        self.assertEqual(after['scope']['vantage'], 'branch')
        self.assertEqual(after['policy_revision'], before['policy_revision'] + 1)
        self.assertNotEqual(after['policy_hash'], before['policy_hash'])
        self.assertEqual(after['events'][-1]['prior_scope'], SCOPE)
        self.assertEqual(self.call('create', self.create), before)
        self.assertEqual(self.call('scope', event), after)
        self.assertEqual(self.call('get'), after)

    def test_stale_and_conflicting_events(self):
        self.call('create', self.create)
        event = dict(self.event('scope1', 1), scope=dict(SCOPE, vantage='branch'), verification_plan=PLAN, reason='known')
        state = self.call('scope', event)
        conflict = dict(event, reason='changed')
        self.call('scope', conflict, ok=False)
        stale = dict(event, event_id='scope2')
        self.call('scope', stale, ok=False)
        self.assertEqual(self.call('get'), state)

    def test_interrupted_transaction_is_atomic(self):
        before = self.call('create', self.create)
        db = sqlite3.connect(self.case / 'case.sqlite3')
        db.execute('BEGIN IMMEDIATE')
        db.execute("UPDATE state SET snapshot = '{}' WHERE id = 1")
        db.close()
        self.assertEqual(self.call('get'), before)

    def sample_run(self, run_id):
        run = self.root / run_id
        run.mkdir()
        evidence = {'id': 'E001', 'started_at_utc': '2026-01-01T00:00:01Z', 'artifacts': []}
        diagnosis = {'status': 'fault_observed', 'evidence_ids': ['E001'], 'counterevidence': []}
        (run / 'evidence.jsonl').write_text(json.dumps(evidence) + '\n')
        (run / 'diagnosis.json').write_text(json.dumps(diagnosis))
        (run / 'report.md').write_text('Scoped report')
        hashes = {name: hashlib.sha256((run / name).read_bytes()).hexdigest() for name in ('evidence.jsonl', 'diagnosis.json', 'report.md')}
        manifest = {'run_id': run_id, 'run_window': {'started_at_utc': '2026-01-01T00:00:00Z', 'ended_at_utc': '2026-01-01T00:00:02Z'}, 'artifact_hashes': hashes, 'validation_errors': {'evidence': [], 'diagnosis': []}, 'scope': {'target': 'example'}}
        (run / 'manifest.json').write_text(json.dumps(manifest))
        hashes['manifest.json'] = hashlib.sha256((run / 'manifest.json').read_bytes()).hexdigest()
        return run, hashes

    def test_import_qualified_ids_and_diagnosis(self):
        self.call('create', self.create)
        for n in (1, 2):
            run, hashes = self.sample_run('run' + str(n))
            state = self.call('import-run', dict(self.event('import' + str(n), n), run_dir=str(run), run_id=run.name, expected_summary_hashes=hashes))
        self.assertEqual([item['evidence_ids'] for item in state['imports']], [['E001'], ['E001']])
        self.assertEqual(state['imports'][0]['diagnosis']['status'], 'fault_observed')
        decision = dict(self.event('decision1', 3), observations=['fact'], hypotheses=['hypothesis'], support=[{'run_id':'run1','evidence_id':'E001'}, {'run_id':'run2','evidence_id':'E001'}], counterevidence=[], confidence='low', limitations=['scope'], next_test=None, expected_support=None, expected_counterevidence=None, changed_condition=None)
        self.assertEqual(len(self.call('decision', decision)['decisions'][0]['support']), 2)

    def test_import_rejects_escape_symlink_and_changed_hash(self):
        before = self.call('create', self.create)
        run, hashes = self.sample_run('run1')
        event = dict(self.event('import1', 1), run_dir=str(run), run_id=run.name, expected_summary_hashes=hashes)
        (run / 'report.md').write_text('changed')
        self.call('import-run', event, ok=False)
        (run / 'report.md').unlink()
        (run / 'report.md').symlink_to(self.root / 'outside')
        self.call('import-run', event, ok=False)
        self.assertEqual(self.call('get'), before)
        self.assertEqual(list((self.case / 'imports').iterdir()), [])

    def test_decision_requires_existing_refs(self):
        before = self.call('create', self.create)
        decision = dict(self.event('decision1', 1), observations=[], hypotheses=[], support=['E001'], counterevidence=[], confidence='unknown', limitations=[], next_test=None, expected_support=None, expected_counterevidence=None, changed_condition=None)
        self.call('decision', decision, ok=False)
        decision['support'] = [{'run_id':'missing','evidence_id':'E001'}]
        self.call('decision', decision, ok=False)
        self.assertEqual(self.call('get'), before)

    def prepare_run(self, budget=None):
        create = dict(self.create, scope=dict(SCOPE, vantage='branch', target='https://example.test'))
        if budget is not None:
            create['budget'] = budget
        self.call('create', create)
        decision = dict(self.event('decision1', 1), observations=['symptom'], hypotheses=['cause'], support=[], counterevidence=[], confidence='low', limitations=[], next_test='compare capture', expected_support='indicator', expected_counterevidence='absence', changed_condition=None)
        self.call('decision', decision)
        marker = self.root / 'spawned'
        provider = self.root / 'diagnose.py'
        event = dict(self.event('run1', 2), purpose='investigation', provider_cli=str(provider), mode='offline_pcap', pcap=str(self.root/'capture'), out=str(self.root/'out'), authorization_ref='approval', decision_event_id='decision1', actual_vantage='branch', vantage_source='operator')
        (self.root/'capture').write_bytes(b'capture')
        return provider, marker, event

    def test_reserve_before_spawn_and_budget_exhaustion(self):
        budget = dict(rounds=1, active_seconds=25, http_requests=6, concurrency=1, verification_reserve_rounds=1, verification_reserve_seconds=25, verification_reserve_requests=6)
        provider, marker, event = self.prepare_run(budget)
        provider.write_text('from pathlib import Path\nPath(%r).write_text("spawned")\nprint("internet-access-triage 0.1.0")\n' % str(marker))
        result = self.call('run', event, ok=False)
        self.assertIn('insufficient budget', result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(self.call('get')['budget']['rounds'], 1)

    def test_run_reserves_before_version_and_retry_does_not_spawn(self):
        provider, marker, event = self.prepare_run()
        provider.write_text('from pathlib import Path\nimport sys\np=Path(%r)\np.write_text((p.read_text() if p.exists() else "") + "x")\nprint("internet-access-triage 0.1.0" if "--version" in sys.argv else "no output")\n' % str(marker))
        result = self.call('run', event)
        self.assertIn('no complete output', result['stopped_reason'])
        self.assertEqual(marker.read_text(), 'xx')
        after = self.call('get')
        self.assertEqual(after['budget']['rounds'], 2)
        self.assertEqual(after['budget']['active_seconds'], 50)
        self.call('run', event)
        self.assertEqual(marker.read_text(), 'xx')
        self.assertEqual(self.call('get'), after)

    def test_cancel_reaps_managed_child(self):
        provider, marker, event = self.prepare_run()
        provider.write_text('from pathlib import Path\nimport sys,time\nif "--version" in sys.argv: print("internet-access-triage 0.1.0"); sys.exit()\nPath(%r).write_text("started")\ntime.sleep(30)\n' % str(marker))
        event_path = self.root/'run.json'
        event_path.write_text(json.dumps(event))
        proc = subprocess.Popen([sys.executable, '-B', str(CLI), 'run', '--case', str(self.case), '--input', str(event_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(.05)
            self.assertTrue(marker.exists())
            snapshot = self.call('get')
            self.assertEqual(snapshot['operations'][0]['status'], 'in_flight')
            self.call('cancel', dict(self.event('cancel1', snapshot['revision']), reason='operator stopped'))
            stdout, stderr = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 0, stderr)
            self.assertEqual(json.loads(stdout)['stopped_reason'], 'cancelled')
            final = self.call('get')
            self.assertEqual(final['status'], 'cancelled')
            self.assertEqual(final['operations'][0]['status'], 'settled')
            self.assertEqual(final['budget']['rounds'], 2)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_crash_charges_reservation_and_blocks_restart(self):
        provider, marker, event = self.prepare_run()
        provider.write_text('from pathlib import Path\nimport time\nPath(%r).write_text("started")\ntime.sleep(1)\nprint("internet-access-triage 0.1.0")\n' % str(marker))
        input_path = self.root/'run.json'
        input_path.write_text(json.dumps(event))
        proc = subprocess.Popen([sys.executable, '-B', str(CLI), 'run', '--case', str(self.case), '--input', str(input_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(.05)
            self.assertTrue(marker.exists())
            proc.kill()
            proc.wait()
            state = self.call('get')
            self.assertEqual(state['budget']['rounds'], 2)
            self.assertEqual(state['operations'][0]['status'], 'in_flight')
            retry = dict(event, event_id='run2', expected_revision=state['revision'], out=str(self.root/'out2'))
            result = self.call('run', retry, ok=False)
            self.assertIn('reconciliation', result.stderr)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_explicit_budget_increase_requires_authorization(self):
        self.call('create', self.create)
        event = dict(self.event('increase1', 1), budget_increase={'rounds': 1, 'active_seconds': 25, 'http_requests': 6}, reason='new evidence')
        self.call('transition', event, ok=False)
        event['authorization_ref'] = 'approval'
        after = self.call('transition', event)
        self.assertEqual(after['budget']['rounds'], 4)
        self.assertEqual(after['budget']['active_seconds'], 100)

    def test_standalone_manual_import_costs_no_round(self):
        before = self.call('create', self.create)
        run, hashes = self.sample_run('run1')
        after = self.call('import-run', dict(self.event('import1', 1), run_dir=str(run), run_id=run.name, expected_summary_hashes=hashes))
        self.assertEqual(after['budget'], before['budget'])

    def test_cancel_and_reopen_preserve_budget(self):
        self.call('create', self.create)
        cancelled = self.call('cancel', dict(self.event('cancel1', 1), reason='stop'))
        self.assertEqual(cancelled['status'], 'cancelled')
        reopened = self.call('reopen', dict(self.event('reopen1', 2), reason='resume'))
        self.assertEqual(reopened['status'], 'intake')
        self.assertEqual(reopened['budget'], cancelled['budget'])
        self.assertNotEqual(reopened['episode_id'], cancelled['episode_id'])

    def ready_case(self):
        scope = dict(SCOPE, vantage='branch', identity='user', operation='submit order', target='https://example.test', protocol='https', address_family='IPv4', proxy='direct', workload='one order', original_window='incident window')
        plan = dict(criterion={'operator':'gte', 'value':1}, unit='successes', window_seconds=1, cadence_seconds=1, maximum_gap_seconds=2, freshness_seconds=5, minimum_checks=1, minimum_coverage=0.5, owner='service owner', agreement_ref='agreement')
        state = self.call('create', dict(self.create, scope=scope, verification_plan=plan))
        state = self.call('transition', dict(self.event('investigate', state['revision']), status='investigating', reason='investigate'))
        return state

    def start_window(self, state):
        state = self.call('transition', dict(self.event('verify', state['revision']), status='verifying', reason='observed recovery'))
        return self.call('verification', dict(self.event('start', state['revision']), kind='start', reason='initial attempt'))

    def check_data(self, state, outcome, value, event_id='check1'):
        window = state['verification_windows'][-1]
        artifact = self.root / (event_id + '.txt')
        artifact.write_text('independent local observation')
        observed = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
        return dict(self.event(event_id, state['revision']), kind='check', window_id=window['window_id'], episode_id=window['episode_id'], policy_revision=window['policy_revision'], policy_hash=window['policy_hash'], window_start=window['window_start'], window_end=window['window_end'], check_id=event_id, scope=state['scope'], observed_at=observed, collected_at=observed, source='observer', source_actor='observer', value=value, unit='successes', outcome=outcome, raw_reference={'root':str(self.root), 'path':artifact.name, 'sha256':hashlib.sha256(artifact.read_bytes()).hexdigest()}, provenance='operator supplied record', trust_grade='independent_observation', differences=[])

    def test_spontaneous_recovery_with_complete_window(self):
        state = self.start_window(self.ready_case())
        check = self.check_data(state, 'pass', 1)
        state = self.call('verification', check)
        state = self.call('transition', dict(self.event('stabilize', state['revision']), status='stabilizing', reason='check passed'))
        self.call('transition', dict(self.event('tooearly', state['revision']), status='closed_recovered', reason='done'), ok=False)
        time.sleep(1.1)
        state = self.call('transition', dict(self.event('closed', state['revision']), status='closed_recovered', reason='window complete'))
        self.assertEqual(state['status'], 'closed_recovered')

    def test_failed_check_and_recurrence_do_not_close(self):
        state = self.start_window(self.ready_case())
        state = self.call('verification', self.check_data(state, 'fail', 0))
        state = self.call('transition', dict(self.event('stabilize', state['revision']), status='stabilizing', reason='observe'))
        time.sleep(1.05)
        self.call('transition', dict(self.event('closed', state['revision']), status='closed_recovered', reason='done'), ok=False)
        self.assertEqual(self.call('get')['status'], 'stabilizing')

    def test_missing_or_changed_check_artifact_rejected(self):
        state = self.start_window(self.ready_case())
        check = self.check_data(state, 'pass', 1)
        (self.root/'check1.txt').write_text('changed')
        self.call('verification', check, ok=False)
        self.assertEqual(self.call('get'), state)

    def test_unknown_action_requires_reconciliation(self):
        state = self.ready_case()
        state = self.call('transition', dict(self.event('await', state['revision']), status='awaiting_action', reason='owner reviewing'))
        action = dict(self.event('action1', state['revision']), owner='operator', intended_change='inspect proxy', affected_scope=state['scope'], preconditions='approved', authorization_ref='approval', expected_check='submit order', rollback_trigger='failure', rollback_owner='operator', correlation_key='change1', action_time='2026-01-01T00:00:00Z', outcome='unknown', evidence=[])
        state = self.call('action', action)
        self.assertEqual(state['status'], 'action_outcome_unknown')
        self.call('transition', dict(self.event('verify', state['revision']), status='verifying', reason='maybe done'), ok=False)
        action['event_id'] = 'action2'
        action['expected_revision'] = state['revision']
        self.call('action', action, ok=False)

    def test_invalid_numeric_policy_and_timestamps(self):
        bad = dict(PLAN, criterion={'operator':'eq', 'value':True})
        self.call('create', dict(self.create, verification_plan=bad), ok=False)
        bad = dict(PLAN, minimum_coverage=2)
        self.call('create', dict(self.create, verification_plan=bad), ok=False)
        self.call('create', dict(self.create, occurred_at='2026-99-01T00:00:00Z'), ok=False)

    def test_unavailable_original_vantage_stays_unresolved(self):
        self.call('create', self.create)
        state = self.call('transition', dict(self.event('investigate', 1), status='investigating', reason='investigate'))
        self.call('transition', dict(self.event('verify', state['revision']), status='verifying', reason='attempt'), ok=False)
        self.assertEqual(self.call('get')['status'], 'investigating')

    def test_wrong_policy_units_time_and_criterion_are_rejected(self):
        state = self.start_window(self.ready_case())
        check = self.check_data(state, 'pass', 1)
        for updates in ({'policy_revision': 999}, {'unit':'ms'}, {'outcome':'fail'}, {'value':True}, {'observed_at':'2999-01-01T00:00:00Z', 'collected_at':'2999-01-01T00:00:00Z'}):
            with self.subTest(updates=updates):
                self.call('verification', dict(check, **updates), ok=False)
                self.assertEqual(self.call('get'), state)
        state = self.call('scope', dict(self.event('scope1', state['revision']), scope=state['scope'], verification_plan=dict(state['verification_plan'], minimum_coverage=.9), reason='updated agreement'))
        self.call('verification', dict(check, expected_revision=state['revision']), ok=False)

    def test_window_end_failure_and_stale_coverage(self):
        sys.path.insert(0, str(CLI.parent))
        from case_runtime import recovery
        state = self.start_window(self.ready_case())
        window = state['verification_windows'][-1]
        start = datetime.fromisoformat(window['window_start'].replace('Z','+00:00'))
        end = datetime.fromisoformat(window['window_end'].replace('Z','+00:00'))
        pass_time = start + timedelta(milliseconds=100)
        check = self.check_data(state, 'pass', 1)
        check['observed_at'] = check['collected_at'] = pass_time.isoformat().replace('+00:00','Z')
        with mock.patch.object(recovery, 'clock', return_value=pass_time):
            state = recovery.record_verification(self.case, check)
        self.assertEqual(recovery.recovery_gaps(state, now=end, case_dir=self.case), [])
        self.assertIn('last observation is stale', recovery.recovery_gaps(state, now=end + timedelta(seconds=6), case_dir=self.case))
        failure = self.check_data(state, 'fail', 0, 'check2')
        failure['observed_at'] = failure['collected_at'] = end.isoformat().replace('+00:00','Z')
        with mock.patch.object(recovery, 'clock', return_value=end):
            state = recovery.record_verification(self.case, failure)
        self.assertIn('failed check or recurrence', recovery.recovery_gaps(state, now=end, case_dir=self.case))
        stored = self.case / state['checks'][0]['stored_artifact']
        stored.write_text('tampered')
        self.assertIn('stored check artifact hash mismatch', recovery.recovery_gaps(state, now=end, case_dir=self.case))

    def test_reconciliation_requires_authority(self):
        state = self.ready_case()
        state = self.call('transition', dict(self.event('await', state['revision']), status='awaiting_action', reason='owner reviewing'))
        action = dict(self.event('action1', state['revision']), owner='operator', intended_change='inspect proxy', affected_scope=state['scope'], preconditions='approved', authorization_ref='approval', expected_check='submit order', rollback_trigger='failure', rollback_owner='operator', correlation_key='change1', action_time='2026-01-01T00:00:00Z', outcome='unknown', evidence=[])
        state = self.call('action', action)
        reconciliation = {'owner':'operator','evidence':'owner confirmation','authorization_ref':'authority','correlation_key':'change1','outcome':'completed'}
        state = self.call('transition', dict(self.event('verify', state['revision']), status='verifying', reason='reconciled', reconciliation=reconciliation))
        self.assertEqual(state['status'], 'verifying')
        self.assertEqual(state['actions'][0]['reconciliation'], reconciliation)

    def test_later_recurrence_and_gap_block_recovery(self):
        sys.path.insert(0, str(CLI.parent))
        from case_runtime import recovery
        state = self.start_window(self.ready_case())
        window = state['verification_windows'][-1]
        start = datetime.fromisoformat(window['window_start'].replace('Z','+00:00'))
        end = datetime.fromisoformat(window['window_end'].replace('Z','+00:00'))
        state['verification_plan']['maximum_gap_seconds'] = .1
        check = self.check_data(state, 'pass', 1)
        t = start + timedelta(milliseconds=500)
        check['observed_at'] = check['collected_at'] = t.isoformat().replace('+00:00','Z')
        with mock.patch.object(recovery, 'clock', return_value=t):
            state = recovery.record_verification(self.case, check)
        state['verification_plan']['maximum_gap_seconds'] = .1
        self.assertIn('observation gap exceeds maximum', recovery.recovery_gaps(state, now=end, case_dir=self.case))
        failure = self.check_data(state, 'fail', 0, 'recurrence')
        t = end + timedelta(milliseconds=100)
        failure['observed_at'] = failure['collected_at'] = t.isoformat().replace('+00:00','Z')
        with mock.patch.object(recovery, 'clock', return_value=t):
            state = recovery.record_verification(self.case, failure)
        self.assertIn('failed check or recurrence', recovery.recovery_gaps(state, now=t, case_dir=self.case))


    def test_database_context_closes_connection(self):
        self.call('create', self.create)
        sys.path.insert(0, str(CLI.parent))
        from case_runtime.store import connect
        with connect(self.case) as conn:
            conn.execute('SELECT 1')
        with self.assertRaises(sqlite3.ProgrammingError):
            conn.execute('SELECT 1')


    def test_live_run_requires_explicit_matching_decision_authorization(self):
        provider, marker, event = self.prepare_run()
        provider.write_text('from pathlib import Path\nPath(%r).write_text("spawned")\nprint("internet-access-triage 0.1.0")\n' % str(marker))
        event.update(mode='live', target='https://example.test', symptom='service unavailable')
        self.call('run', event, ok=False)
        self.assertFalse(marker.exists())
        self.assertEqual(self.call('get')['budget']['rounds'], 3)


    def test_reopened_unknown_action_can_be_reconciled(self):
        state = self.ready_case()
        state = self.call('transition', dict(self.event('await', state['revision']), status='awaiting_action', reason='owner reviewing'))
        action = dict(self.event('action1', state['revision']), owner='operator', intended_change='inspect proxy', affected_scope=state['scope'], preconditions='approved', authorization_ref='approval', expected_check='submit order', rollback_trigger='failure', rollback_owner='operator', correlation_key='change1', action_time='2026-01-01T00:00:00Z', outcome='unknown', evidence=[])
        state = self.call('action', action)
        state = self.call('cancel', dict(self.event('cancel1', state['revision']), reason='stop'))
        state = self.call('reopen', dict(self.event('reopen1', state['revision']), reason='resume'))
        reconciliation = {'owner':'operator','evidence':'owner confirmation','authorization_ref':'authority','correlation_key':'change1','outcome':'completed'}
        state = self.call('transition', dict(self.event('reconcile', state['revision']), reason='owner confirmed', action_reconciliation=reconciliation))
        self.assertEqual(state['actions'][0]['reconciliation'], reconciliation)
        self.assertEqual(state['status'], 'intake')


    def test_import_never_overwrites_existing_destination(self):
        before = self.call('create', self.create)
        run, hashes = self.sample_run('run1')
        orphan = self.case / 'imports' / 'run1'
        orphan.mkdir()
        (orphan / 'keep').write_text('preserve')
        self.call('import-run', dict(self.event('import1', 1), run_dir=str(run), run_id=run.name, expected_summary_hashes=hashes), ok=False)
        self.assertEqual((orphan/'keep').read_text(), 'preserve')
        self.assertEqual(self.call('get'), before)


    def test_cancel_imports_complete_output_and_preserves_cancelled_status(self):
        provider, marker, event = self.prepare_run()
        source, hashes = self.sample_run('run-output')
        provider.write_text('from pathlib import Path\nimport shutil,sys,time\nif "--version" in sys.argv: print("internet-access-triage 0.1.0"); sys.exit()\nout=sys.argv[sys.argv.index("--out")+1]\nshutil.copytree(%r,out)\nPath(%r).write_text("complete")\ntime.sleep(30)\n' % (str(source), str(marker)))
        input_path = self.root/'run.json'
        input_path.write_text(json.dumps(event))
        proc = subprocess.Popen([sys.executable, '-B', str(CLI), 'run', '--case', str(self.case), '--input', str(input_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(.05)
            self.assertTrue(marker.exists())
            state = self.call('get')
            self.call('cancel', dict(self.event('cancel1', state['revision']), reason='operator stopped'))
            stdout, stderr = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 0, stderr)
            result = json.loads(stdout)
            self.assertEqual(result['accepted_run_id'], 'run-output')
            self.assertEqual(result['stopped_reason'], 'cancelled')
            state = self.call('get')
            self.assertEqual(state['status'], 'cancelled')
            self.assertEqual(len(state['imports']), 1)
            self.assertEqual(state['imports'][0]['summary_hashes'], hashes)
            self.assertEqual(state['operations'][0]['status'], 'settled')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


if __name__ == '__main__':
    unittest.main()
