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

if __name__ == '__main__':
    unittest.main()
