from __future__ import annotations

import copy
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
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

if __name__ == '__main__':
    unittest.main()
