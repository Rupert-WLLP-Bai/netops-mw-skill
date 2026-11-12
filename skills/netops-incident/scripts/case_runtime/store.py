"""Durable local cases and transactional event application."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import uuid
from datetime import datetime
from pathlib import Path

TOKEN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
SCOPE_FIELDS = ('vantage', 'identity', 'operation', 'target', 'protocol', 'address_family', 'proxy', 'workload', 'original_window')
PLAN_FIELDS = ('criterion', 'unit', 'window_seconds', 'cadence_seconds', 'maximum_gap_seconds', 'freshness_seconds', 'minimum_checks', 'minimum_coverage', 'owner', 'agreement_ref')
DEFAULT_BUDGET = dict(rounds=3, active_seconds=75, http_requests=18, concurrency=1, verification_reserve_rounds=1, verification_reserve_seconds=25, verification_reserve_requests=6)
TERMINAL = {'closed_recovered', 'closed_unresolved', 'cancelled'}

class CaseError(ValueError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def token(value, label):
    if not isinstance(value, str) or not TOKEN.fullmatch(value):
        raise CaseError('invalid ' + label)
    return value

def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z', value):
        raise CaseError('timestamp must be UTC RFC 3339')
    try:
        return datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError as exc:
        raise CaseError('invalid timestamp') from exc

def nonempty(value, label):
    if not isinstance(value, str) or not value.strip():
        raise CaseError('invalid ' + label)
    return value

def number(value, label, minimum=None, integer=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or (integer and not isinstance(value, int)) or (minimum is not None and value < minimum):
        raise CaseError('invalid ' + label)
    return value

def validate_policy(scope, plan):
    if not isinstance(scope, dict) or set(scope) != set(SCOPE_FIELDS) or not isinstance(plan, dict) or set(plan) != set(PLAN_FIELDS):
        raise CaseError('scope and verification plan must include all fields')
    for value in scope.values():
        if value is not None:
            nonempty(value, 'scope value')
    criterion = plan['criterion']
    if criterion is not None:
        if not isinstance(criterion, dict) or set(criterion) != {'operator', 'value'} or criterion['operator'] not in ('eq', 'gte', 'lte'):
            raise CaseError('invalid criterion')
        number(criterion['value'], 'criterion value')
    for key in ('unit', 'owner', 'agreement_ref'):
        if plan[key] is not None:
            nonempty(plan[key], key)
    for key in ('window_seconds', 'cadence_seconds', 'maximum_gap_seconds', 'freshness_seconds'):
        if plan[key] is not None:
            number(plan[key], key, 0)
            if plan[key] == 0:
                raise CaseError('duration must be positive')
    if plan['minimum_checks'] is not None:
        number(plan['minimum_checks'], 'minimum_checks', 1, integer=True)
    if plan['minimum_coverage'] is not None:
        number(plan['minimum_coverage'], 'minimum_coverage', 0)
        if not 0 < plan['minimum_coverage'] <= 1:
            raise CaseError('invalid minimum_coverage')

def validate_budget(budget):
    if not isinstance(budget, dict) or set(budget) != set(DEFAULT_BUDGET):
        raise CaseError('invalid budget fields')
    for key, value in budget.items():
        number(value, key, 0, integer=True)
    if budget['concurrency'] != 1:
        raise CaseError('only concurrency 1 is supported')
    for reserve, total in (('verification_reserve_rounds', 'rounds'), ('verification_reserve_seconds', 'active_seconds'), ('verification_reserve_requests', 'http_requests')):
        if budget[reserve] > budget[total]:
            raise CaseError('reserve exceeds budget')

def validate_event(data, create=False):
    if not isinstance(data, dict):
        raise CaseError('input must be an object')
    token(data.get('event_id'), 'event_id')
    nonempty(data.get('actor'), 'actor')
    timestamp(data.get('occurred_at'))
    if not create:
        number(data.get('expected_revision'), 'expected_revision', 1, integer=True)

def _check_path(case_dir):
    case_dir = Path(case_dir)
    if case_dir.is_symlink() or not case_dir.is_dir():
        raise CaseError('case directory must be a real directory')
    for name in ('case.sqlite3', 'case.sqlite3-journal', 'case.sqlite3-wal', 'case.sqlite3-shm'):
        path = case_dir / name
        if path.is_symlink() or (path.exists() and not stat.S_ISREG(path.stat().st_mode)):
            raise CaseError('unsafe case database path')
    if not (case_dir / 'case.sqlite3').is_file():
        raise CaseError('case database missing')
    imports = case_dir / 'imports'
    if imports.is_symlink() or not imports.is_dir():
        raise CaseError('unsafe imports directory')
    return case_dir

def connect(case_dir):
    case_dir = _check_path(case_dir)
    conn = sqlite3.connect(str(case_dir / 'case.sqlite3'), timeout=5, isolation_level=None)
    conn.execute('PRAGMA journal_mode=DELETE')
    conn.execute('PRAGMA synchronous=FULL')
    conn.execute('PRAGMA busy_timeout=5000')
    return conn

def get_case(case_dir):
    with connect(case_dir) as conn:
        row = conn.execute('SELECT snapshot FROM state WHERE id=1').fetchone()
        if row is None:
            raise CaseError('invalid case')
        return json.loads(row[0])

def create_case(case_dir, data):
    validate_event(data, create=True)
    token(data.get('case_id'), 'case_id')
    nonempty(data.get('symptom'), 'symptom')
    nonempty(data.get('business_impact'), 'business_impact')
    validate_policy(data.get('scope'), data.get('verification_plan'))
    budget = data.get('budget', DEFAULT_BUDGET)
    validate_budget(budget)
    case_dir = Path(case_dir)
    if case_dir.exists() or case_dir.is_symlink():
        with connect(case_dir) as conn:
            row = conn.execute('SELECT kind, payload, result FROM events WHERE event_id=?', (data['event_id'],)).fetchone()
            if row and row[0] == 'create' and row[1] == canonical(data):
                return json.loads(row[2])
        raise CaseError('case directory already exists')
    case_dir.mkdir(mode=0o700)
    try:
        (case_dir / 'imports').mkdir(mode=0o700)
        fd = os.open(str(case_dir / 'case.sqlite3'), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        event = {'event_id': data['event_id'], 'kind': 'create', 'actor': data['actor'], 'occurred_at': data['occurred_at'], 'revision': 1}
        state = dict(schema_version=1, case_id=data['case_id'], episode_id=uuid.uuid4().hex, revision=1, status='intake', symptom=data['symptom'], business_impact=data['business_impact'], scope=data['scope'], verification_plan=data['verification_plan'], policy_revision=1, policy_hash=digest([data['scope'], data['verification_plan']]), budget=dict(budget), events=[event], imports=[], decisions=[], actions=[], verification_windows=[], checks=[], operations=[])
        with connect(case_dir) as conn:
            conn.execute('CREATE TABLE state (id INTEGER PRIMARY KEY CHECK (id=1), snapshot TEXT NOT NULL)')
            conn.execute('CREATE TABLE events (event_id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL, result TEXT NOT NULL)')
            conn.execute('BEGIN IMMEDIATE')
            conn.execute('INSERT INTO state VALUES (1, ?)', (canonical(state),))
            conn.execute('INSERT INTO events VALUES (?, ?, ?, ?)', (data['event_id'], 'create', canonical(data), canonical(state)))
            conn.commit()
        return state
    except Exception:
        import shutil
        shutil.rmtree(case_dir)
        raise

def transact(case_dir, data, kind, mutate):
    validate_event(data)
    payload = canonical(data)
    with connect(case_dir) as conn:
        conn.execute('BEGIN IMMEDIATE')
        try:
            old = conn.execute('SELECT kind, payload, result FROM events WHERE event_id=?', (data['event_id'],)).fetchone()
            if old:
                if old[0] != kind or old[1] != payload:
                    raise CaseError('conflicting event ID')
                conn.rollback()
                return json.loads(old[2])
            state = json.loads(conn.execute('SELECT snapshot FROM state WHERE id=1').fetchone()[0])
            if state['revision'] != data['expected_revision']:
                raise CaseError('stale revision')
            detail = mutate(state, conn) or {}
            state['revision'] += 1
            event = dict(event_id=data['event_id'], kind=kind, actor=data['actor'], occurred_at=data['occurred_at'], revision=state['revision'])
            event.update(detail)
            state['events'].append(event)
            result = canonical(state)
            conn.execute('UPDATE state SET snapshot=? WHERE id=1', (result,))
            conn.execute('INSERT INTO events VALUES (?, ?, ?, ?)', (data['event_id'], kind, payload, result))
            conn.commit()
            return state
        except Exception:
            conn.rollback()
            raise

def update_scope(case_dir, data):
    def change(state, conn):
        if state['status'] in TERMINAL:
            raise CaseError('reopen terminal case before updating scope')
        validate_policy(data.get('scope'), data.get('verification_plan'))
        nonempty(data.get('reason'), 'reason')
        old_scope, old_plan = state['scope'], state['verification_plan']
        if (old_scope, old_plan) != (data['scope'], data['verification_plan']):
            state['scope'], state['verification_plan'] = data['scope'], data['verification_plan']
            state['policy_revision'] += 1
            state['policy_hash'] = digest([state['scope'], state['verification_plan']])
        return {'reason': data['reason'], 'prior_scope': old_scope, 'prior_verification_plan': old_plan}
    return transact(case_dir, data, 'scope', change)

def apply_event(case_dir, data, kind):
    if kind == 'scope':
        return update_scope(case_dir, data)
    raise CaseError('unsupported event')
