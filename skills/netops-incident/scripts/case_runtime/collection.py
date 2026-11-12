"""Reserve finite collection budgets and supervise explicitly selected providers."""
from __future__ import annotations
import hashlib
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from .evidence import SUMMARIES, import_run, read_confined
from .store import CaseError, TERMINAL, connect, get_case, nonempty, token, transact


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

def cancel_case(case_dir, data):
    def change(state, conn):
        if state['status'] in TERMINAL:
            raise CaseError('case already terminal')
        nonempty(data.get('reason'), 'reason')
        state['status'] = 'cancelled'
        return {'reason': data['reason']}
    return transact(case_dir, data, 'cancel', change)

def reopen_case(case_dir, data):
    def change(state, conn):
        if state['status'] not in TERMINAL:
            raise CaseError('only terminal cases can reopen')
        nonempty(data.get('reason'), 'reason')
        previous = state['episode_id']
        state['episode_id'] = uuid.uuid4().hex
        state['status'] = 'intake'
        return {'reason': data['reason'], 'prior_episode_id': previous}
    return transact(case_dir, data, 'reopen', change)

def preflight(state, data):
    if state['status'] in TERMINAL:
        raise CaseError('case is terminal')
    if any(op['status'] == 'in_flight' for op in state['operations']):
        raise CaseError('in-flight operation requires reconciliation')
    purpose = data.get('purpose')
    if purpose not in ('investigation', 'verification'):
        raise CaseError('invalid purpose')
    provider = Path(nonempty(data.get('provider_cli'), 'provider_cli'))
    if not provider.is_absolute() or provider.is_symlink() or not provider.is_file() or provider.name != 'diagnose.py':
        raise CaseError('provider must be a trusted absolute diagnose.py file')
    out = Path(nonempty(data.get('out'), 'out'))
    if not out.is_absolute() or out.exists() or out.is_symlink() or not out.parent.is_dir() or out.parent.is_symlink():
        raise CaseError('output must be a new absolute directory')
    nonempty(data.get('authorization_ref'), 'authorization_ref')
    vantage = nonempty(data.get('actual_vantage'), 'actual_vantage')
    nonempty(data.get('vantage_source'), 'vantage_source')
    if not state['scope']['vantage'] or vantage != state['scope']['vantage']:
        raise CaseError('vantage does not match case scope')
    decision = next((d for d in state['decisions'] if d['event_id'] == data.get('decision_event_id')), None)
    if not decision or not decision.get('next_test') or decision.get('scope') != state['scope']:
        raise CaseError('current authorized decision required')
    mode = data.get('mode')
    if mode == 'live':
        target = nonempty(data.get('target'), 'target')
        parts = urlsplit(target)
        if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.fragment or target != state['scope']['target']:
            raise CaseError('live target must match authorized HTTPS scope')
        nonempty(data.get('symptom'), 'symptom')
        args = ['--url', target, '--symptom', data['symptom'], '--out', str(out)]
        requests = 6
    elif mode == 'offline_pcap':
        pcap = Path(nonempty(data.get('pcap'), 'pcap'))
        if not pcap.is_absolute() or pcap.is_symlink() or not pcap.is_file():
            raise CaseError('capture must be an existing local file')
        args = ['--pcap', str(pcap), '--out', str(out)]
        requests = 0
    else:
        raise CaseError('invalid mode')
    budget = state['budget']
    reserve = (budget['verification_reserve_rounds'], budget['verification_reserve_seconds'], budget['verification_reserve_requests']) if purpose == 'investigation' else (0, 0, 0)
    if budget['rounds'] - 1 < reserve[0] or budget['active_seconds'] - 25 < reserve[1] or budget['http_requests'] - requests < reserve[2]:
        raise CaseError('insufficient budget')
    return provider, args, requests

def stop_child(proc):
    if proc.poll() is None:
        try:
            if os.name == 'posix':
                os.killpg(proc.pid, signal.SIGTERM)
            else:
                proc.terminate()
            proc.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            try:
                if os.name == 'posix':
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
            except OSError:
                pass
            proc.wait(timeout=1)

def supervise(case_dir, command, deadline, maximum):
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        import json
        with connect(case_dir) as conn:
            conn.execute('BEGIN IMMEDIATE')
            state = json.loads(conn.execute('SELECT snapshot FROM state WHERE id=1').fetchone()[0])
            if state['status'] == 'cancelled':
                conn.rollback()
                return None, b'', 'cancelled'
            proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=(os.name == 'posix'))
            conn.commit()
        try:
            until = min(deadline, time.monotonic() + maximum)
            while proc.poll() is None:
                if get_case(case_dir)['status'] == 'cancelled':
                    stop_child(proc)
                    return None, b'', 'cancelled'
                if time.monotonic() >= until:
                    stop_child(proc)
                    return None, b'', 'deadline exceeded'
                time.sleep(0.05)
            stdout.seek(0)
            return proc.returncode, stdout.read(4097), None
        finally:
            stop_child(proc)

def _internal_event(case_dir, event_id):
    state = get_case(case_dir)
    return dict(event_id=event_id, actor='local-controller', occurred_at=now(), expected_revision=state['revision'])

def _retry_internal(case_dir, event_id, callback):
    for _ in range(20):
        event = _internal_event(case_dir, event_id)
        try:
            return callback(event)
        except CaseError as exc:
            if str(exc) != 'stale revision':
                raise
    raise CaseError('could not settle operation after revision conflicts')

def run_collector(case_dir, data):
    spawned = []
    operation_id = uuid.uuid4().hex
    def reserve(state, conn):
        provider, args, requests = preflight(state, data)
        state['budget']['rounds'] -= 1
        state['budget']['active_seconds'] -= 25
        state['budget']['http_requests'] -= requests
        if data['purpose'] == 'verification':
            for key, amount in (('verification_reserve_rounds', 1), ('verification_reserve_seconds', 25), ('verification_reserve_requests', requests)):
                state['budget'][key] = max(0, state['budget'][key] - amount)
        state['operations'].append({'operation_id': operation_id, 'event_id': data['event_id'], 'status': 'in_flight', 'purpose': data['purpose'], 'mode': data['mode'], 'reserved_rounds': 1, 'reserved_seconds': 25, 'reserved_requests': requests, 'accepted_run_id': None, 'stopped_reason': None})
        spawned.append((provider, args))
        return {'operation_id': operation_id, 'reservation': {'rounds': 1, 'seconds': 25, 'http_requests': requests}}
    snapshot = transact(case_dir, data, 'run', reserve)
    if not spawned:
        op = next(op for op in snapshot['operations'] if op['event_id'] == data['event_id'])
        current = get_case(case_dir)
        op = next((x for x in current['operations'] if x['operation_id'] == op['operation_id']), op)
        return {k: op[k] for k in ('operation_id', 'accepted_run_id', 'stopped_reason')}
    provider, args = spawned[0]
    deadline = time.monotonic() + 25
    accepted = None
    reason = None
    try:
        code, output, reason = supervise(case_dir, [sys.executable, str(provider), '--version'], deadline, 2)
        if not reason and (code != 0 or not re.fullmatch(rb'internet-access-triage 0\.1\.\d+\s*', output)):
            reason = 'incompatible provider version'
        if not reason:
            code, _, reason = supervise(case_dir, [sys.executable, str(provider)] + args, deadline, max(0, deadline - time.monotonic()))
            if code != 0 and not reason:
                reason = 'collector exited unsuccessfully'
        out = Path(data['out'])
        if out.is_dir() and not out.is_symlink():
            try:
                contents = {name: read_confined(out, name, 16 * 1024 * 1024) for name in SUMMARIES}
                import json
                manifest = json.loads(contents['manifest.json'])
                run_id = token(manifest.get('run_id'), 'run_id')
                hashes = {name: hashlib.sha256(value).hexdigest() for name, value in contents.items()}
                _retry_internal(case_dir, 'import-' + operation_id, lambda ev: import_run(case_dir, dict(ev, run_dir=str(out), run_id=run_id, expected_summary_hashes=hashes), allow_terminal=True))
                accepted = run_id
            except (CaseError, OSError, ValueError, TypeError) as exc:
                reason = reason or ('invalid collector output: ' + str(exc))
        else:
            reason = reason or 'collector produced no complete output'
    except (OSError, CaseError) as exc:
        reason = 'provider execution failed: ' + str(exc)
    def settle(ev):
        def change(state, conn):
            op = next(item for item in state['operations'] if item['operation_id'] == operation_id)
            if op['status'] != 'in_flight':
                raise CaseError('operation already settled')
            op.update(status='settled', accepted_run_id=accepted, stopped_reason=reason)
            return {'operation_id': operation_id, 'accepted_run_id': accepted, 'stopped_reason': reason, 'descendant_cleanup': 'unverified'}
        return transact(case_dir, ev, 'settle', change)
    _retry_internal(case_dir, 'settle-' + operation_id, settle)
    return {'operation_id': operation_id, 'accepted_run_id': accepted, 'stopped_reason': reason}

def transition_case(case_dir, data):
    from .store import number
    def change(state, conn):
        if state['status'] in TERMINAL:
            raise CaseError('reopen terminal case before transition')
        nonempty(data.get('reason'), 'reason')
        if 'budget_increase' in data:
            nonempty(data.get('authorization_ref'), 'authorization_ref')
            increase = data['budget_increase']
            if not isinstance(increase, dict) or not increase or not set(increase) <= {'rounds', 'active_seconds', 'http_requests'}:
                raise CaseError('invalid budget increase')
            for key, value in increase.items():
                number(value, key, 0, integer=True)
                state['budget'][key] += value
            if not any(increase.values()):
                raise CaseError('budget increase must be positive')
            return {'reason': data['reason'], 'authorization_ref': data['authorization_ref'], 'budget_increase': increase}
        if 'reconcile_operation_id' in data:
            op = next((item for item in state['operations'] if item['operation_id'] == data['reconcile_operation_id']), None)
            if not op or op['status'] != 'in_flight' or data.get('confirmed_ended') is not True:
                raise CaseError('in-flight operation and confirmation required')
            nonempty(data.get('owner'), 'owner')
            nonempty(data.get('evidence'), 'evidence')
            op.update(status='reconciled_unknown', stopped_reason='owner confirmed prior process ended; outcome unknown')
            return {'operation_id': op['operation_id'], 'owner': data['owner'], 'evidence': data['evidence'], 'reason': data['reason']}
        raise CaseError('unsupported transition')
    return transact(case_dir, data, 'transition', change)
