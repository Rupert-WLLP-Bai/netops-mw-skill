"""Record operator actions and evaluate declared original-flow observations."""
from __future__ import annotations
import hashlib
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .collection import transition_case as collection_transition
from .evidence import read_confined, rename_noreplace, validate_refs
from .store import CaseError, TERMINAL, nonempty, number, timestamp, token, transact

TRANSITIONS = {
    'intake': {'investigating'},
    'investigating': {'awaiting_action', 'verifying', 'closed_unresolved'},
    'awaiting_action': {'verifying', 'action_outcome_unknown', 'closed_unresolved'},
    'action_outcome_unknown': {'awaiting_action', 'verifying', 'closed_unresolved'},
    'verifying': {'stabilizing', 'investigating', 'closed_unresolved'},
    'stabilizing': {'closed_recovered', 'investigating', 'closed_unresolved'},
}

def clock():
    return datetime.now(timezone.utc)

def stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')

def complete_policy(state):
    if any(value is None for value in state['scope'].values()) or any(value is None for value in state['verification_plan'].values()):
        raise CaseError('complete original scope and verification plan required')

def unknown_action(state):
    return any(a['outcome'] == 'unknown' and not a.get('reconciliation') for a in state['actions'])

def record_action(case_dir, data):
    def change(state, conn):
        if state['status'] != 'awaiting_action' or unknown_action(state):
            raise CaseError('action requires awaiting action and no unknown outcome')
        complete_policy(state)
        fields = ('owner', 'intended_change', 'preconditions', 'authorization_ref', 'expected_check', 'rollback_trigger', 'rollback_owner', 'correlation_key')
        for field in fields:
            nonempty(data.get(field), field)
        token(data['correlation_key'], 'correlation_key')
        if any(action['correlation_key'] == data['correlation_key'] for action in state['actions']):
            raise CaseError('correlation key already recorded')
        if data.get('affected_scope') != state['scope']:
            raise CaseError('action scope differs from original scope')
        action_time = timestamp(data.get('action_time'))
        if action_time > clock():
            raise CaseError('action time is in the future')
        if data.get('outcome') not in ('proposed', 'completed', 'partial', 'unknown', 'failed'):
            raise CaseError('invalid action outcome')
        validate_refs(state, data.get('evidence'))
        action = {key: data[key] for key in fields + ('affected_scope', 'action_time', 'outcome', 'evidence')}
        action.update(event_id=data['event_id'], episode_id=state['episode_id'], policy_revision=state['policy_revision'], reconciliation=None)
        state['actions'].append(action)
        if action['outcome'] == 'unknown':
            state['status'] = 'action_outcome_unknown'
        return {'action': action}
    return transact(case_dir, data, 'action', change)

def record_verification(case_dir, data):
    created = []
    def change(state, conn):
        if state['status'] not in ('verifying', 'stabilizing') or unknown_action(state):
            raise CaseError('case is not eligible for verification')
        complete_policy(state)
        if data.get('kind') == 'start':
            reason = nonempty(data.get('reason'), 'reason')
            start = clock()
            end = start + timedelta(seconds=state['verification_plan']['window_seconds'])
            window = {'window_id': uuid.uuid4().hex, 'episode_id': state['episode_id'], 'policy_revision': state['policy_revision'], 'policy_hash': state['policy_hash'], 'window_start': stamp(start), 'window_end': stamp(end), 'reason': reason}
            state['verification_windows'].append(window)
            return {'window': window}
        if data.get('kind') != 'check':
            raise CaseError('invalid verification kind')
        if not state['verification_windows']:
            raise CaseError('verification window required')
        window = state['verification_windows'][-1]
        for key in ('window_id', 'episode_id', 'policy_revision', 'policy_hash', 'window_start', 'window_end'):
            if data.get(key) != window[key]:
                raise CaseError('window identity mismatch')
        if window['episode_id'] != state['episode_id'] or window['policy_revision'] != state['policy_revision'] or window['policy_hash'] != state['policy_hash'] or data.get('scope') != state['scope']:
            raise CaseError('scope or policy mismatch')
        check_id = token(data.get('check_id'), 'check_id')
        if any(item['check_id'] == check_id for item in state['checks']):
            raise CaseError('duplicate check ID')
        observed = timestamp(data.get('observed_at'))
        collected = timestamp(data.get('collected_at'))
        recorded = clock()
        if not observed <= collected <= recorded:
            raise CaseError('invalid observation time order')
        for key in ('source', 'source_actor', 'provenance'):
            nonempty(data.get(key), key)
        if data.get('trust_grade') not in ('independent_observation', 'owner_claim') or not isinstance(data.get('differences'), list):
            raise CaseError('invalid trust grade or differences')
        value = number(data.get('value'), 'check value')
        plan = state['verification_plan']
        if data.get('unit') != plan['unit']:
            raise CaseError('check unit mismatch')
        criterion = plan['criterion']
        passed = {'eq': value == criterion['value'], 'gte': value >= criterion['value'], 'lte': value <= criterion['value']}[criterion['operator']]
        if data.get('outcome') != ('pass' if passed else 'fail'):
            raise CaseError('outcome disagrees with criterion')
        ref = data.get('raw_reference')
        if not isinstance(ref, dict) or set(ref) != {'root', 'path', 'sha256'}:
            raise CaseError('artifact reference required')
        root = Path(nonempty(ref['root'], 'artifact root'))
        if not root.is_absolute():
            raise CaseError('artifact root must be absolute')
        raw = read_confined(root, ref['path'], 16 * 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != ref['sha256']:
            raise CaseError('artifact hash mismatch')
        imports = Path(case_dir) / 'imports'
        stage = Path(tempfile.mkdtemp(prefix='.check-', dir=imports))
        try:
            fd = os.open(str(stage / 'artifact'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            destination = imports / ('check-' + check_id)
            if destination.exists() or destination.is_symlink():
                raise CaseError('check destination already exists')
            rename_noreplace(stage, destination)
            created.append(destination)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
        keys = ('check_id', 'window_id', 'episode_id', 'policy_revision', 'policy_hash', 'window_start', 'window_end', 'scope', 'observed_at', 'collected_at', 'source', 'source_actor', 'value', 'unit', 'outcome', 'raw_reference', 'provenance', 'trust_grade', 'differences')
        check = {key: data[key] for key in keys}
        check.update(event_id=data['event_id'], recorded_at=stamp(recorded), stored_artifact='imports/check-' + check_id + '/artifact', provenance_verified=False)
        state['checks'].append(check)
        return {'check': check}
    try:
        return transact(case_dir, data, 'verification', change)
    except Exception:
        for path in created:
            shutil.rmtree(path)
        raise

def recovery_gaps(state, now=None, case_dir=None):
    now = now or clock()
    complete_policy(state)
    if unknown_action(state):
        return ['unknown action outcome']
    if not state['verification_windows']:
        return ['no verification window']
    window = state['verification_windows'][-1]
    if window['episode_id'] != state['episode_id'] or window['policy_revision'] != state['policy_revision'] or window['policy_hash'] != state['policy_hash']:
        return ['verification policy or episode changed']
    start, end = timestamp(window['window_start']), timestamp(window['window_end'])
    plan = state['verification_plan']
    checks = [c for c in state['checks'] if c['episode_id'] == state['episode_id'] and c['policy_revision'] == state['policy_revision'] and c['policy_hash'] == state['policy_hash'] and c['scope'] == state['scope'] and c['window_id'] == window['window_id']]
    gaps = []
    if case_dir is not None:
        for check in checks:
            try:
                content = read_confined(Path(case_dir), check['stored_artifact'], 16 * 1024 * 1024)
                if hashlib.sha256(content).hexdigest() != check['raw_reference']['sha256']:
                    gaps.append('stored check artifact hash mismatch')
            except (CaseError, OSError):
                gaps.append('stored check artifact unavailable')
    if now < end:
        gaps.append('window has not ended')
    if any(c['outcome'] == 'fail' and start <= timestamp(c['observed_at']) <= now for c in checks):
        gaps.append('failed check or recurrence')
    passes = sorted(timestamp(c['observed_at']) for c in checks if c['outcome'] == 'pass' and c['trust_grade'] == 'independent_observation' and start <= timestamp(c['observed_at']) <= end)
    if len(passes) < plan['minimum_checks']:
        gaps.append('insufficient independent checks')
    if not passes:
        return gaps + ['no qualifying passing check']
    if (now - passes[-1]).total_seconds() > plan['freshness_seconds']:
        gaps.append('last observation is stale')
    boundaries = [start] + passes + [end]
    if any((b-a).total_seconds() > plan['maximum_gap_seconds'] for a,b in zip(boundaries, boundaries[1:])):
        gaps.append('observation gap exceeds maximum')
    coverage = sum(max(0, (min(passes[i+1] if i+1 < len(passes) else end, point + timedelta(seconds=plan['cadence_seconds']), end) - point).total_seconds()) for i, point in enumerate(passes)) / (end-start).total_seconds()
    if coverage < plan['minimum_coverage']:
        gaps.append('insufficient observation coverage')
    return gaps

def reconcile_action(state, reconciliation):
    if not isinstance(reconciliation, dict):
        raise CaseError('authoritative action reconciliation required')
    for key in ('owner', 'evidence', 'authorization_ref'):
        nonempty(reconciliation.get(key), key)
    if reconciliation.get('outcome') not in ('completed', 'partial', 'failed', 'not_performed'):
        raise CaseError('invalid reconciled action outcome')
    unresolved = [a for a in state['actions'] if a['outcome'] == 'unknown' and not a.get('reconciliation')]
    if len(unresolved) != 1 or reconciliation.get('correlation_key') != unresolved[0]['correlation_key']:
        raise CaseError('reconciliation correlation mismatch')
    unresolved[0]['reconciliation'] = dict(reconciliation)

def transition_case(case_dir, data):
    if 'budget_increase' in data or 'reconcile_operation_id' in data:
        return collection_transition(case_dir, data)
    def change(state, conn):
        reason = nonempty(data.get('reason'), 'reason')
        if 'action_reconciliation' in data:
            if state['status'] in TERMINAL:
                raise CaseError('reopen terminal case before reconciliation')
            reconcile_action(state, data['action_reconciliation'])
            return {'reason': reason, 'action_reconciliation': data['action_reconciliation']}
        target = data.get('status')
        if target not in TRANSITIONS.get(state['status'], set()):
            raise CaseError('unsupported status transition')
        if state['status'] == 'action_outcome_unknown' and target != 'closed_unresolved' and unknown_action(state):
            reconcile_action(state, data.get('reconciliation'))
        if target in ('awaiting_action', 'verifying'):
            complete_policy(state)
            if unknown_action(state):
                raise CaseError('unknown action outcome requires reconciliation')
        if target == 'investigating' and state['status'] in ('verifying', 'stabilizing'):
            latest_failure = max((event['revision'] for event in state['events'] if event['kind'] == 'verification' and event.get('check', {}).get('outcome') == 'fail'), default=0)
            last_decision_revision = max((event['revision'] for event in state['events'] if event['kind'] == 'decision'), default=0)
            if not state['decisions'] or not state['decisions'][-1].get('next_test') or last_decision_revision <= latest_failure or state['budget']['rounds'] <= state['budget']['verification_reserve_rounds']:
                raise CaseError('new permitted next test and budget required')
        if target == 'closed_recovered':
            gaps = recovery_gaps(state, case_dir=case_dir)
            if gaps:
                raise CaseError('recovery not established: ' + '; '.join(gaps))
        prior = state['status']
        state['status'] = target
        return {'prior_status': prior, 'status': target, 'reason': reason, 'reconciliation': data.get('reconciliation')}
    return transact(case_dir, data, 'transition', change)

def export_report(case_dir):
    from .store import get_case
    state = get_case(case_dir)
    try:
        gaps = recovery_gaps(state, case_dir=case_dir)
    except CaseError as exc:
        gaps = [str(exc)]
    lines = ['# Incident handoff draft', '', 'Status: ' + state['status'], 'Case: ' + state['case_id'], 'Episode: ' + state['episode_id'], 'Symptom: ' + state['symptom'], 'Business impact: ' + state['business_impact'], '', '## Original scope']
    lines.extend('- ' + key + ': ' + str(value) for key, value in state['scope'].items())
    lines += ['', '## Evidence and decisions']
    for item in state['imports']:
        lines.append('- Run ' + item['run_id'] + ': evidence ' + ', '.join(item['evidence_ids']) + '; summary hashes ' + str(item['summary_hashes']))
    for decision in state['decisions']:
        lines.append('- Observations: ' + str(decision['observations']) + '; hypotheses: ' + str(decision['hypotheses']) + '; support: ' + str(decision['support']) + '; counterevidence: ' + str(decision['counterevidence']) + '; limitations: ' + str(decision['limitations']) + '; next test: ' + str(decision['next_test']))
    lines += ['', '## Actions and checks']
    lines.extend('- Action ' + action['correlation_key'] + ': ' + action['outcome'] + '; owner: ' + action['owner'] + '; reconciliation: ' + str(action['reconciliation']) for action in state['actions'])
    lines.extend('- Check ' + check['check_id'] + ': ' + check['outcome'] + '; observed: ' + check['observed_at'] + '; SHA-256: ' + check['raw_reference']['sha256'] + '; trust: ' + check['trust_grade'] for check in state['checks'])
    lines += ['', 'Verification gaps: ' + ('; '.join(gaps) if gaps else 'none under declared policy'), 'Budget: ' + str(state['budget']), 'Owner: ' + str(state['verification_plan']['owner']), 'Next action: ' + str(state['decisions'][-1]['next_test'] if state['decisions'] else 'not recorded'), '', 'Observations and provenance are supplied claims; hashes do not authenticate them.']
    return '\n'.join(lines) + '\n'
