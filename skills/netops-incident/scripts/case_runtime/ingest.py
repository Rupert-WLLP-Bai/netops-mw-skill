"""Bounded offline carrier file ingestion; input text is never executed."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import multiprocessing
import os
import re
import shutil
import tempfile
from pathlib import Path

from .carrier import bounded, validate_context, validate_envelope
from .evidence import read_confined, rename_noreplace
from .store import CaseError, timestamp, token

VERSION = '1.0.0'
SOURCE_LIMIT = 1024 * 1024
OUTPUT_LIMIT = 2 * 1024 * 1024
LINE_LIMIT = 1024
LINE_BYTES = 8192
RECORD_LIMIT = 256
FORMATS = {'telemetry-json-v1', 'telemetry-csv-v1', 'topology-json-v1', 'optical-json-v1', 'cli-keyvalue-v1', 'syslog-rfc5424-v1'}
FIELDS = ('metric', 'value', 'unit', 'direction', 'denominator', 'sample_interval_seconds', 'sample_count', 'counter_semantics', 'reset_state', 'event_time', 'object_id')
CONFIG_FIELDS = {'format', 'run_id', 'source', 'actor', 'authorization_ref', 'collected_at', 'reference_time', 'max_age_seconds', 'timezone', 'clock_quality', 'clock_uncertainty_seconds', 'metric_allowlist', 'unit_allowlist', 'relation_allowlist', 'value_allowlists', 'pseudonyms'}
TYPES = {'service', 'customer_pseudonym', 'site', 'circuit', 'access_line', 'device', 'interface', 'vlan', 'vrf', 'session', 'path', 'alarm', 'measurement', 'sla', 'acceptance_criterion'}
LAYERS = {None, 'endpoint_lan', 'access', 'aggregation_subscriber_edge', 'ip_bearer_transport', 'internet_edge_interconnect', 'destination_application'}


def dump(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise CaseError('duplicate JSON key')
            result[key] = value
        return result
    try:
        result = json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(CaseError('invalid JSON number')))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CaseError('invalid JSON') from exc
    bounded(result)
    return result


def safe_token(value):
    return token(value, 'controlled label')


def finite(value, minimum=None):
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise CaseError('invalid number')
    try:
        if not math.isfinite(value) or (minimum is not None and value < minimum): raise CaseError('invalid number')
    except OverflowError as exc:
        raise CaseError('invalid number') from exc
    return value


def validate_config(cfg):
    bounded(cfg)
    if not isinstance(cfg, dict) or set(cfg) != CONFIG_FIELDS: raise CaseError('invalid configuration fields')
    for key in ('format', 'run_id', 'source', 'actor', 'authorization_ref'):
        safe_token(cfg[key])
    zone = cfg['timezone']
    if not isinstance(zone, str) or not re.fullmatch(r'[A-Za-z0-9_+:./-]{1,128}', zone) or '..' in zone:
        raise CaseError('invalid timezone')
    timestamp(cfg['collected_at']); timestamp(cfg['reference_time'])
    finite(cfg['max_age_seconds'], 0)
    if cfg['clock_quality'] not in ('synchronized', 'skewed', 'unknown'): raise CaseError('invalid clock quality')
    if cfg['clock_uncertainty_seconds'] is not None: finite(cfg['clock_uncertainty_seconds'], 0)
    for key in ('metric_allowlist', 'unit_allowlist', 'relation_allowlist'):
        values = cfg[key]
        if not isinstance(values, list) or len(values) > 256 or any(not isinstance(v, str) for v in values): raise CaseError('invalid allowlist')
        for value in values:
            if key == 'unit_allowlist':
                if not 1 <= len(value) <= 128 or not value.strip() or not all(char.isprintable() for char in value): raise CaseError('invalid unit label')
            else: safe_token(value)
        if len(set(values)) != len(values): raise CaseError('duplicate allowlist value')
    value_lists = cfg['value_allowlists']
    if not isinstance(value_lists, dict) or len(value_lists) > 256: raise CaseError('invalid value allowlists')
    for key, values in value_lists.items():
        if key not in cfg['metric_allowlist'] or not isinstance(values, list) or len(values) > 256: raise CaseError('invalid value allowlist')
        for value in values: safe_token(value)
        if len(set(values)) != len(values): raise CaseError('duplicate value allowlist')
    aliases = cfg['pseudonyms']
    if not isinstance(aliases, dict) or len(aliases) > 256: raise CaseError('invalid pseudonyms')
    for key, value in aliases.items():
        if not isinstance(key, str) or not key or len(key) > 2048: raise CaseError('invalid pseudonym source')
        safe_token(value)
    if len(set(aliases.values())) != len(aliases): raise CaseError('duplicate pseudonym')
    if set(aliases).intersection(aliases.values()): raise CaseError('pseudonym collides with a private identifier')
    return cfg


def _source_text(raw):
    try: text = raw.decode('utf-8')
    except UnicodeError as exc: raise CaseError('invalid text encoding') from exc
    if any(ord(char) < 32 and char not in '\n\r\t' for char in text) or '\x7f' in text:
        raise CaseError('terminal control in source')
    lines = text.splitlines()
    if len(lines) > LINE_LIMIT or any(len(line.encode('utf-8')) > LINE_BYTES for line in lines): raise CaseError('source line limit exceeded')
    return text, lines


def _normalize_record(row, cfg, quality):
    if not isinstance(row, dict) or set(row) != set(FIELDS): raise CaseError('invalid record fields')
    metric, value = row['metric'], row['value']
    if metric not in cfg['metric_allowlist']: raise CaseError('metric not allowed')
    if isinstance(value, str):
        if value not in cfg['value_allowlists'].get(metric, []): raise CaseError('value not allowed')
    elif value is not None: finite(value)
    if row['unit'] is not None and row['unit'] not in cfg['unit_allowlist']: raise CaseError('unit not allowed')
    if row['denominator'] is not None and row['denominator'] not in cfg['unit_allowlist']: raise CaseError('denominator not allowed')
    if row['direction'] not in ('ingress', 'egress', 'bidirectional', 'unknown'): raise CaseError('invalid direction')
    if row['counter_semantics'] not in ('gauge', 'delta', 'cumulative', 'unknown') or row['reset_state'] not in ('none', 'reset', 'wrap', 'unknown'): raise CaseError('invalid counter semantics')
    if row['reset_state'] in ('reset', 'wrap') and row['counter_semantics'] not in ('cumulative', 'unknown'): raise CaseError('invalid counter reset')
    if row['sample_interval_seconds'] is not None:
        if finite(row['sample_interval_seconds'], 0) == 0: raise CaseError('invalid sampling interval')
    count = row['sample_count']
    if count is not None and (isinstance(count, bool) or not isinstance(count, int) or count < 0): raise CaseError('invalid sample count')
    event = row['event_time']
    if event is not None:
        when = timestamp(event)
        if cfg['clock_quality'] == 'synchronized' and when > timestamp(cfg['collected_at']): raise CaseError('event after collection')
        if (timestamp(cfg['reference_time']) - when).total_seconds() > cfg['max_age_seconds']: quality.add('stale')
    else:
        quality.add('clock_uncertain')
    if row['counter_semantics'] == 'unknown': quality.add('unknown_counter_semantics')
    native = row['object_id']
    if native is not None and (not isinstance(native, str) or not native or len(native) > 2048): raise CaseError('invalid object id')
    alias = cfg['pseudonyms'].get(native) if native is not None else None
    # A source alias is not an independently mapped topology object.
    quality.add('incomplete_topology')
    result = dict(row); result['object_id'] = alias
    return result


def _topology(data, cfg, quality):
    if not isinstance(data, dict) or set(data) != {'format', 'version', 'service_id', 'objects', 'links'} or data['format'] != cfg['format'] or data['version'] != 1 or isinstance(data['version'], bool): raise CaseError('invalid topology header')
    objects, links = data['objects'], data['links']
    if not isinstance(objects, list) or len(objects) > 256 or not isinstance(links, list) or len(links) > 512: raise CaseError('invalid topology size')
    output, mapping, states = [], {}, {}
    used = set(cfg['pseudonyms'].values())
    for index, obj in enumerate(objects):
        if not isinstance(obj, dict) or set(obj) != {'id', 'type', 'layer'} or not isinstance(obj['id'], str) or not obj['id'] or obj['id'] in mapping or obj['type'] not in TYPES or obj['layer'] not in LAYERS: raise CaseError('invalid topology object')
        alias = cfg['pseudonyms'].get(obj['id']); known = alias is not None
        if not known:
            alias = 'unknown-' + str(index + 1)
            while alias in used: alias += '-x'
            quality.add('incomplete_topology')
        used.add(alias); mapping[obj['id']] = alias; states[alias] = known
        output.append(dict(id=alias, type=obj['type'], identity_state='known' if known else 'unknown', layer=obj['layer'], source=cfg['source'], source_native_id=None, reason=None if known else 'mapping unavailable'))
    topology = []
    for link in links:
        if not isinstance(link, dict) or set(link) != {'from_id', 'to_id', 'relation', 'state', 'confidence'}: raise CaseError('invalid topology link')
        if link['from_id'] not in mapping or link['to_id'] not in mapping or link['relation'] not in cfg['relation_allowlist'] or link['state'] not in ('verified', 'unverified', 'ambiguous') or link['confidence'] not in (None, 'low', 'medium', 'high'): raise CaseError('invalid topology link')
        left, right = mapping[link['from_id']], mapping[link['to_id']]
        state = link['state']; reason = None if state == 'verified' else 'source declaration'
        if state == 'verified' and (not states[left] or not states[right]): state, reason = 'unverified', 'mapping unavailable'
        if state != 'verified': quality.add('incomplete_topology')
        topology.append(dict(from_id=left, to_id=right, relation=link['relation'], state=state, confidence=link['confidence'], reason=reason))
    service = data['service_id']
    if service is not None and (not isinstance(service, str) or service not in mapping): raise CaseError('invalid service id')
    service_ref = mapping[service] if service is not None and states[mapping[service]] else None
    if service_ref is None: quality.add('incomplete_topology')
    context = dict(schema_version=1, service_ref=service_ref, objects=output, topology=topology)
    validate_context(context)
    return context


def parse_source(raw, cfg):
    """Interpret only the explicitly selected formats, returning safe data."""
    quality = set()
    warnings = set()
    if cfg['clock_quality'] != 'synchronized' or cfg['clock_uncertainty_seconds'] is None or timestamp(cfg['reference_time']) < timestamp(cfg['collected_at']): quality.add('clock_uncertain')
    if cfg['format'] not in FORMATS:
        return dict(parse_status='unsupported_vendor_format', quality=sorted(quality), warnings=[], records=[], service_context=None)
    if cfg['format'] == 'optical-json-v1' and b'\x00' in raw:
        return dict(parse_status='unsupported_vendor_format', quality=sorted(quality), warnings=[], records=[], service_context=None)
    text, lines = _source_text(raw)
    fmt = cfg['format']; records = []; context = None
    if fmt in ('telemetry-json-v1', 'optical-json-v1', 'topology-json-v1'):
        data = strict_json(text)
        if not isinstance(data, dict): raise CaseError('invalid JSON root')
        if data.get('format') != fmt or data.get('version') != 1 or isinstance(data.get('version'), bool):
            return dict(parse_status='unsupported_vendor_format', quality=sorted(quality), warnings=[], records=[], service_context=None)
        if fmt == 'topology-json-v1':
            context = _topology(data, cfg, quality)
        else:
            if set(data) != {'format', 'version', 'records'} or not isinstance(data['records'], list) or len(data['records']) > RECORD_LIMIT: raise CaseError('invalid records')
            records = [_normalize_record(record, cfg, quality) for record in data['records']]
    elif fmt == 'telemetry-csv-v1':
        try:
            reader = csv.reader(io.StringIO(text, newline=''), strict=True)
            header = next(reader, None)
            if header != list(FIELDS): raise CaseError('invalid CSV header')
            for values in reader:
                if len(values) != len(FIELDS) or any(len(value) > 2048 for value in values) or len(records) >= RECORD_LIMIT: raise CaseError('invalid CSV row')
                row = dict(zip(FIELDS, values))
                for field in ('unit', 'denominator', 'event_time', 'object_id'): row[field] = row[field] or None
                for field in ('value', 'sample_interval_seconds', 'sample_count'):
                    value = row[field]
                    if value == '': row[field] = None
                    elif field == 'value' and value in cfg['value_allowlists'].get(row['metric'], []): row[field] = value
                    else:
                        try:
                            if field == 'sample_count':
                                if not re.fullmatch(r'\d+', value): raise ValueError('integer required')
                                row[field] = int(value)
                            else: row[field] = float(value)
                        except ValueError as exc: raise CaseError('invalid CSV number') from exc
                records.append(_normalize_record(row, cfg, quality))
        except csv.Error as exc:
            raise CaseError('invalid CSV') from exc
    elif fmt == 'cli-keyvalue-v1':
        if not lines or lines[0] != '# carrier-cli-keyvalue-v1':
            return dict(parse_status='unsupported_vendor_format', quality=sorted(quality), warnings=[], records=[], service_context=None)
        for line in lines[1:]:
            if len(records) >= RECORD_LIMIT: raise CaseError('record limit exceeded')
            parts = line.split('=', 1)
            if len(parts) != 2 or parts[0] not in cfg['metric_allowlist']:
                warnings.add('withheld_unrecognized_line'); continue
            metric, value = parts
            if value not in cfg['value_allowlists'].get(metric, []):
                try: value = float(value)
                except ValueError: warnings.add('withheld_unrecognized_line'); continue
            row = dict(metric=metric, value=value, unit=None, direction='unknown', denominator=None, sample_interval_seconds=None, sample_count=None, counter_semantics='unknown', reset_state='unknown', event_time=None, object_id=None)
            records.append(_normalize_record(row, cfg, quality))
    else:
        for line in lines:
            if len(records) >= RECORD_LIMIT: raise CaseError('record limit exceeded')
            match = re.match(r'^<(\d{1,3})>1 ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) (.+)$', line)
            if not match or int(match.group(1)) > 191: raise CaseError('unsupported syslog header')
            remainder = match.group(7)
            if not (remainder == '-' or remainder.startswith('- ') or remainder.startswith('[')):
                raise CaseError('missing syslog structured data')
            event = match.group(2)
            if event == '-':
                event = None
                quality.add('clock_uncertain')
            elif not event.endswith('Z'): raise CaseError('unsupported timestamp offset')
            if event is not None:
                when = timestamp(event)
                if cfg['clock_quality'] == 'synchronized' and when > timestamp(cfg['collected_at']): raise CaseError('event after collection')
                if (timestamp(cfg['reference_time']) - when).total_seconds() > cfg['max_age_seconds']: quality.add('stale')
            records.append(dict(priority=int(match.group(1)), event_time=event))
            quality.add('incomplete_topology')
        warnings.add('withheld_syslog_content')
    return dict(parse_status='complete', quality=sorted(quality), warnings=sorted(warnings), records=records, service_context=context)


def _failure(status, cfg, warnings=None):
    quality = []
    if cfg['clock_quality'] != 'synchronized' or cfg['clock_uncertainty_seconds'] is None or timestamp(cfg['reference_time']) < timestamp(cfg['collected_at']):
        quality.append('clock_uncertain')
    return dict(parse_status=status, quality=quality, warnings=warnings or [], records=[], service_context=None)


def _worker(result_path, raw, cfg):
    try: result = parse_source(raw, cfg)
    except Exception:
        result = _failure('parse_error', cfg)
    data = dump(result)
    if len(data) > OUTPUT_LIMIT:
        data = dump(_failure('parse_error', cfg, ['output_limit']))
    with open(result_path, 'xb') as stream:
        stream.write(data)


def _process(raw, cfg, result_path):
    context = multiprocessing.get_context('spawn')
    return context.Process(target=_worker, args=(str(result_path), raw, cfg), daemon=True)


def run_worker(raw, cfg, timeout=5):
    with tempfile.TemporaryDirectory(prefix='carrier-worker-') as temp:
        result_path = Path(temp) / 'result.json'
        process = _process(raw, cfg, result_path)
        process.start()
        try:
            process.join(timeout)
            if process.is_alive():
                return _failure('parse_timeout', cfg)
            if process.exitcode != 0:
                return _failure('parse_error', cfg)
            try:
                data = read_confined(Path(temp), 'result.json', OUTPUT_LIMIT)
                return strict_json(data)
            except (OSError, CaseError):
                return _failure('parse_error', cfg)
        finally:
            if process.is_alive():
                process.terminate()
                process.join(1)
                if process.is_alive(): process.kill()
            process.join()


def bundle(raw, cfg, parsed):
    visible = dict(schema_version=1, parse_status=parsed['parse_status'], quality=parsed['quality'], records=parsed['records'])
    visible_bytes = dump(visible) + b'\n'
    visible_hash, raw_hash = digest(visible_bytes), digest(raw)
    rows = parsed['records'] or [None]
    evidence = []; carrier = []
    status = {'complete': 'complete', 'unsupported_vendor_format': 'unsupported', 'parse_error': 'parse_error', 'parse_timeout': 'timeout'}[parsed['parse_status']]
    for index, row in enumerate(rows, 1):
        eid = 'ev-' + format(index, '012x')
        evidence.append(dict(id=eid, kind='carrier_import', tool=dict(name='carrier-ingest', version=VERSION), status=status, scope={}, started_at_utc=cfg['collected_at'], duration_ns=0, observation=dict(parse_status=parsed['parse_status'], quality=parsed['quality'], record=row), sources=[dict(kind='run_artifact', path='carrier-visible.json', sha256=visible_hash)], failure=None))
        event = row.get('event_time') if row else None
        measurement = None
        if row and 'metric' in row and not isinstance(row['value'], str):
            measurement = dict(value=row['value'], unit=row['unit'], direction=row['direction'], denominator=row['denominator'], sample_interval_seconds=row['sample_interval_seconds'], sample_count=row['sample_count'], missing_reason='not supplied' if row['value'] is None else None, counter_semantics=row['counter_semantics'], reset_state=row['reset_state'])
        carrier.append(dict(evidence_id=eid, object_refs=[], source=cfg['source'], source_native_id=row.get('object_id') if row else None, device_role=None, event_time=event, collected_at=cfg['collected_at'], timezone=cfg['timezone'], clock_quality=cfg['clock_quality'], clock_uncertainty_seconds=cfg['clock_uncertainty_seconds'], artifact_sha256=visible_hash, redaction=dict(status='redacted', raw_sha256=raw_hash, visible_sha256=visible_hash, policy_ref='allowlisted-derivative-v1'), topology_mapping_confidence=None, measurement=measurement))
    envelope = dict(schema_version=1, records=carrier)
    validate_envelope(envelope, parsed['service_context'], evidence)
    evidence_bytes = b''.join(dump(record) + b'\n' for record in evidence)
    diagnosis = dict(schema_version='0.1.0', status='insufficient_evidence', scope=dict(mode='replay', target=None, protocol=None, time_window=None), evidence_ids=[record['id'] for record in evidence], candidates=[], counterevidence=[], limitations=['Offline import does not establish service health or cause.'], next_steps=['Review source scope and evidence limitations.'], origin='replay')
    files = {'carrier-visible.json':visible_bytes, 'evidence.jsonl':evidence_bytes, 'diagnosis.json':dump(diagnosis) + b'\n', 'report.md':b'# Offline carrier import\n\nObservations are supplied claims; no service diagnosis is made.\n'}
    adapter = dict(format=cfg['format'], version=VERSION, parse_status=parsed['parse_status'], quality=parsed['quality'], warnings=parsed['warnings'], source=cfg['source'], actor=cfg['actor'], authorization_ref=cfg['authorization_ref'], collected_at=cfg['collected_at'], reference_time=cfg['reference_time'], timezone=cfg['timezone'])
    manifest = dict(run_id=cfg['run_id'], run_window=dict(started_at_utc=cfg['collected_at'], ended_at_utc=cfg['collected_at']), completed_at_utc=cfg['collected_at'], artifact_hashes={name:digest(data) for name, data in files.items()}, validation_errors=dict(evidence=[], diagnosis=[]), scope={}, failures=[], privacy='allowlisted derivative; original restricted', carrier_adapter=adapter, carrier_evidence=envelope)
    if parsed['service_context'] is not None: manifest['service_context'] = parsed['service_context']
    files['manifest.json'] = dump(manifest) + b'\n'
    if sum(len(data) for data in files.values()) > OUTPUT_LIMIT: raise CaseError('visible output limit exceeded')
    return files


def _safe_destination(path):
    path = Path(os.path.abspath(path))
    if path.exists() or path.is_symlink(): raise CaseError('destination already exists')
    parent = path.parent
    current = Path(parent.anchor)
    for part in parent.parts[1:]:
        current = current / part
        if current.is_symlink() or not current.is_dir(): raise CaseError('unsafe destination parent')
    return path


def _write_file(directory, name, data):
    fd = os.open(str(directory / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def ingest(source_root, source, config_path, output, private):
    config_path = Path(os.path.abspath(config_path))
    config_bytes = read_confined(config_path.parent, config_path.name, SOURCE_LIMIT)
    cfg = validate_config(strict_json(config_bytes))
    source_root = Path(os.path.abspath(source_root))
    raw = read_confined(source_root, source, SOURCE_LIMIT)
    output = _safe_destination(output); private = _safe_destination(private)
    if output == private or output in private.parents or private in output.parents or source_root in output.parents or source_root in private.parents or output == source_root or private == source_root:
        raise CaseError('destinations must be separate from each other and source')
    parsed = run_worker(raw, cfg)
    files = bundle(raw, cfg, parsed)
    staged = []; published = []
    try:
        raw_stage = Path(tempfile.mkdtemp(prefix='.carrier-private-', dir=private.parent)); staged.append(raw_stage)
        visible_stage = Path(tempfile.mkdtemp(prefix='.carrier-visible-', dir=output.parent)); staged.append(visible_stage)
        _write_file(raw_stage, 'raw.bin', raw)
        _write_file(raw_stage, 'pseudonyms.json', dump(cfg['pseudonyms']) + b'\n')
        for name, content in files.items(): _write_file(visible_stage, name, content)
        for stage, destination in ((raw_stage, private), (visible_stage, output)):
            identity = stage.stat()
            rename_noreplace(stage, destination)
            published.append((destination, identity.st_dev, identity.st_ino))
        return dict(run_id=cfg['run_id'], parse_status=parsed['parse_status'], quality=parsed['quality'], summary_hashes={name:digest(files[name]) for name in ('manifest.json', 'evidence.jsonl', 'diagnosis.json', 'report.md')})
    except Exception:
        for path, device, inode in reversed(published):
            try:
                info = path.lstat()
                if info.st_dev == device and info.st_ino == inode and path.is_dir() and not path.is_symlink(): shutil.rmtree(path)
            except OSError:
                pass
        raise
    finally:
        for path in staged:
            if path.exists() and not path.is_symlink(): shutil.rmtree(path)
