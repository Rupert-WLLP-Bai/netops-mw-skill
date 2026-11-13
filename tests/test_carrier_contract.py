"""Carrier contract and persisted-case compatibility tests."""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/netops-incident/scripts'))
from case_runtime.carrier import validate_context, validate_envelope, comparison_gaps
from case_runtime.store import CaseError

FIXTURES = ROOT / 'tests/fixtures/carrier'

class CarrierContractTests(unittest.TestCase):
    def setUp(self):
        self.context = json.loads((FIXTURES / 'context.json').read_text())
        self.envelope = json.loads((FIXTURES / 'evidence.json').read_text())
        self.records = [{'id': 'E001', 'sources': [{'sha256': 'a' * 64}]}]

    def test_valid_and_unknown(self):
        validate_context(self.context)
        validate_envelope(self.envelope, self.context, self.records)
        unknown = copy.deepcopy(self.envelope)
        unknown['records'][0]['measurement'].update(value=None, missing_reason='not measured', unit=None)
        validate_envelope(unknown, self.context, self.records)

    def test_duplicate_and_topology_references(self):
        for change in ('duplicate', 'unknown', 'unverified_identity'):
            context = copy.deepcopy(self.context)
            if change == 'duplicate': context['objects'].append(copy.deepcopy(context['objects'][0]))
            if change == 'unknown': context['topology'][0]['to_id'] = 'missing'
            if change == 'unverified_identity': context['objects'][0].update(identity_state='unknown', reason='not mapped')
            with self.subTest(change=change), self.assertRaises(CaseError): validate_context(context)

    def test_invalid_record_and_skew(self):
        for field, value in [('evidence_id', 'missing'), ('artifact_sha256', 'b' * 64), ('clock_quality', 'synchronized')]:
            envelope = copy.deepcopy(self.envelope)
            record = envelope['records'][0]
            if field == 'clock_quality': record['event_time'] = '2026-01-01T00:00:02Z'
            record[field] = value
            with self.subTest(field=field), self.assertRaises(CaseError): validate_envelope(envelope, self.context, self.records)
        envelope['records'][0]['clock_quality'] = 'skewed'
        validate_envelope(envelope, self.context, self.records)

    def test_comparison_gaps_keep_heterogeneous_data(self):
        left = copy.deepcopy(self.envelope['records'][0]); right = copy.deepcopy(left)
        right['measurement'].update(unit='bytes', direction='egress', reset_state='reset')
        right['clock_quality'] = 'unknown'
        context = copy.deepcopy(self.context); context['topology'][0].update(state='unverified', reason='not checked')
        gaps = comparison_gaps(left, right, context)
        for gap in ('unit', 'direction', 'clock', 'counter_reset', 'topology'):
            self.assertIn(gap, gaps)

    def test_schema_parity_on_structural_inputs(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest('independent jsonschema package unavailable')
        schema_dir = ROOT / 'skills/netops-incident/schemas'
        for name, value, validate in [('service-context', self.context, validate_context), ('carrier-evidence', self.envelope, lambda v: validate_envelope(v, self.context, self.records))]:
            schema = json.loads((schema_dir / (name + '.schema.json')).read_text())
            jsonschema.Draft202012Validator.check_schema(schema)
            jsonschema.validate(value, schema)
            validate(value)
            invalid = copy.deepcopy(value); invalid['unexpected'] = True
            with self.assertRaises(jsonschema.ValidationError): jsonschema.validate(invalid, schema)
            with self.assertRaises(CaseError): validate(invalid)

    def test_comparison_ignores_unrelated_links_and_positive_count_difference(self):
        left = copy.deepcopy(self.envelope['records'][0]); right = copy.deepcopy(left)
        left['source_native_id'] = right['source_native_id'] = 'counter-1'
        right['measurement']['sample_count'] = 3
        context = copy.deepcopy(self.context)
        context['objects'].extend([dict(context['objects'][1], id='extra-1'), dict(context['objects'][1], id='extra-2')])
        context['topology'].append(dict(from_id='extra-1', to_id='extra-2', relation='related', state='unverified', confidence=None, reason='not checked'))
        validate_context(context)
        self.assertEqual(comparison_gaps(left, right, context), [])
        right['object_refs'] = ['extra-1']
        self.assertIn('topology', comparison_gaps(left, right, context))

    def test_clock_reset_units_and_hash_declarations_are_conservative(self):
        left = copy.deepcopy(self.envelope['records'][0]); right = copy.deepcopy(left)
        left['source_native_id'] = right['source_native_id'] = 'counter-1'
        right['measurement']['sample_interval_seconds'] = 30
        right['measurement']['denominator'] = '0'
        right['topology_mapping_confidence'] = None
        self.assertTrue({'sample_interval_seconds', 'denominator', 'topology'}.issubset(comparison_gaps(left, right, self.context)))
        envelope = copy.deepcopy(self.envelope)
        envelope['records'][0]['artifact_sha256'] = None
        envelope['records'][0]['redaction']['visible_sha256'] = 'b' * 64
        with self.assertRaises(CaseError): validate_envelope(envelope, self.context, self.records)

    def test_limits_and_missingness(self):
        context = copy.deepcopy(self.context)
        context['objects'][0]['source'] = 'a' * 2049
        with self.assertRaises(CaseError): validate_context(context)
        context = copy.deepcopy(self.context)
        context['objects'][0]['identity_state'] = 'ambiguous'
        with self.assertRaises(CaseError): validate_context(context)
        envelope = copy.deepcopy(self.envelope)
        envelope['records'][0]['measurement']['value'] = None
        with self.assertRaises(CaseError): validate_envelope(envelope, self.context, self.records)
        envelope['records'][0]['measurement']['value'] = float('nan')
        with self.assertRaises(CaseError): validate_envelope(envelope, self.context, self.records)

if __name__ == '__main__': unittest.main()
