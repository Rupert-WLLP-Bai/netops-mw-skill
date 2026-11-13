#!/usr/bin/env python3
"""Operate a local incident case using JSON inputs."""
import argparse
import json
import sys
from pathlib import Path
from case_runtime.collection import run_collector, cancel_case, reopen_case
from case_runtime.recovery import record_action, record_verification, transition_case, export_report
from case_runtime.evidence import import_run, record_decision, read_confined
from case_runtime.store import CaseError, create_case, get_case, update_scope

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['create', 'scope', 'import-run', 'decision', 'run', 'cancel', 'reopen', 'transition', 'action', 'verification', 'get', 'export'])
    parser.add_argument('--case', required=True, type=Path)
    parser.add_argument('--input', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'get':
            result = get_case(args.case)
        elif args.command == 'export':
            print(export_report(args.case), end='')
            return 0
        else:
            if args.input is None:
                raise CaseError('--input is required')
            input_path = args.input.absolute()
            raw = read_confined(input_path.parent, input_path.name, 16 * 1024 * 1024)
            data = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(CaseError('non-finite JSON number')))
            result = {'create': create_case, 'scope': update_scope, 'import-run': import_run, 'decision': record_decision, 'run': run_collector, 'cancel': cancel_case, 'reopen': reopen_case, 'transition': transition_case, 'action': record_action, 'verification': record_verification}[args.command](args.case, data)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (CaseError, OSError, ValueError, KeyError, RecursionError) as exc:
        print('case: ' + str(exc), file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
