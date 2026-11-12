#!/usr/bin/env python3
"""Operate a local incident case using JSON inputs."""
import argparse
import json
import sys
from pathlib import Path
from case_runtime.store import CaseError, create_case, get_case, update_scope

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['create', 'scope', 'get'])
    parser.add_argument('--case', required=True, type=Path)
    parser.add_argument('--input', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'get':
            result = get_case(args.case)
        else:
            if args.input is None:
                raise CaseError('--input is required')
            data = json.loads(args.input.read_text(encoding='utf-8'), parse_constant=lambda value: (_ for _ in ()).throw(CaseError('non-finite JSON number')))
            result = {'create': create_case, 'scope': update_scope}[args.command](args.case, data)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (CaseError, OSError, ValueError, KeyError) as exc:
        print('case: ' + str(exc), file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
