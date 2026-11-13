#!/usr/bin/env python3
"""Create an offline, bounded carrier evidence bundle from one supplied file."""
import argparse
import json
import sys
from pathlib import Path
from case_runtime.ingest import ingest
from case_runtime.store import CaseError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--private-out', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = ingest(args.source_root, args.source, args.config, args.out, args.private_out)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (CaseError, OSError, ValueError, RuntimeError, RecursionError):
        print('ingest: invalid input or unavailable local storage', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
