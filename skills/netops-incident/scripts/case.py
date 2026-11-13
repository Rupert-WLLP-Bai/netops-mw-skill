#!/usr/bin/env python3
"""Operate a local incident case using JSON inputs."""
import argparse
import json
import os
import stat
import sys
from pathlib import Path
from case_runtime.collection import run_collector, cancel_case, reopen_case
from case_runtime.recovery import record_action, record_verification, transition_case, export_report
from case_runtime.evidence import import_run, record_decision
from case_runtime.store import CaseError, create_case, get_case, update_scope

INPUT_LIMIT = 16 * 1024 * 1024

def read_input(path):
    """Read an explicitly selected bounded regular file without blocking on a FIFO."""
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size > INPUT_LIMIT:
        raise CaseError('input must be a bounded regular file')
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > INPUT_LIMIT or identity(before) != identity(opened):
            raise CaseError('input changed or is not a bounded regular file')
        chunks = []
        remaining = INPUT_LIMIT + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk: break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b''.join(chunks)
        after = os.fstat(fd)
        current = os.lstat(path)
        if len(data) > INPUT_LIMIT or len(data) != opened.st_size or not stat.S_ISREG(current.st_mode) or identity(opened) != identity(after) or identity(after) != identity(current):
            raise CaseError('input changed or exceeded limit')
        return data
    finally:
        os.close(fd)

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
            raw = read_input(args.input)
            data = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(CaseError('non-finite JSON number')))
            result = {'create': create_case, 'scope': update_scope, 'import-run': import_run, 'decision': record_decision, 'run': run_collector, 'cancel': cancel_case, 'reopen': reopen_case, 'transition': transition_case, 'action': record_action, 'verification': record_verification}[args.command](args.case, data)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (CaseError, OSError, ValueError, KeyError, RecursionError) as exc:
        print('case: ' + str(exc), file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
