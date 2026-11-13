#!/usr/bin/env python3
"""Analyze supplied offline transport evidence without collecting or changing it."""
import argparse
import json
import os
import sys
from pathlib import Path
from case_runtime.transport import analyze_bounded, LIMIT
from case_runtime.evidence import read_confined
from case_runtime.store import CaseError


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,required=True)
    args=parser.parse_args()
    try:
        path=Path(os.path.abspath(args.input))
        result=analyze_bounded(read_confined(path.parent,path.name,LIMIT))
        print(json.dumps(result,ensure_ascii=False,sort_keys=True,allow_nan=False))
        return 0
    except (CaseError,OSError,ValueError,RuntimeError,RecursionError):
        print('transport: invalid input or unavailable evidence',file=sys.stderr)
        return 1


if __name__=='__main__':
    sys.exit(main())
