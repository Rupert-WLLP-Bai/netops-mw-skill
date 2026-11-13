#!/usr/bin/env python3
"""Restore the pinned, unfinished network-suite handoff without overwriting files."""
from __future__ import annotations
import argparse
import hashlib
import os
import shutil
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

CORPUS_SHA256 = 'e1986f9de2bb2e5c572076d3356ed56b08bdcb3c6c88e6dd80b2a0d130b0ba83'
EVIDENCE_SHA256 = '2f1eaf6b8093ed480b82d5858bc8290892a06481a6d39bad02513569c8d7ddee'
CORPUS_FILES = ('.tools/pcap-corpus/derived/lab-omit.pcapng', '.tools/pcap-corpus/derived/lab-snap96.pcapng', '.tools/pcap-corpus/derived/slow-omit.pcapng', '.tools/pcap-corpus/derived/slow-snap96.pcapng', '.tools/pcap-corpus/derived/web-omit.pcapng', '.tools/pcap-corpus/derived/web-snap96.pcapng', '.tools/pcap-corpus/downloads/download-slow.pcapng', '.tools/pcap-corpus/downloads/lotsofweb.pcapng', '.tools/pcap-corpus/downloads/own_traffic_capture_01.pcap', '.tools/pcap-corpus/NOTICES/chris-sanders-README.md', '.tools/pcap-corpus/NOTICES/omar-babba-LICENSE.txt', '.tools/pcap-corpus/HANDOFF-PROVENANCE.json', '.tools/pcap-corpus/SHA256SUMS.txt')
EVIDENCE_FILES = ('.tools/network-suite/evaluations/packet-baseline/answer.md', '.tools/network-suite/evaluations/packet-baseline/actions.json', '.tools/network-suite/evaluations/packet-suite/answer.md', '.tools/network-suite/evaluations/packet-suite/actions.json', '.tools/network-suite/evaluations/recovery-baseline/answer.md', '.tools/network-suite/evaluations/recovery-baseline/actions.json', '.tools/network-suite/evaluations/recovery-terra-baseline/answer.md', '.tools/network-suite/evaluations/recovery-terra-baseline/actions.json', '.tools/network-suite/evaluations/recovery-terra-suite/answer.md', '.tools/network-suite/evaluations/recovery-terra-suite/actions.json', '.tools/network-suite/evaluations/unknown-baseline/answer.md', '.tools/network-suite/evaluations/unknown-baseline/actions.json', '.tools/network-suite/evaluations/unknown-suite/answer.md', '.tools/network-suite/evaluations/unknown-suite/actions.json', '.tools/network-suite/evaluations/unknown-suite-clean/answer.md', '.tools/network-suite/evaluations/unknown-suite-clean/actions.json', '.tools/network-suite/task7-tests-complete.log', '.tools/network-suite/extracted-lifecycle-tests-final.log', '.tools/network-suite/extracted-suite-smoke.json', '.tools/network-suite/paired-tls-check.json', '.tools/network-suite/sol-review/repro-results.json', '.tools/network-suite/sol-review/reproduce-original.txt', '.tools/network-suite/sol-review/reproduce-portable.py', '.tools/network-suite/corpus-validation-summary.json', '.tools/network-suite/RESTORED-EVIDENCE.md', '.tools/network-suite/sol-review/final-review.md', '.tools/network-suite/sol-review/unittest.log', '.tools/network-suite/sol-review/verification.json', '.tools/network-suite/sol-review/build-a.json', '.tools/network-suite/sol-review/build-b.json', '.tools/network-suite/evaluations/recovery-baseline/inputs/record-a.json', '.tools/network-suite/evaluations/recovery-baseline/inputs/record-b.json', '.tools/network-suite/evaluations/recovery-baseline/inputs/observation-0.txt', '.tools/network-suite/evaluations/recovery-baseline/inputs/observation-1.txt', '.tools/network-suite/evaluations/recovery-baseline/inputs/observation-2.txt', '.tools/network-suite/evaluations/recovery-baseline/inputs/observation-3.txt', '.tools/network-suite/evaluations/recovery-baseline/inputs/observation-4.txt', '.tools/network-suite/evaluations/recovery-baseline/inputs/imports/check-check0/artifact', '.tools/network-suite/evaluations/recovery-baseline/inputs/imports/check-check1/artifact', '.tools/network-suite/evaluations/recovery-baseline/inputs/imports/check-check2/artifact', '.tools/network-suite/evaluations/recovery-baseline/inputs/imports/check-check3/artifact', '.tools/network-suite/evaluations/recovery-baseline/inputs/imports/check-check4/artifact', '.tools/network-suite/evaluations/unknown-baseline/inputs/record.json', '.tools/network-suite/HANDOFF-EVIDENCE-MANIFEST.json', '.tools/network-suite/HANDOFF-EVIDENCE-SHA256SUMS.txt')


def digest(path):
    sha = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            sha.update(block)
    return sha.hexdigest()

def restore(archive_path, destination, expected_hash, expected_names):
    if digest(archive_path) != expected_hash:
        raise ValueError('archive SHA-256 mismatch: ' + str(archive_path))
    if destination.is_symlink() or not destination.is_dir():
        raise ValueError('destination must be a real existing directory')
    root = destination.resolve()
    created_files = []
    created_dirs = []
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            if len(infos) != len(expected_names) or set(i.filename for i in infos) != set(expected_names):
                raise ValueError('archive contents differ from the allowlist')
            if sum(info.file_size for info in infos) > 80 * 1024 * 1024:
                raise ValueError('archive exceeds the extraction limit')
            for info in infos:
                path = PurePosixPath(info.filename)
                if path.is_absolute() or path.as_posix() != info.filename or '..' in path.parts or '\\' in info.filename or not stat.S_ISREG(info.external_attr >> 16):
                    raise ValueError('unsafe archive member: ' + info.filename)
                target = root.joinpath(*path.parts)
                if target.exists() or target.is_symlink():
                    raise ValueError('refusing to overwrite: ' + str(target))
                for parent in reversed(target.parents):
                    if parent == root or root not in parent.parents:
                        continue
                    if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
                        raise ValueError('unsafe destination directory: ' + str(parent))
            for info in infos:
                target = root.joinpath(*PurePosixPath(info.filename).parts)
                for parent in reversed(target.parents):
                    if parent == root or root not in parent.parents:
                        continue
                    if not parent.exists():
                        parent.mkdir(mode=0o700)
                        created_dirs.append(parent)
                    if parent.is_symlink() or not parent.is_dir():
                        raise ValueError('unsafe destination directory: ' + str(parent))
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
                fd = os.open(str(target), flags, 0o600)
                created_files.append(target)
                with os.fdopen(fd, 'wb') as out, archive.open(info) as source:
                    shutil.copyfileobj(source, out, length=1024 * 1024)
    except Exception:
        for path in reversed(created_files):
            path.unlink(missing_ok=True)
        for path in reversed(created_dirs):
            try: path.rmdir()
            except OSError: pass
        raise
    print('Restored', len(expected_names), 'verified files from', archive_path.name)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--destination', type=Path, default=Path('.'))
    args = parser.parse_args()
    if not args.corpus and not args.evidence:
        parser.error('supply --corpus and/or --evidence')
    try:
        if args.corpus: restore(args.corpus, args.destination, CORPUS_SHA256, CORPUS_FILES)
        if args.evidence: restore(args.evidence, args.destination, EVIDENCE_SHA256, EVIDENCE_FILES)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print('handoff restore failed: ' + str(exc), file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
