"""Focused M6 isolation checks; run only after the M6 artifact freeze."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evaluation.carrier import isolation


REPO = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith('linux'), 'M6 launcher supports Linux only')
class CarrierIsolationTests(unittest.TestCase):
    def _roots(self, root: Path):
        visible = root / 'visible'
        code = root / 'copied-code'
        writable = root / 'trial-tmp'
        for path in (visible, code, writable):
            path.mkdir()
        return visible, code, writable

    def test_oracle_and_sibling_are_unreadable_and_unmodifiable_after_exec(self):
        """Check real blocked paths in the launcher and one inherited exec child."""
        with tempfile.TemporaryDirectory(prefix='carrier-isolation-') as temp:
            root = Path(temp)
            visible, code, writable = self._roots(root)
            oracle_root = root / 'oracle-private'
            sibling_root = root / 'sibling-private'
            oracle_root.mkdir()
            sibling_root.mkdir()
            oracle = oracle_root / 'expected.json'
            sibling = sibling_root / 'case.json'
            control = visible / 'control.txt'
            oracle.write_text('{"secret":"parent-only"}', encoding='utf-8')
            sibling.write_text('{"sibling":"private"}', encoding='utf-8')
            control.write_text('visible control', encoding='utf-8')
            before = {path: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
                      for path in (oracle, sibling)}
            helper = (
                'import ctypes,errno,fcntl,json,os,socket,sys\n'
                'def denied(fn):\n'
                ' try: fn(); return False\n'
                ' except OSError as exc: return exc.errno in (errno.EACCES,errno.EPERM)\n'
                'def ioctl_controls(control):\n'
                ' fd=os.open(control,os.O_RDONLY)\n'
                ' try:\n'
                '  allowed=fcntl.ioctl(fd,0x5451)==0\n'
                '  try: fcntl.ioctl(fd,0x5452); other_denied=False\n'
                '  except OSError as exc: other_denied=exc.errno==errno.EPERM\n'
                '  return allowed,other_denied\n'
                ' finally: os.close(fd)\n'
                'def attempts(oracle,sibling,control):\n'
                ' return {"read":denied(lambda:open(oracle).read()),'
                '"truncate":denied(lambda:os.open(oracle,os.O_WRONLY|os.O_TRUNC)),'
                '"unlink":denied(lambda:os.unlink(sibling)),'
                '"chmod":denied(lambda:os.chmod(oracle,0o600)),'
                '"socket":denied(lambda:socket.socket()),'
                '"io_uring":(lambda r: r == -1 and ctypes.get_errno() in '
                '(errno.EPERM,errno.ENOSYS))(ctypes.CDLL(None,use_errno=True).syscall(425,1,None)), '
                '"ioctl_fioclex,ioctl_other":ioctl_controls(control)}\n')
            child = code / 'child.py'
            child.write_text(helper + 'print(json.dumps(attempts(*sys.argv[1:4])))\n',
                             encoding='utf-8')
            probe = code / 'probe.py'
            probe.write_text(
                helper +
                'import subprocess\n'
                'oracle,sibling=sys.argv[1:3]; control=sys.argv[4]\n'
                'direct=attempts(oracle,sibling,control)\n'
                'child=subprocess.run([sys.executable,"-B","-I","-S",sys.argv[3],'
                'oracle,sibling,control],capture_output=True,text=True,timeout=8)\n'
                'print(json.dumps({"direct":direct,"child":json.loads(child.stdout)}))\n',
                encoding='utf-8')
            result = isolation.run_isolated(
                [sys.executable, '-I', '-S', str(probe), str(oracle), str(sibling),
                 str(child), str(control)],
                read_roots=[visible, code], write_root=writable,
                blocked_roots=[REPO, oracle_root, sibling_root], timeout_seconds=15,
                output_limit_bytes=65536)
            self.assertEqual(result['status'], 'ok', result['reason'])
            report = json.loads(result['stdout'])
            self.assertEqual(report['direct'],
                             {'read': True, 'truncate': True, 'unlink': True, 'chmod': True,
                              'socket': True, 'io_uring': True,
                              'ioctl_fioclex,ioctl_other': [True, True]})
            self.assertEqual(report['child'],
                             {'read': True, 'truncate': True, 'unlink': True, 'chmod': True,
                              'socket': True, 'io_uring': True,
                              'ioctl_fioclex,ioctl_other': [True, True]})
            for path, expected in before.items():
                self.assertEqual((path.read_bytes(), path.stat().st_mode,
                                  path.stat().st_mtime_ns), expected)

    def test_actual_copied_access_provider_runs_inside_boundary(self):
        """Use an independently materialized visible M3 task and copied real CLI."""
        from evaluation.carrier.corpus import materialize_case

        with tempfile.TemporaryDirectory(prefix='carrier-provider-isolation-') as temp:
            root = Path(temp)
            case = materialize_case(REPO, 'case-001', root / 'work')
            oracle_root = root / 'oracle-private'
            oracle_root.mkdir()
            (oracle_root / 'expected.json').write_text(
                json.dumps(case['oracle'], sort_keys=True), encoding='utf-8')
            code = root / 'copied-code'
            code.mkdir()
            for source in (REPO / 'evaluation' / 'carrier').glob('*.py'):
                shutil.copy2(source, code / source.name)
            product = root / 'copied-product'
            (product / 'scripts').mkdir(parents=True)
            source_scripts = REPO / 'skills' / 'netops-incident' / 'scripts'
            for name in ('diagnose_access.py', 'diagnose_transport.py', 'review_service.py'):
                shutil.copy2(source_scripts / name, product / 'scripts' / name)
            shutil.copytree(source_scripts / 'case_runtime',
                            product / 'scripts' / 'case_runtime')
            shutil.copytree(REPO / 'skills' / 'netops-incident' / 'schemas',
                            product / 'schemas')
            writable = root / 'trial-tmp'
            writable.mkdir()
            result = isolation.run_isolated(
                [sys.executable, '-I', '-S', str(code / 'adapter.py'), '--task',
                 str(case['task_path']), '--product', str(product)],
                read_roots=[code, product, case['visible_root']],
                write_root=writable, blocked_roots=[REPO, oracle_root], timeout_seconds=90,
                output_limit_bytes=2 * 1024 * 1024)
            self.assertEqual(result['status'], 'ok', result['reason'])
            answer = json.loads(result['stdout'])
            self.assertEqual(answer['completion'], 'complete')
            self.assertEqual(answer['jobs'][0]['job_id'], 'job-01')
            self.assertEqual(answer['jobs'][0]['completion'], 'complete')
            self.assertIsInstance(answer['jobs'][0]['raw_result'], dict)
            self.assertTrue((oracle_root / 'expected.json').is_file())

    def test_parent_rejects_read_grant_that_covers_private_root(self):
        with tempfile.TemporaryDirectory(prefix='carrier-grant-check-') as temp:
            root = Path(temp)
            broad = root / 'broad'
            blocked = broad / 'oracle'
            blocked.mkdir(parents=True)
            writable = root / 'tmp'
            writable.mkdir()
            with self.assertRaises(ValueError):
                isolation._policy([broad], writable, [blocked])

    def test_timeout_and_output_cap_kill_the_whole_trial_group(self):
        import time

        with tempfile.TemporaryDirectory(prefix='carrier-launcher-limits-') as temp:
            root = Path(temp)
            visible, code, writable = self._roots(root)
            oversized = code / 'oversized.py'
            oversized.write_text('print("x" * 100000)\n', encoding='utf-8')
            capped = isolation.run_isolated(
                [sys.executable, '-B', '-I', '-S', str(oversized)],
                read_roots=[visible, code], write_root=writable, blocked_roots=[REPO],
                output_limit_bytes=1024, timeout_seconds=5)
            self.assertEqual(capped['status'], 'output_limit')

            marker = writable / 'late-child-write'
            child = code / 'late-child.py'
            child.write_text(
                'import pathlib,sys,time; time.sleep(3); '
                'pathlib.Path(sys.argv[1]).write_text("late")\n', encoding='utf-8')
            sleeper = code / 'sleeper.py'
            sleeper.write_text(
                'import subprocess,sys,time; print("started",flush=True); '
                'subprocess.Popen([sys.executable,"-B","-I","-S",sys.argv[1],sys.argv[2]]); '
                'time.sleep(10)\n', encoding='utf-8')
            timed = isolation.run_isolated(
                [sys.executable, '-B', '-I', '-S', str(sleeper), str(child), str(marker)],
                read_roots=[visible, code], write_root=writable, blocked_roots=[REPO],
                output_limit_bytes=65536, timeout_seconds=2.5)
            self.assertEqual(timed['status'], 'timeout')
            self.assertIn('started', timed['stdout'])
            time.sleep(3.2)
            self.assertFalse(marker.exists())

    def test_setup_failure_seam_never_launches_candidate(self):
        with tempfile.TemporaryDirectory(prefix='carrier-setup-failure-') as temp:
            root = Path(temp)
            visible, code, writable = self._roots(root)
            bootstrap = root / 'setup-failure.py'
            bootstrap.write_text(
                'import sys; sys.stderr.write("isolation_unavailable:injected\\n"); sys.exit(125)\n',
                encoding='utf-8')
            marker = root / 'must-not-exist'
            with mock.patch.object(isolation, '_BOOTSTRAP', bootstrap):
                result = isolation.run_isolated(
                    [sys.executable, '-c',
                     'from pathlib import Path; Path(%r).write_text("launched")' % str(marker)],
                    read_roots=[visible, code], write_root=writable,
                    blocked_roots=[REPO], timeout_seconds=5)
            self.assertEqual(result['status'], 'isolation_unavailable')
            self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
