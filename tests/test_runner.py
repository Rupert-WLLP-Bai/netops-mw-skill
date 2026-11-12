from __future__ import annotations

import os
import sys
import time
import unittest

from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "skills" / "internet-access-triage" / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from netops.runner import Deadline, run_command


class RunnerTests(unittest.TestCase):
    def test_timeout_terminates_and_reaps_direct_child(self) -> None:
        started = time.monotonic()
        result = run_command([sys.executable, "-c", "import time; time.sleep(10)"],
                             Deadline(2), 1024, 1024, timeout_seconds=0.3)
        self.assertEqual(result.status, "timeout")
        self.assertIsNotNone(result.returncode)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_stdout_limit_terminates_noisy_process_and_bounds_retained_bytes(self) -> None:
        code = "import os; block=b'x'*8192;\nwhile True: os.write(1, block)"
        started = time.monotonic()
        result = run_command([sys.executable, "-c", code], Deadline(2), 65536, 1024)
        self.assertEqual(result.status, "partial")
        self.assertEqual(len(result.stdout), 65536)
        self.assertTrue(result.stdout_truncated)
        self.assertLess(time.monotonic() - started, 1.5)

    @unittest.skipUnless(os.name == "posix", "process group cleanup is platform-specific")
    def test_exited_parent_does_not_leave_descendant_holding_pipe_open(self) -> None:
        child_code = "import time; time.sleep(30)"
        parent_code = (
            "import subprocess,sys; "
            f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
            "print(p.pid, flush=True)"
        )
        started = time.monotonic()
        result = run_command([sys.executable, "-c", parent_code], Deadline(0.4), 1024, 1024)
        elapsed = time.monotonic() - started
        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.error_kind, "descendant_kept_pipe_open")
        self.assertLess(elapsed, 1.2)
        child_pid = int(result.stdout.decode("ascii").strip())
        proc_stat = Path(f"/proc/{child_pid}/stat")
        end = time.monotonic() + 0.5
        while proc_stat.exists() and time.monotonic() < end:
            try:
                state = proc_stat.read_text(encoding="ascii").split()[2]
            except (OSError, IndexError):
                break
            if state == "Z":
                break
            time.sleep(0.02)
        if proc_stat.exists():
            try:
                self.assertEqual(proc_stat.read_text(encoding="ascii").split()[2], "Z")
            except (OSError, IndexError):
                pass

    def test_missing_executable_is_unsupported_without_process_start(self) -> None:
        result = run_command(["netops-tool-that-does-not-exist"], Deadline(1), 100, 100)
        self.assertEqual(result.status, "unsupported")
        self.assertFalse(result.process_started)


if __name__ == "__main__":
    unittest.main()
