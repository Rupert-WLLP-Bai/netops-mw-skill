"""Subprocess execution with wall-clock and captured-output limits."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


class Deadline:
    def __init__(self, seconds: float) -> None:
        self.started = time.monotonic()
        self.end = self.started + seconds

    def remaining(self) -> float:
        return max(0.0, self.end - time.monotonic())

    def elapsed_ns(self) -> int:
        return int((time.monotonic() - self.started) * 1_000_000_000)


@dataclass
class CommandResult:
    args: list[str]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    duration_ns: int
    status: str
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    error_kind: str | None = None
    process_started: bool = False


def _terminate_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=2, check=False)
        except (OSError, subprocess.SubprocessError):
            pass
        if process.poll() is None:
            process.kill()
    else:
        # The direct child may have exited while a descendant still holds a pipe.
        # Its process group remains addressable by the original session leader PID.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                process.terminate()
            except OSError:
                pass
        grace_end = time.monotonic() + 0.12
        while time.monotonic() < grace_end:
            try:
                os.killpg(process.pid, 0)
            except (ProcessLookupError, PermissionError):
                break
            time.sleep(0.01)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            process.wait(timeout=0.12)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=0.12)
            except (OSError, subprocess.TimeoutExpired):
                pass


def _drain(pipe, limit: int, target: bytearray, overflow: threading.Event,
           truncate_event: threading.Event) -> None:
    try:
        while True:
            block = pipe.read(65536)
            if not block:
                break
            room = max(0, limit - len(target))
            if room:
                target.extend(block[:room])
            if len(block) > room:
                truncate_event.set()
                overflow.set()
    finally:
        try:
            pipe.close()
        except OSError:
            pass


def run_command(args: Sequence[str], deadline: Deadline, stdout_limit: int,
                stderr_limit: int, timeout_seconds: float | None = None,
                env: Mapping[str, str] | None = None,
                cwd: Path | None = None) -> CommandResult:
    """Run one argv command, drain bounded pipes, then terminate and reap on limits."""
    started = time.monotonic()
    remaining = deadline.remaining()
    if remaining <= 0:
        return CommandResult(list(args), None, b"", b"", 0, "budget_exhausted", error_kind="deadline")
    timeout = min(remaining, timeout_seconds) if timeout_seconds is not None else remaining
    popen_kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": dict(env) if env is not None else None,
        "cwd": str(cwd) if cwd else None,
        "shell": False,
        "bufsize": 0,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(list(args), **popen_kwargs)
    except FileNotFoundError:
        return CommandResult(list(args), None, b"", b"", int((time.monotonic() - started) * 1e9),
                             "unsupported", error_kind="executable_not_found")
    except PermissionError:
        return CommandResult(list(args), None, b"", b"", int((time.monotonic() - started) * 1e9),
                             "permission_denied", error_kind="permission_denied")
    except OSError as error:
        kind = "permission_denied" if getattr(error, "errno", None) in (1, 13) else "tool_error"
        return CommandResult(list(args), None, b"", str(error).encode("utf-8", "replace")[:stderr_limit],
                             int((time.monotonic() - started) * 1e9), kind, error_kind="spawn_error")

    stdout, stderr = bytearray(), bytearray()
    overflow = threading.Event()
    out_truncated, err_truncated = threading.Event(), threading.Event()
    out_thread = threading.Thread(target=_drain, args=(process.stdout, stdout_limit, stdout, overflow, out_truncated), daemon=True)
    err_thread = threading.Thread(target=_drain, args=(process.stderr, stderr_limit, stderr, threading.Event(), err_truncated), daemon=True)
    out_thread.start()
    err_thread.start()
    status = "complete"
    error_kind = None
    hard_end = started + timeout
    try:
        end = started + timeout
        while process.poll() is None:
            if overflow.is_set():
                status = "partial"
                error_kind = "stdout_limit"
                _terminate_tree(process)
                break
            if time.monotonic() >= end:
                status = "timeout" if deadline.remaining() > 0.001 else "budget_exhausted"
                error_kind = "timeout" if status == "timeout" else "deadline"
                _terminate_tree(process)
                break
            time.sleep(0.01)
        if process.poll() is None:
            _terminate_tree(process)
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                pass
        # A completed parent can leave grandchildren holding inherited stdout or
        # stderr open. Treat that as an unfinished command and clean its group.
        drain_grace_end = min(hard_end, time.monotonic() + 0.08)
        while (out_thread.is_alive() or err_thread.is_alive()) and time.monotonic() < drain_grace_end:
            time.sleep(0.005)
        if out_thread.is_alive() or err_thread.is_alive():
            if status == "complete":
                status, error_kind = "timeout", "descendant_kept_pipe_open"
            _terminate_tree(process)
    finally:
        join_limit = min(0.2, max(0.01, deadline.remaining() + 0.1))
        out_thread.join(timeout=join_limit)
        err_thread.join(timeout=join_limit)
    if overflow.is_set() and status == "complete":
        status, error_kind = "partial", "stdout_limit"
    if out_thread.is_alive() or err_thread.is_alive():
        _terminate_tree(process)
    return CommandResult(list(args), process.returncode, bytes(stdout), bytes(stderr),
                         int((time.monotonic() - started) * 1e9), status,
                         out_truncated.is_set(), err_truncated.is_set(), error_kind, True)
