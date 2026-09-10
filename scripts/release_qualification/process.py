"""Supervise a command, bound its output, and retain measured child CPU time."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from .records import MAX_LOG_BYTES, QualificationError, file_digest, sync_directory


def execute(argv: list[str], cwd: Path, environment: dict[str, str], log: Path,
            timeout_seconds: int, maximum_log_bytes: int = MAX_LOG_BYTES) -> dict[str, Any]:
    """Always reap the leader and terminate its process group before returning.

    wait4 measures CPU consumed by the child and descendants it waited for.
    Drivers must join their workers; elapsed wall time never substitutes for
    the per-target fuzz CPU budget.
    """
    descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    started = time.monotonic_ns()
    failure = None
    written = 0
    child = None
    usage = None
    status = None
    exited_at = None
    with os.fdopen(descriptor, "wb", buffering=0) as output, selectors.DefaultSelector() as poller:
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     start_new_session=True)
            if child.stdout is None:
                raise QualificationError("child output pipe is absent")
            os.set_blocking(child.stdout.fileno(), False)
            poller.register(child.stdout, selectors.EVENT_READ)
            while True:
                elapsed = (time.monotonic_ns() - started) / 1_000_000_000
                if failure is None and elapsed >= timeout_seconds:
                    failure = "timeout"
                if failure is not None:
                    terminate_group(child.pid)
                if status is None:
                    pid, child_status, measured = os.wait4(child.pid, os.WNOHANG)
                    if pid:
                        status, usage = child_status, measured
                        child.returncode = os.waitstatus_to_exitcode(status)
                        exited_at = time.monotonic_ns()
                        # Descendants holding stdout open must not outlive their driver.
                        terminate_group(child.pid)
                if exited_at is not None and poller.get_map() and time.monotonic_ns() - exited_at > 10**9:
                    failure = "unjoined_output_owner"
                    break
                for key, _ in poller.select(0.1):
                    data = os.read(key.fd, 65536)
                    if not data:
                        poller.unregister(key.fileobj)
                        continue
                    available = maximum_log_bytes - written
                    output.write(data[:available])
                    written += min(len(data), available)
                    if len(data) > available:
                        failure = "log_limit"
                if status is not None and not poller.get_map():
                    break
        except (KeyboardInterrupt, SystemExit):
            failure = "interrupted"
        except OSError as error:
            failure = "execution_error"
            diagnostic = f"command could not run: errno={error.errno}\n".encode()
            output.write(diagnostic[:maximum_log_bytes - written])
        finally:
            if child is not None:
                terminate_group(child.pid)
                if status is None:
                    _, status, usage = os.wait4(child.pid, 0)
                    child.returncode = os.waitstatus_to_exitcode(status)
                if child.stdout is not None:
                    child.stdout.close()
            os.fsync(output.fileno())
    sync_directory(log.parent)
    elapsed_ns = time.monotonic_ns() - started
    return {
        "exit_code": os.waitstatus_to_exitcode(status) if status is not None else None,
        "failure": failure,
        "elapsed_ns": elapsed_ns,
        "cpu_user_ns": int(usage.ru_utime * 1_000_000_000) if usage else 0,
        "cpu_system_ns": int(usage.ru_stime * 1_000_000_000) if usage else 0,
        "maximum_rss_kib": int(usage.ru_maxrss) if usage else 0,
        "log_sha256": file_digest(log),
        "log_bytes": log.stat().st_size,
    }


def terminate_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
