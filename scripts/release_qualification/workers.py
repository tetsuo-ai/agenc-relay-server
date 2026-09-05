"""Supervise a bounded group of sibling workers and account for every child's CPU."""

from __future__ import annotations

import os
import selectors
import time
from pathlib import Path
from typing import Any

from .process import terminate_group
from .records import MAX_LOG_BYTES, QualificationError, file_digest, sync_directory

MAX_GROUP_WORKERS = 64


class _Worker:
    def __init__(self, index: int, argv: list[str], log: Path) -> None:
        self.index = index
        self.argv = argv
        self.log = log
        self.child = None
        self.output = None
        self.written = 0
        self.failure: str | None = None
        self.status: int | None = None
        self.usage = None
        self.exited_at: int | None = None
        self.pipe_open = False


def execute_group(commands: list[tuple[list[str], Path]], cwd: Path, environment: dict[str, str],
                  timeout_seconds: int, maximum_log_bytes: int = MAX_LOG_BYTES) -> list[dict[str, Any]]:
    """Run every command at once, bound each log, and join every child before returning.

    Each child runs in its own session. The first child that exits with a
    failure, exceeds its log bound, or outlives the timeout terminates the
    whole group, but every child is still reaped with ``wait4`` so its CPU
    time is charged to this process and, through it, to the release runner.
    """
    if not commands or len(commands) > MAX_GROUP_WORKERS:
        raise QualificationError("worker group size is outside its bound")
    import subprocess

    workers = [_Worker(index, argv, log) for index, (argv, log) in enumerate(commands)]
    started = time.monotonic_ns()
    group_failure: str | None = None
    with selectors.DefaultSelector() as poller:
        try:
            for worker in workers:
                descriptor = os.open(worker.log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                worker.output = os.fdopen(descriptor, "wb", buffering=0)
            for worker in workers:
                try:
                    worker.child = subprocess.Popen(worker.argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                                    start_new_session=True)
                except OSError as error:
                    worker.failure = "execution_error"
                    worker.output.write(f"worker could not run: errno={error.errno}\n".encode()[:maximum_log_bytes])
                    continue
                if worker.child.stdout is None:
                    raise QualificationError("worker output pipe is absent")
                os.set_blocking(worker.child.stdout.fileno(), False)
                poller.register(worker.child.stdout, selectors.EVENT_READ, worker)
                worker.pipe_open = True
            if any(worker.failure == "execution_error" for worker in workers):
                group_failure = "execution_error"
            while True:
                elapsed = (time.monotonic_ns() - started) / 1_000_000_000
                if group_failure is None and elapsed >= timeout_seconds:
                    group_failure = "timeout"
                if group_failure is not None:
                    for worker in workers:
                        if worker.child is not None:
                            if worker.failure is None and worker.status is None:
                                worker.failure = group_failure
                            terminate_group(worker.child.pid)
                for worker in workers:
                    if worker.child is None or worker.status is not None:
                        continue
                    pid, child_status, measured = os.wait4(worker.child.pid, os.WNOHANG)
                    if pid:
                        worker.status, worker.usage = child_status, measured
                        worker.child.returncode = os.waitstatus_to_exitcode(child_status)
                        worker.exited_at = time.monotonic_ns()
                        terminate_group(worker.child.pid)
                        if worker.child.returncode != 0 and group_failure is None:
                            group_failure = "worker_failed"
                for worker in workers:
                    if worker.exited_at is not None and worker.pipe_open and time.monotonic_ns() - worker.exited_at > 10**9:
                        worker.failure = worker.failure or "unjoined_output_owner"
                        poller.unregister(worker.child.stdout)
                        worker.pipe_open = False
                for key, _ in poller.select(0.1):
                    worker = key.data
                    data = os.read(key.fd, 65536)
                    if not data:
                        poller.unregister(key.fileobj)
                        worker.pipe_open = False
                        continue
                    available = maximum_log_bytes - worker.written
                    worker.output.write(data[:available])
                    worker.written += min(len(data), available)
                    if len(data) > available:
                        worker.failure = "log_limit"
                        group_failure = group_failure or "log_limit"
                if all(worker.child is None or (worker.status is not None and not worker.pipe_open) for worker in workers):
                    break
        except (KeyboardInterrupt, SystemExit):
            group_failure = "interrupted"
            for worker in workers:
                if worker.failure is None:
                    worker.failure = "interrupted"
        finally:
            for worker in workers:
                if worker.child is not None:
                    terminate_group(worker.child.pid)
                    if worker.status is None:
                        _, worker.status, worker.usage = os.wait4(worker.child.pid, 0)
                        worker.child.returncode = os.waitstatus_to_exitcode(worker.status)
                    if worker.child.stdout is not None:
                        worker.child.stdout.close()
                if worker.output is not None:
                    os.fsync(worker.output.fileno())
                    worker.output.close()
    sync_directory(commands[0][1].parent)
    elapsed_ns = time.monotonic_ns() - started
    results = []
    for worker in workers:
        usage = worker.usage
        results.append({
            "index": worker.index,
            "argv": worker.argv,
            "exit_code": os.waitstatus_to_exitcode(worker.status) if worker.status is not None else None,
            "failure": worker.failure,
            "elapsed_ns": elapsed_ns,
            "cpu_user_ns": int(usage.ru_utime * 1_000_000_000) if usage else 0,
            "cpu_system_ns": int(usage.ru_stime * 1_000_000_000) if usage else 0,
            "maximum_rss_kib": int(usage.ru_maxrss) if usage else 0,
            "log_sha256": file_digest(worker.log),
            "log_bytes": worker.log.stat().st_size,
        })
    return results
