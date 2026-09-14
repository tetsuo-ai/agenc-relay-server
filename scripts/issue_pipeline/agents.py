"""Fresh, sandboxed Codex sessions with bounded logs and independent validation.

Production must enable ``use_systemd``: process groups alone cannot contain a
descendant that calls setsid(). Structured results are claims, never gate authority.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path, PurePosixPath
import selectors
import shutil
import signal
import subprocess
import threading
import time
import uuid

from .prompts import build_prompt


MAX_RESULT_BYTES = 1024 * 1024
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_EVENT_BYTES = 2 * 1024 * 1024
_GLOBAL_SESSIONS = threading.BoundedSemaphore(4)
_ROLES = frozenset({"planner", "worker", "reviewer"})
_SCHEMAS = Path(__file__).with_name("schemas")


class AgentRunError(RuntimeError):
    """A session failed closed; logs remain in ``output_dir``."""

    def __init__(self, kind: str, message: str, output_dir: Path):
        super().__init__(message)
        self.kind = kind
        self.output_dir = Path(output_dir)


def _object(value, keys, where):
    if type(value) is not dict or set(value) != set(keys.split()):
        raise ValueError(f"{where}: expected exactly these keys: {keys}")


def _string(value, where, limit=16384):
    if type(value) is not str or not value.strip() or len(value) > limit:
        raise ValueError(f"{where}: expected nonempty string of at most {limit} characters")
    if any(ord(char) < 32 and char not in "\n\t" for char in value):
        raise ValueError(f"{where}: forbidden control character")


def _list(value, where, maximum=256, minimum=0):
    if type(value) is not list or not minimum <= len(value) <= maximum:
        raise ValueError(f"{where}: expected list length {minimum}..{maximum}")


def _strings(value, where, minimum=0, maximum=256):
    _list(value, where, maximum, minimum)
    for item in value:
        _string(item, where)
    if len(set(value)) != len(value):
        raise ValueError(f"{where}: duplicate entries")


def _enum(value, options, where):
    if type(value) is not str or value not in options:
        raise ValueError(f"{where}: unexpected value")


def _boolean(value, where):
    if type(value) is not bool:
        raise ValueError(f"{where}: expected boolean")


def _path(value, worktree, where):
    _string(value, where, 1024)
    parts = value.split("/")
    if (
        PurePosixPath(value).is_absolute()
        or any(part in {"", ".", "..", ".git"} for part in parts)
        or any(char in value for char in "\\*?[]:\n\r\t")
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError(f"{where}: expected exact normalized repository-relative file path")
    if worktree is not None:
        root = Path(worktree).resolve(strict=True)
        candidate = root.joinpath(*parts)
        if not candidate.resolve().is_relative_to(root) or candidate.is_dir():
            raise ValueError(f"{where}: path escapes worktree or names a directory")


def _argv(value, where):
    _list(value, where, maximum=64, minimum=1)
    for arg in value:
        _string(arg, where, 4096)
        if any(ord(char) < 32 for char in arg):
            raise ValueError(f"{where}: argument contains control characters")
    if sum(len(arg.encode("utf-8")) for arg in value) > 32768:
        raise ValueError(f"{where}: command exceeds 32 KiB")


def validate_result(role: str, value: object, worktree: Path | None = None) -> dict:
    """Validate closed structures and role invariants, independently of JSON Schema.

    Commands are bounded proposals/claims, not an execution allowlist. The
    controller must authorize any command separately. Paths are checked against
    worktree symlinks when a worktree is supplied.
    """
    if role not in _ROLES:
        raise ValueError("unknown agent role")
    if role == "planner":
        _object(value, "status summary phases blockers", role)
        _enum(value["status"], {"planned", "blocked"}, "status")
        _strings(value["blockers"], "blockers")
        _list(value["phases"], "phases", 32)
        names = set()
        noncontract_seen = False
        for phase in value["phases"]:
            _object(phase, "name kind files acceptance validation", "phase")
            _string(phase["name"], "phase.name", 128)
            if phase["name"] in names:
                raise ValueError("duplicate phase name")
            names.add(phase["name"])
            _enum(phase["kind"], {"contract", "implementation", "evidence"}, "phase.kind")
            if phase["kind"] == "contract" and noncontract_seen:
                raise ValueError("contract phases must precede implementation and evidence")
            noncontract_seen = noncontract_seen or phase["kind"] != "contract"
            _strings(phase["files"], "phase.files", minimum=1, maximum=512)
            for path in phase["files"]:
                _path(path, worktree, "phase.files")
            _strings(phase["acceptance"], "phase.acceptance", minimum=1)
            _list(phase["validation"], "phase.validation", maximum=64, minimum=1)
            for argv in phase["validation"]:
                _argv(argv, "phase.validation")
        if value["status"] == "planned" and (not value["phases"] or value["blockers"]):
            raise ValueError("planned result requires phases and no blockers")
        if value["status"] == "blocked" and not value["blockers"]:
            raise ValueError("blocked plan must explain blockers")
    elif role == "worker":
        _object(value, "status summary acceptance tests discoveries needs_new_phase", role)
        _enum(value["status"], {"complete", "blocked"}, "status")
        _boolean(value["needs_new_phase"], "needs_new_phase")
        _list(value["acceptance"], "acceptance")
        for item in value["acceptance"]:
            _object(item, "criterion evidence", "acceptance")
            _string(item["criterion"], "criterion")
            _string(item["evidence"], "evidence")
        _list(value["tests"], "tests", 128)
        for item in value["tests"]:
            _object(item, "argv result", "test")
            _argv(item["argv"], "test.argv")
            _string(item["result"], "test.result")
        _list(value["discoveries"], "discoveries", 64)
        for item in value["discoveries"]:
            _object(item, "title description acceptance", "discovery")
            _string(item["title"], "discovery.title", 256)
            _string(item["description"], "discovery.description")
            _strings(item["acceptance"], "discovery.acceptance", minimum=1)
        if value["discoveries"] and not value["needs_new_phase"]:
            raise ValueError("discoveries require a new phase")
        if value["status"] == "complete" and (
            value["discoveries"] or value["needs_new_phase"] or not value["acceptance"]
        ):
            raise ValueError("complete worker requires acceptance and no unresolved new work")
    else:
        _object(value, "verdict summary findings acceptance_complete contract_separated", role)
        _enum(value["verdict"], {"approve", "request_changes", "blocked"}, "verdict")
        _boolean(value["acceptance_complete"], "acceptance_complete")
        _boolean(value["contract_separated"], "contract_separated")
        _list(value["findings"], "findings")
        for item in value["findings"]:
            _object(item, "severity path line description", "finding")
            _enum(item["severity"], {"critical", "high", "medium", "low"}, "severity")
            _path(item["path"], worktree, "finding.path")
            if type(item["line"]) is not int or not 1 <= item["line"] <= 10000000:
                raise ValueError("finding.line: expected positive bounded integer")
            _string(item["description"], "finding.description")
        if value["verdict"] == "approve" and (
            value["findings"] or not value["acceptance_complete"] or not value["contract_separated"]
        ):
            raise ValueError("approval requires complete acceptance, separated contract and no findings")
        if value["verdict"] == "request_changes" and (
            not value["findings"] and value["acceptance_complete"] and value["contract_separated"]
        ):
            raise ValueError("request_changes must identify incomplete acceptance or a finding")
    _string(value["summary"], "summary")
    return value


def _closed_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _invalid_constant(_):
    raise ValueError("non-finite JSON number")


def _json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_closed_pairs, parse_constant=_invalid_constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid JSON encoding or nesting") from error


class _EventObject(list):
    """Preserve event object pairs so telemetry cannot hide envelope ambiguity."""


def _event_type(raw):
    """Read control events strictly, tolerating one observed Codex telemetry quirk.

    Codex 0.154 emits two string ``item.id`` keys for web-search item events:
    its item identifier and the flattened search identifier. Neither identifier
    grants authority here. Preserve the raw log, ignore both identifiers, and
    reject every other duplicate, including envelope/turn-status fields. Final
    role results always use the separate, recursively strict ``_json`` parser.
    """
    try:
        event = json.loads(raw, object_pairs_hook=_EventObject, parse_constant=_invalid_constant)
        if type(event) is not _EventObject:
            raise ValueError("event requires an object")
        envelope = _closed_pairs(event)
        if type(envelope.get("type")) is not str:
            raise ValueError("event requires a string type")
        kind = envelope["type"]

        def check(node, path):
            if type(node) is _EventObject:
                fields = {}
                for key, value in node:
                    fields.setdefault(key, []).append(value)
                for key, values in fields.items():
                    if len(values) > 1 and not (
                        path == ("item",) and key == "id" and len(values) == 2
                        and all(type(value) is str for value in values)
                        and fields.get("type") == ["web_search"]
                        and kind in {"item.started", "item.updated", "item.completed"}
                    ):
                        raise ValueError("duplicate JSON event object key")
                for key, value in node:
                    check(value, (*path, key))
            elif type(node) is list:
                for value in node:
                    check(value, (*path, None))

        for key, value in envelope.items():
            check(value, (key,))
        return kind
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid JSON event encoding or nesting") from error


def load_result(role: str, path: Path, worktree: Path | None = None) -> dict:
    """Read a bounded regular final JSON file without following a final symlink."""
    import stat

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("result is not a regular file")
        raw = stream.read(MAX_RESULT_BYTES + 1)
    if len(raw) > MAX_RESULT_BYTES:
        raise ValueError("result exceeds 1 MiB")
    return validate_result(role, _json(raw), worktree)


def _child_environment():
    # A safe allowlist also prevents future or vendor-specific credential variable
    # names from silently entering the child. Authentication stays in existing HOME.
    names = {"HOME", "CODEX_HOME", "PATH", "USER", "LOGNAME", "SHELL", "LANG", "TZ",
             "TMPDIR", "TMP", "TEMP", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME",
             "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "DBUS_SESSION_BUS_ADDRESS",
             "SSL_CERT_FILE", "SSL_CERT_DIR"}
    env = {key: value for key, value in os.environ.items()
           if key in names or key.startswith("LC_")}
    if not env.get("HOME") or not env.get("PATH"):
        raise ValueError("existing HOME and PATH are required")
    return env


def _private_file(path, mode="wb"):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(descriptor, mode)


class CodexRunner:
    """Run isolated roles; at most four sessions exist across all runner instances."""

    def __init__(self, codex_path, model, reasoning_effort, max_sessions=4,
                 timeout_seconds=7200, use_systemd=False):
        if type(max_sessions) is not int or not 1 <= max_sessions <= 4:
            raise ValueError("max_sessions must be an integer in 1..4")
        if (type(timeout_seconds) not in {int, float} or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= 86400):
            raise ValueError("timeout_seconds must be positive and at most one day")
        _string(model, "model", 128)
        if any(ord(char) < 33 for char in model) or model.startswith("-"):
            raise ValueError("invalid model")
        _enum(reasoning_effort, {"minimal", "low", "medium", "high", "xhigh", "max", "ultra"},
              "reasoning_effort")
        if type(use_systemd) is not bool:
            raise ValueError("use_systemd must be boolean")
        executable = shutil.which(str(codex_path))
        if not executable:
            raise ValueError("Codex executable is unavailable")
        self.codex_path = str(Path(executable).absolute())
        self.model = model
        self.reasoning_effort = reasoning_effort
        self.timeout_seconds = timeout_seconds
        self.use_systemd = use_systemd
        self._slots = threading.BoundedSemaphore(max_sessions)
        self._cancelled = threading.Event()
        self._lock = threading.Lock()
        self._active = set()
        self._registered = set()
        self._systemd_run = shutil.which("systemd-run") if use_systemd else None
        self._systemctl = shutil.which("systemctl") if use_systemd else None
        self._env_binary = shutil.which("env") if use_systemd else None
        if use_systemd and not all((self._systemd_run, self._systemctl, self._env_binary)):
            raise ValueError("production containment requires systemd-run, systemctl and env")

    def cancel(self):
        """Cancel active sessions and queued calls permanently for this runner.

        Active run() calls stop/verify their owned systemd unit before they return.
        The caller must join its running tasks before releasing their worktrees.
        """
        self._cancelled.set()
        with self._lock:
            for process in self._active:
                self._signal_group(process, signal.SIGTERM)

    @staticmethod
    def _signal_group(process, sig):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass

    def _acquire(self, semaphore, deadline, output_dir):
        while True:
            if self._cancelled.is_set():
                raise AgentRunError("cancelled", "agent runner cancelled", output_dir)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AgentRunError("timeout", "agent timed out waiting for a session slot", output_dir)
            if semaphore.acquire(timeout=min(0.05, remaining)):
                return

    def _argv(self, role, worktree, result_path):
        sandbox = "workspace-write" if role == "worker" else "read-only"
        return [self.codex_path, "exec", "--ignore-user-config",
                "--strict-config", "--ephemeral", "--model", self.model,
                "--sandbox", sandbox, "--json", "--cd", str(worktree),
                "--output-schema", str(_SCHEMAS / f"{role}.json"),
                "--output-last-message", str(result_path),
                "-c", f"model_reasoning_effort={json.dumps(self.reasoning_effort)}",
                "-c", 'model_provider="openai"',
                "-c", 'approval_policy="never"', "-c", "agents.enabled=false",
                "-c", "features.multi_agent=false", "-c", "features.multi_agent_v2=false",
                "-c", "features.plugins=false", "-c", "features.hooks=false",
                "-c", "features.apps=false", "-c", "features.remote_plugin=false",
                "-c", "features.skill_mcp_dependency_install=false", "-"]

    def _contained_argv(self, argv, env, unit):
        if not self.use_systemd:
            return argv
        # env -i clears even credentials inherited from the user service manager.
        # --expand-environment=no prevents systemd expanding literal '$' in argv.
        return [self._systemd_run, "--user", "--quiet", "--wait", "--collect", "--pipe",
                "--service-type=exec", "--expand-environment=no", f"--unit={unit}",
                "-p", "KillMode=control-group", "-p", f"RuntimeMaxSec={self.timeout_seconds}s",
                "-p", "TimeoutStopSec=15s", "-p", "CPUQuota=800%", "-p", "MemoryMax=64G",
                f"--setenv=PATH={env['PATH']}", "--", self._env_binary, "-i",
                *[f"{key}={value}" for key, value in sorted(env.items())], *argv]

    def _uncertain_registration(self, unit, output_dir):
        # Recovery must not turn one later absent-unit observation into proof
        # that a previously submitted StartTransientUnit RPC cannot still apply.
        with _private_file(output_dir / "cleanup-uncertain.json", "w") as stream:
            json.dump({"version": 1, "unit": unit,
                       "reason": "launcher registration was not confirmed before cancellation"}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = os.open(output_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _stop_unit(self, unit, env, output_dir, *, registered=False):
        if unit is None:
            return
        try:
            subprocess.run([self._systemctl, "--user", "stop", unit], env=env,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20, check=False)
            state = subprocess.run([self._systemctl, "--user", "show",
                                    "--property=LoadState,ActiveState,MainPID,ControlPID,ControlGroup", unit], env=env,
                                   stdin=subprocess.DEVNULL, capture_output=True,
                                   timeout=5, check=False)
            properties = {}
            for line in state.stdout.decode("utf-8", errors="strict").splitlines():
                key, separator, value = line.partition("=")
                if not separator or key in properties:
                    raise ValueError("invalid systemd property response")
                properties[key] = value
            quiet = (state.returncode == 0 and properties.get("LoadState") in {"loaded", "not-found"}
                     and properties.get("ActiveState") in {"inactive", "failed"}
                     and properties.get("MainPID") == "0" and properties.get("ControlPID") == "0")
            group = properties.get("ControlGroup")
            if group is None:
                quiet = False
            elif group:
                if not group.startswith("/") or ".." in Path(group).parts:
                    quiet = False
                else:
                    events = Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.events"
                    if events.exists() and "populated 0" not in events.read_text().splitlines():
                        quiet = False
            if not quiet:
                raise AgentRunError("cleanup", "owned systemd unit is not confirmed quiescent", output_dir)
            if not registered and properties["LoadState"] == "not-found":
                self._uncertain_registration(unit, output_dir)
                raise AgentRunError("cleanup", "launcher registration is ambiguous; preserve the session for reconciliation", output_dir)
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            raise AgentRunError("cleanup", "cannot stop/verify owned systemd unit", output_dir) from error

    def _stream(self, process, events, errors, deadline, output_dir):
        pending = bytearray()
        total = 0
        completed = False
        with selectors.DefaultSelector() as selector:
            for stream, kind in ((process.stdout, "events"), (process.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, kind)
            while selector.get_map() or process.poll() is None:
                if self._cancelled.is_set():
                    raise AgentRunError("cancelled", "agent runner cancelled", output_dir)
                if time.monotonic() >= deadline:
                    raise AgentRunError("timeout", "agent session timed out", output_dir)
                for key, _ in selector.select(timeout=0.05):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > MAX_LOG_BYTES:
                        raise AgentRunError("log_limit", "agent logs exceed configured bound", output_dir)
                    if key.data == "stderr":
                        errors.write(chunk)
                        errors.flush()
                        continue
                    events.write(chunk)
                    events.flush()
                    pending.extend(chunk)
                    while b"\n" in pending:
                        raw, _, remainder = pending.partition(b"\n")
                        pending = bytearray(remainder)
                        if len(raw) > MAX_EVENT_BYTES:
                            raise AgentRunError("event_limit", "agent event exceeds configured bound", output_dir)
                        try:
                            kind = _event_type(raw)
                        except ValueError as error:
                            raise AgentRunError("event_json", "invalid agent JSONL event", output_dir) from error
                        # A real Codex event proves the transient service has
                        # executed; merely starting its systemd-run client does not.
                        with self._lock:
                            self._registered.add(process)
                        if kind in {"error", "turn.failed"}:
                            raise AgentRunError("agent_failure", "Codex emitted a failure event", output_dir)
                        if kind == "turn.completed":
                            completed = True
                    if len(pending) > MAX_EVENT_BYTES:
                        raise AgentRunError("event_limit", "agent event exceeds configured bound", output_dir)
            if self._cancelled.is_set():
                raise AgentRunError("cancelled", "agent runner cancelled", output_dir)
            if time.monotonic() >= deadline:
                raise AgentRunError("timeout", "agent session timed out", output_dir)
            if pending:
                raise AgentRunError("event_json", "truncated agent JSONL event", output_dir)
            if process.returncode != 0:
                raise AgentRunError("exit", f"Codex exited with status {process.returncode}", output_dir)
            if not completed:
                raise AgentRunError("event_json", "Codex emitted no completed turn", output_dir)

    def run(self, role: str, worktree: Path, prompt: str, output_dir: Path, *,
            review_purpose: str = "candidate") -> dict:
        """Run a fresh process and return a validated claim object, or fail closed.

        output_dir must be outside the source worktree and unused for any previous
        invocation. Logs and final output are private files retained on failures.
        """
        wrapped = build_prompt(role, prompt, review_purpose=review_purpose)
        worktree = Path(worktree).resolve(strict=True)
        if not worktree.is_dir():
            raise ValueError("worktree must be a directory")
        output_dir = Path(output_dir).absolute()
        if output_dir.resolve().is_relative_to(worktree):
            raise ValueError("agent outputs must be outside the worktree")
        output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if output_dir.is_symlink() or any(output_dir.iterdir()):
            raise ValueError("output directory must be a fresh non-symlink directory")
        output_dir = output_dir.resolve(strict=True)
        if output_dir.stat().st_uid != os.getuid():
            raise ValueError("output directory must belong to the current user")
        output_dir.chmod(0o700)
        env = _child_environment()
        deadline = time.monotonic() + self.timeout_seconds
        result_path = output_dir / "result.json"
        argv = self._argv(role, worktree, result_path)
        unit = f"agenc-ircd-agent-{uuid.uuid4().hex}.service" if self.use_systemd else None
        actual_argv = self._contained_argv(argv, env, unit)
        with _private_file(output_dir / "request.json", "w") as stream:
            json.dump({"role": role, "review_purpose": review_purpose if role == "reviewer" else None,
                       "argv": argv, "systemd_unit": unit}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        with _private_file(output_dir / "prompt.txt", "w") as stream:
            stream.write(wrapped)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(output_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        acquired = []
        process = None
        try:
            for semaphore in (self._slots, _GLOBAL_SESSIONS):
                self._acquire(semaphore, deadline, output_dir)
                acquired.append(semaphore)
            if self._cancelled.is_set():
                raise AgentRunError("cancelled", "agent runner cancelled", output_dir)
            with (open(output_dir / "prompt.txt", "rb") as source,
                  _private_file(output_dir / "events.jsonl") as events,
                  _private_file(output_dir / "stderr.log") as errors):
                with self._lock:
                    if self._cancelled.is_set():
                        raise AgentRunError("cancelled", "agent runner cancelled before launch", output_dir)
                    try:
                        process = subprocess.Popen(actual_argv, stdin=source, stdout=subprocess.PIPE,
                                                   stderr=subprocess.PIPE, cwd=worktree, env=env,
                                                   start_new_session=True)
                    except OSError as error:
                        raise AgentRunError("spawn", "cannot start Codex session", output_dir) from error
                    self._active.add(process)
                self._stream(process, events, errors, deadline, output_dir)
            try:
                return load_result(role, result_path, worktree)
            except (OSError, ValueError) as error:
                raise AgentRunError("result", "invalid or missing final agent result", output_dir) from error
        finally:
            try:
                if process is not None:
                    # Quiesce the local launcher before checking its remote unit;
                    # it must not submit a new start after the inactive readback.
                    try:
                        self._signal_group(process, signal.SIGTERM)
                        try:
                            process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            pass
                        self._signal_group(process, signal.SIGKILL)
                        process.wait(timeout=5)
                    except (OSError, subprocess.TimeoutExpired) as error:
                        if unit is not None:
                            self._uncertain_registration(unit, output_dir)
                        raise AgentRunError("cleanup", "local launcher is not confirmed stopped", output_dir) from error
                    finally:
                        for pipe in (process.stdout, process.stderr):
                            if pipe is not None:
                                pipe.close()
                    try:
                        with self._lock:
                            registered = process in self._registered
                        self._stop_unit(unit, env, output_dir, registered=registered)
                    finally:
                        with self._lock:
                            self._active.discard(process)
                            self._registered.discard(process)
            finally:
                for semaphore in reversed(acquired):
                    semaphore.release()
