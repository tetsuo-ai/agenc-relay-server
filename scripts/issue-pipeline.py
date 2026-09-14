#!/usr/bin/env python3
"""Operate the AgenC IRCD issue controller; see docs/issue-pipeline.md."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
sys.dont_write_bytecode = True

from issue_pipeline.config import Config, digest_file, private_directory
from issue_pipeline.controller import Controller, PipelineBlocked, body_hash, encode, halt_children, task_hash, write_record
from issue_pipeline.github import Github, issue_identity, native_issue_numbers
from issue_pipeline.gitops import GitRepo
from issue_pipeline.graph import Graph
from issue_pipeline.state import State, SupervisorLock
from issue_pipeline.sandbox import IMAGE, DOCKER_HOST


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--config", type=Path, default=Path.home() / ".local/state/agenc-ircd-pipeline/config.toml")
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="check local prerequisites and live graph without starting workers")
    sub.add_parser("plan", help="print dependency order and execution routes")
    sub.add_parser("status", help="show durable local task state")
    run = sub.add_parser("run", help="run the persistent controller")
    run.add_argument("--once", action="store_true", help="dispatch one ready batch and wait for it")
    sub.add_parser("pause", help="pause new dispatch; in-progress work completes its checks")
    sub.add_parser("resume", help="resume new dispatch")
    sub.add_parser("halt-children", help="stop only owned transient process groups (service recovery)")
    retry = sub.add_parser("retry", help="retry a blocked task from its retained checkpoint")
    retry.add_argument("issue", type=int)
    install = sub.add_parser("install", help="install an immutable controller release and stopped user service")
    install.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    install.add_argument("--source-commit", required=True)
    accept = sub.add_parser("accept-external", help="operator-only import of independently obtained qualification evidence")
    accept.add_argument("issue", type=int)
    accept.add_argument("--evidence", required=True, type=Path)
    return result


def doctor(config: Config) -> dict:
    commands = {}
    for name in ("git", "gh", "systemctl", "systemd-run", "docker", "prlimit", "cargo", "rustup", "bash", "python3"):
        path = shutil.which(name)
        if not path:
            raise PipelineBlocked("missing executable: " + name)
        commands[name] = path
    commands["codex"] = config.executable()
    for argv in ([commands["codex"], "login", "status"], ["gh", "auth", "status"],
                 ["systemctl", "--user", "show-environment"]):
        # Authentication/environment output is deliberately not returned or logged.
        subprocess.run(argv, check=True, capture_output=True, timeout=30)
    docker_env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()),
                  "DOCKER_HOST": DOCKER_HOST, "DOCKER_CLI_HINTS": "false"}
    image = subprocess.run([commands["docker"], "--host", DOCKER_HOST, "image", "inspect",
                            "--format", "{{.Id}}", IMAGE], check=True, capture_output=True,
                           text=True, timeout=30, env=docker_env)
    if image.stdout.strip() != IMAGE:
        raise PipelineBlocked("local Docker daemon does not provide the qualified pinned gate image")
    if config.clone.exists():
        if config.clone.is_symlink():
            raise PipelineBlocked("controller clone must not be a symlink")
        # Constructor needs an existing parent; use the clone only for this
        # read-only view so a missing worktree directory is not created.
        repo = GitRepo(config.clone, base_branch=config.base_branch, worktree_root=config.clone)
        origin = repo.run(["remote", "get-url", "origin"]).strip()
        if origin not in ("https://github.com/" + config.repository + ".git",
                          "git@github.com:" + config.repository + ".git"):
            raise PipelineBlocked("controller clone has an unexpected remote")
        if repo.run(["rev-parse", "--is-shallow-repository"]).strip() != "false":
            raise PipelineBlocked("controller clone must retain full source history")
        identity = [repo.run(["config", "--get", field]).strip() for field in ("user.name", "user.email")]
    else:
        # A new clone inherits global configuration, not the current checkout's
        # local identity. Read globals explicitly without creating any state.
        identity = [subprocess.run(["git", "config", "--global", "--get", field], check=True,
                                   capture_output=True, text=True, timeout=15).stdout.strip()
                    for field in ("user.name", "user.email")]
    if any(not value or any(char in value for char in "\r\n\x00") for value in identity):
        raise PipelineBlocked("set a valid Git user.name and user.email for controller commits")
    root = config.state
    while not root.exists():
        root = root.parent
    free = shutil.disk_usage(root).free / 2**30
    if free < config.minimum_free_gib:
        raise PipelineBlocked("free disk is below the configured floor")
    github = Github(config.repository)
    master = github.issue(config.master_issue)
    issue_identity(master, config.repository, config.master_issue)
    graph = Graph.from_master(master["body"])
    if graph.master_issue != config.master_issue:
        raise PipelineBlocked("master graph identity changed")
    children = github.children(config.master_issue)
    from concurrent.futures import ThreadPoolExecutor
    numbers = [task.issue for task in graph.tasks] + [int(graph.legacy_umbrella["issue"])]
    with ThreadPoolExecutor(max_workers=4) as pool:
        issues = dict(zip(numbers, pool.map(github.issue, numbers)))
        blockers = dict(zip(numbers, pool.map(
            lambda n: native_issue_numbers(github.blockers(n), config.repository, issues), numbers)))
    graph.validate_native_links(native_issue_numbers(children, config.repository, issues), blockers)
    return {"result": "prerequisites and live native DAG verified", "repository": config.repository,
            "master_issue": config.master_issue, "tasks": len(graph.tasks),
            "dependency_edges": sum(len(task.depends_on) for task in graph.tasks),
            "free_disk_gib": round(free, 1), "executables": commands,
            "gate_container": {"daemon": DOCKER_HOST, "image": IMAGE},
            "limits": {"issues": config.max_issues, "codex_sessions": config.max_sessions, "full_gates": 1},
            "note": "This does not qualify a source revision or prove external/native requirements."}


IMPORT_JSON_LIMIT = 1024 * 1024
IMPORT_ARTIFACT_LIMIT = 8 * 1024**3
IMPORT_TOTAL_LIMIT = 32 * 1024**3


def _json_object(pairs):
    """Reject ambiguous duplicate fields at every qualification object depth."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise PipelineBlocked("external qualification contains duplicate JSON fields")
        result[key] = value
    return result


def _regular_reader(path: Path):
    """Open only an ordinary file, never follow a symlink or block on a FIFO."""
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise PipelineBlocked("qualification files must not be symlinks")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise PipelineBlocked("qualification files must be ordinary files")
    return os.fdopen(fd, "rb")


def _qualification(path: Path, number: int) -> dict:
    """Read a bounded, typed, closed attestation before any remote mutation."""
    with _regular_reader(path) as stream:
        raw = stream.read(IMPORT_JSON_LIMIT + 1)
    if len(raw) > IMPORT_JSON_LIMIT:
        raise PipelineBlocked("external qualification JSON exceeds one MiB")
    def nonfinite(_value):
        raise PipelineBlocked("external qualification JSON must be finite")
    try:
        value = json.loads(raw, object_pairs_hook=_json_object, parse_constant=nonfinite)
    except (ValueError, RecursionError) as error:
        raise PipelineBlocked("external qualification contains invalid JSON") from error
    required = {"version", "issue", "route", "source", "approver", "qualification_url", "acceptance", "artifacts"}
    if (type(value) is not dict or set(value) != required or type(value["version"]) is not int
            or value["version"] != 1 or type(value["issue"]) is not int
            or value["issue"] != number or number <= 0):
        raise PipelineBlocked("external qualification must match the documented closed version-1 schema")
    if type(value["source"]) is not str or re.fullmatch(r"[0-9a-f]{40}", value["source"]) is None:
        raise PipelineBlocked("qualified source must be a full lowercase commit SHA")
    if type(value["route"]) is not str or value["route"] not in ("host", "native", "upstream", "external"):
        raise PipelineBlocked("external qualification route must identify a specialized task")
    for field in ("approver", "qualification_url"):
        if (type(value[field]) is not str or not value[field].strip() or len(value[field]) > 4096
                or any(ord(char) < 32 for char in value[field])):
            raise PipelineBlocked("external qualification must identify its approver and published evidence")
    try:
        url = urlsplit(value["qualification_url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise ValueError("invalid qualification URL")
        url.port
    except ValueError as error:
        raise PipelineBlocked("qualification URL must identify an HTTPS evidence record") from error
    if type(value["acceptance"]) is not list or not 1 <= len(value["acceptance"]) <= 2000:
        raise PipelineBlocked("external qualification requires a bounded acceptance-to-evidence matrix")
    criteria = set()
    for row in value["acceptance"]:
        if (type(row) is not dict or set(row) != {"criterion", "evidence"}
                or any(type(text) is not str or not text.strip() or len(text) > 65536 for text in row.values())):
            raise PipelineBlocked("invalid qualification acceptance row")
        if row["criterion"] in criteria:
            raise PipelineBlocked("qualification acceptance criteria must be distinct")
        criteria.add(row["criterion"])
    if type(value["artifacts"]) is not list or not 1 <= len(value["artifacts"]) <= 64:
        raise PipelineBlocked("qualification must include between one and 64 actual artifacts")
    paths = set()
    for item in value["artifacts"]:
        if (type(item) is not dict or set(item) != {"path", "sha256"}
                or type(item["path"]) is not str or not item["path"] or "\x00" in item["path"]
                or type(item["sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None):
            raise PipelineBlocked("qualification artifacts need an absolute path and lowercase SHA-256")
        path = Path(item["path"])
        if not path.is_absolute() or ".." in path.parts or str(path) in paths:
            raise PipelineBlocked("qualification artifact paths must be absolute, distinct and canonical")
        paths.add(str(path))
    return value


def _retained_artifact(source: Path, target: Path, expected: str, limit: int) -> int:
    """Publish a complete, fsynced, hash-checked artifact without replacing evidence.

    Hard-link publication gives an atomic no-overwrite operation. Interrupted
    copies leave only a disposable private temporary file, never a partial final.
    """
    def checked_existing() -> int:
        digest = hashlib.sha256()
        size = 0
        with _regular_reader(target) as reader:
            if os.fstat(reader.fileno()).st_mode & 0o077:
                raise PipelineBlocked("retained qualification artifact must be private")
            for block in iter(lambda: reader.read(1024 * 1024), b""):
                size += len(block)
                if size > limit:
                    raise PipelineBlocked("qualification artifact exceeds its retained byte limit")
                digest.update(block)
        if digest.hexdigest() != expected:
            raise PipelineBlocked("retained qualification artifact differs")
        return size
    if target.exists() or target.is_symlink():
        return checked_existing()
    fd, name = tempfile.mkstemp(prefix=".artifact-", dir=target.parent)
    temporary = Path(name)
    try:
        size = 0
        digest = hashlib.sha256()
        with os.fdopen(fd, "wb") as writer, _regular_reader(source) as reader:
            if os.fstat(reader.fileno()).st_size > limit:
                raise PipelineBlocked("qualification artifact exceeds its retained byte limit")
            for block in iter(lambda: reader.read(1024 * 1024), b""):
                size += len(block)
                if size > limit:
                    raise PipelineBlocked("qualification artifact exceeds its retained byte limit")
                digest.update(block)
                writer.write(block)
            if digest.hexdigest() != expected:
                raise PipelineBlocked("qualification artifact does not match its claimed digest")
            writer.flush()
            os.fsync(writer.fileno())
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError:
            return checked_existing()
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return size
    finally:
        temporary.unlink(missing_ok=True)


def accept_external(controller: Controller, number: int, evidence: Path) -> dict:
    """Import a named operator's attestation, with durable explicit retry intent.

    Structure and artifact provenance are checked here. Authenticity, acceptance
    completeness and domain qualification remain the identified human's duty.
    Repeating this command with the identical JSON reconciles an ambiguous close;
    the scheduler cannot turn an unfinished import into generic repository work.
    """
    value = _qualification(evidence, number)
    graph, issues = controller.snapshot()
    task = graph.by_issue.get(number)
    if task is None or task.route == "repository" or value["route"] != task.route:
        raise PipelineBlocked("external evidence route does not match the specialized task")
    issue_hash = body_hash(issues[number])
    tip = controller.fetch()
    if not controller.repo.is_ancestor(value["source"], tip):
        raise PipelineBlocked("qualified source is not on remote main")
    proofs = controller.verified_receipts(graph, issues, tip)
    if any(issues[n]["state"] != "closed" or n not in proofs for n in task.depends_on):
        raise PipelineBlocked("qualification prerequisites lack accepted completion evidence")
    if any(not controller.repo.is_ancestor(proofs[n]["source"], value["source"]) for n in task.depends_on):
        raise PipelineBlocked("qualification source predates its prerequisite evidence")
    binding = task_hash(task)
    prerequisites = {str(n): proofs[n]["digest"] for n in task.depends_on}
    identity = hashlib.sha256(encode(value).encode()).hexdigest()
    old = controller.state.get_task(number)
    previous = old["data"].get("external_import") if old else None
    if previous and old["status"] != "complete" and (
            previous["identity"] != identity or previous["issue_hash"] != issue_hash
            or previous.get("task_hash") != binding or previous.get("dependency_receipts") != prerequisites):
        raise PipelineBlocked("unfinished external import differs; reconcile its original evidence and issue first")
    destination = controller.config.state / "imports" / identity
    private_directory(destination)
    artifacts = {}
    total = 0
    for index, item in enumerate(value["artifacts"]):
        target = destination / str(index)
        total += _retained_artifact(Path(item["path"]), target, item["sha256"],
                                    min(IMPORT_ARTIFACT_LIMIT, IMPORT_TOTAL_LIMIT - total))
        artifacts[str(index)] = str(target)
    data = dict(old["data"]) if old else {}
    data.update({"external_import": {"identity": identity, "source": value["source"], "issue_hash": issue_hash,
                                     "task_hash": binding, "dependency_receipts": prerequisites},
                 "remote_action": "external-import", "reason": "External qualification import awaits verified closure; repeat accept-external with the original evidence JSON."})
    controller.state.set_task(number, "blocked", data)
    receipts = [receipt for receipt in controller.state.receipts(number, "completion")
                if receipt["source"] == value["source"] and receipt["status"] == "accepted"
                and receipt["data"].get("operator_import") == value and receipt["data"].get("issue_hash") == issue_hash
                and receipt["data"].get("task_hash") == binding and receipt["data"].get("dependency_receipts") == prerequisites]
    if receipts:
        receipt = receipts[-1]
        if not controller.receipt_valid(receipt):
            raise PipelineBlocked("retained external completion receipt differs")
    else:
        receipt = controller.record(number, "completion", value["source"], value["source"],
                                     {"issue_hash": issue_hash, "operator_import": value, "artifacts": artifacts,
                                      "task_hash": binding, "dependency_receipts": prerequisites})
    # Recheck the live issue, graph and dependency proofs after potentially long
    # artifact copying; a receipt for stale requirements cannot close new work.
    latest_graph, latest_issues = controller.snapshot()
    tip = controller.fetch()
    latest_proofs = controller.verified_receipts(latest_graph, latest_issues, tip)
    if (latest_graph.by_issue.get(number) != task or body_hash(latest_issues[number]) != issue_hash
            or not controller.repo.is_ancestor(value["source"], tip)
            or any(latest_issues[n]["state"] != "closed" or n not in latest_proofs
                   or latest_proofs[n]["digest"] != prerequisites[str(n)] for n in task.depends_on)):
        raise PipelineBlocked("qualification issue, source or prerequisite evidence changed during import")
    controller.comment_once(number, "<!-- agenc-pipeline-external:" + identity + " -->",
        "Specialized qualification imported by the operator. This is an external attestation, not a generic model/test pass.\n\n"
        f"Approver: {value['approver']}\n\nEvidence: {value['qualification_url']}\n\nSource: `{value['source']}`\n\nReceipt: `{receipt['digest']}`\n\n" +
        "\n".join("- " + row["criterion"] + ": " + row["evidence"] for row in value["acceptance"]))
    if controller.github.issue(number)["state"] != "closed":
        controller.github.close_issue(number)
    observed = controller.github.issue(number)
    if observed["state"] != "closed" or body_hash(observed) != issue_hash:
        raise PipelineBlocked("external qualification closure readback failed")
    controller.state.set_task(number, "complete", {"operator_import": identity, "external_import": data["external_import"]})
    controller.state.release(number)
    return {"issue": number, "status": "complete", "receipt": receipt["digest"]}


def main() -> int:
    args = parser().parse_args()
    config = Config.load(args.config)
    if args.command == "halt-children":
        halt_children(config.state)
    elif args.command == "doctor":
        print(encode(doctor(config)))
    elif args.command == "install":
        from issue_pipeline.installer import install
        print(encode(install(args.config, args.source_root, args.source_commit)))
    elif args.command in ("pause", "resume"):
        private_directory(config.state)
        flag = config.state / "PAUSED"
        if args.command == "pause":
            flag.touch(mode=0o600, exist_ok=True)
        else:
            flag.unlink(missing_ok=True)
        print(args.command + " applied")
    elif args.command == "status":
        if not (config.state / "state.sqlite3").exists():
            print(encode({"status": "not started", "state": str(config.state)}))
        else:
            with State(config.state / "state.sqlite3") as state:
                print(encode({"paused": (config.state / "PAUSED").exists(),
                              "tasks": [{"issue": row["issue"], "status": row["status"],
                                         "phase": row["data"].get("phase_index"),
                                         "reason": row["data"].get("reason"), "updated_at": row["updated_at"]}
                                        for row in state.list_tasks()], "claims": state.claims()}))
    elif args.command == "plan":
        github = Github(config.repository)
        graph = Graph.from_master(github.issue(config.master_issue)["body"])
        print(encode([{"key": task.key, "issue": task.issue, "level": task.level, "route": task.route,
                       "depends_on": task.depends_on, "locks": task.locks}
                      for task in sorted(graph.tasks, key=lambda task: (task.level, task.issue))]))
    elif args.command == "retry":
        with SupervisorLock(config.state / "supervisor.lock"), State(config.state / "state.sqlite3") as state:
            row = state.get_task(args.issue)
            if row is None or row["status"] != "blocked":
                raise PipelineBlocked("retry requires an existing blocked task; stop the service first")
            data = dict(row["data"])
            if data.get("remote_action") == "external-import":
                raise PipelineBlocked("repeat accept-external with the original evidence JSON to reconcile this import")
            data.update({"attempt": 0, "reason": None, "retry_after": 0})
            pending = data.get("pending_discoveries")
            if pending:
                for entry in pending["entries"][pending["cursor"]:]:
                    if "review_attempts" in entry:
                        entry["review_attempts"] = 0
                data["remote_action"] = "register-discoveries"
            state.set_task(args.issue, "pending", data)
            print(encode({"issue": args.issue, "status": "pending", "note": "restart the service to reconcile and retry"}))
    elif args.command == "accept-external":
        with SupervisorLock(config.state / "supervisor.lock"):
            controller = Controller(config)
            try:
                print(encode(accept_external(controller, args.issue, args.evidence)))
            finally:
                controller.state.close()
    else:
        controller = Controller(config)
        if args.command == "run":
            def stop(_signum, _frame):
                controller.shutdown()
            signal.signal(signal.SIGTERM, stop)
            signal.signal(signal.SIGINT, stop)
            try:
                controller.run(once=args.once)
            finally:
                controller.shutdown()
                controller.state.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("pipeline stopped: " + str(error), file=sys.stderr)
        raise SystemExit(1)
