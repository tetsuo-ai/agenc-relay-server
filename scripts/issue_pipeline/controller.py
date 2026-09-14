"""Deterministic issue scheduling, source-bound acceptance and recoverable promotion.

Model outputs propose changes. Only this controller owns Git/GitHub mutations.
Every remote mutation has a durable checkpoint and an observable reconciliation.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time
import uuid

from .agents import AgentRunError, CodexRunner, validate_result
from .config import Config, digest_file, private_directory
from .gitops import GitRepo, GitError
from .github import Github
from .graph import Graph, Task
from .state import ClaimConflict, State, SupervisorLock
from .gate import GateFailure


CONTEXTS = ("agenc-pipeline/recorded-gate", "agenc-pipeline/independent-review")
UNIT = re.compile(r"agenc-ircd-(?:agent|pipeline-gate)-[0-9a-f]{32}\.service\Z")


class PipelineBlocked(RuntimeError):
    """Keep evidence and source; do not infer completion or weaken a check."""


def encode(value: object) -> str:
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"


def body_hash(issue: dict) -> str:
    return hashlib.sha256(encode({"title": issue.get("title"), "body": issue.get("body")}).encode()).hexdigest()


def write_record(path: Path, value: object) -> str:
    """Create an immutable, private, fsynced evidence file."""
    private_directory(path.parent)
    raw = encode(value).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return hashlib.sha256(raw).hexdigest()


def halt_children(state_dir: Path) -> None:
    """Stop only this controller's UUID-named transient units, including descendants."""
    result = subprocess.run(["systemctl", "--user", "list-units", "--all", "--no-legend",
                             "--plain", "--no-pager"], check=True, capture_output=True, text=True, timeout=30)
    owned = set()
    for pattern, field in (("sessions/*/request.json", "systemd_unit"), ("gates/*/unit.json", "unit")):
        for path in state_dir.glob(pattern):
            if (any(parent.is_symlink() for parent in (path, *path.parents))
                    or not path.resolve().is_relative_to(state_dir.resolve()) or path.stat().st_size > 128 * 1024):
                raise PipelineBlocked("invalid process ownership record: " + str(path))
            value = json.loads(path.read_text())
            if field == "unit" and value.get("state_dir") != str(state_dir):
                raise PipelineBlocked("process ownership record belongs to another state directory")
            unit = value.get(field)
            if unit is not None:
                if not isinstance(unit, str) or not UNIT.fullmatch(unit):
                    raise PipelineBlocked("invalid owned process unit identity")
                owned.add(unit)
    units = [line.split()[0] for line in result.stdout.splitlines() if line.split() and line.split()[0] in owned]
    for unit in units:
        subprocess.run(["systemctl", "--user", "stop", unit], check=True, capture_output=True, timeout=60)
        status = subprocess.run(["systemctl", "--user", "show", unit, "--property=ActiveState", "--value"],
                                check=True, capture_output=True, text=True, timeout=15)
        if status.stdout.strip() not in ("inactive", "failed"):
            raise PipelineBlocked("pipeline child unit is not quiescent: " + unit)


def ensure_clone(config: Config) -> GitRepo:
    private_directory(config.state)
    private_directory(config.worktrees)
    if not config.clone.exists():
        # Clone to a temporary sibling so an interrupted clone is never accepted.
        temporary = config.state / ("clone-" + uuid.uuid4().hex)
        subprocess.run(["git", "clone", "--no-checkout", "--", "https://github.com/" + config.repository + ".git",
                        str(temporary)], check=True, timeout=600)
        temporary.rename(config.clone)
    repo = GitRepo(config.clone, base_branch=config.base_branch, worktree_root=config.worktrees)
    origin = repo.run(["remote", "get-url", "origin"]).strip()
    if origin not in ("https://github.com/" + config.repository + ".git", "git@github.com:" + config.repository + ".git"):
        raise PipelineBlocked("controller clone has an unexpected remote")
    if repo.run(["rev-parse", "--is-shallow-repository"]).strip() != "false":
        raise PipelineBlocked("controller clone must retain full source history")
    # Git identity is controller-local and derived from the authenticated account.
    for key in ("user.name", "user.email"):
        value = repo.run(["config", "--get", key]).strip()
        if not value or "\n" in value:
            raise PipelineBlocked("set a Git " + key + " for controller commits")
        repo.run(["config", "--local", key, value])
    return repo


class Controller:
    def __init__(self, config: Config, *, repo=None, github=None, runner=None, gate=None):
        self.config = config
        private_directory(config.state)
        self.repo = repo if repo is not None else ensure_clone(config)
        self.github = github if github is not None else Github(config.repository, cwd=config.clone)
        self.state = State(config.state / "state.sqlite3")
        self.runner = runner if runner is not None else CodexRunner(
            config.executable(), config.model, config.reasoning_effort,
            max_sessions=config.max_sessions, timeout_seconds=config.agent_timeout_seconds,
            use_systemd=config.use_systemd)
        if gate is None:
            from .gate import GateRunner
            gate = GateRunner(config)
        self.gate = gate
        self.stop = threading.Event()
        self.integration = threading.Lock()
        self.graph_lock = threading.RLock()
        self.git_lock = threading.RLock()

    def fetch(self) -> str:
        with self.git_lock:
            return self.repo.fetch()

    def log(self, message: str, **data) -> None:
        print(encode({"time": time.time(), "message": message, **data}).strip(), flush=True)

    def checkpoint(self, number: int, status: str, data: dict, **changes) -> None:
        data.update(changes)
        self.state.set_task(number, status, data)

    def snapshot(self) -> tuple[Graph, dict[int, dict]]:
        with self.graph_lock:
            master = self.github.issue(self.config.master_issue)
            graph = Graph.from_master(master["body"])
            if graph.master_issue != self.config.master_issue:
                raise PipelineBlocked("master graph identity changed")
            numbers = [task.issue for task in graph.tasks] + [int(graph.legacy_umbrella["issue"])]
            with ThreadPoolExecutor(max_workers=4) as pool:
                issues = dict(zip(numbers, pool.map(self.github.issue, numbers)))
                blockers = dict(zip(numbers, pool.map(lambda n: [row["number"] for row in self.github.blockers(n)], numbers)))
            graph.validate_native_links([row["number"] for row in self.github.children(graph.master_issue)], blockers)
            return graph, issues

    def verified(self, number: int, tip: str) -> bool:
        """Closed labels alone never satisfy a dependency."""
        record = self.state.get_task(number)
        if record is None or record["status"] != "complete":
            return False
        issue = self.github.issue(number)
        for receipt in reversed(self.state.receipts(number, "completion")):
            if receipt["status"] == "accepted" and receipt["data"].get("issue_hash") == body_hash(issue):
                if not self.receipt_valid(receipt) or not self.repo.is_ancestor(receipt["source"], tip):
                    return False
                try:
                    for phase in receipt["data"].get("merged_phases", []):
                        self.require_candidate_receipts(number, phase["source"], phase["base"])
                        if not self.repo.is_ancestor(phase["source"], tip):
                            return False
                except PipelineBlocked:
                    return False
                return True
        return False

    def receipt_valid(self, receipt: dict) -> bool:
        paths = receipt.get("data", {}).get("artifacts", {})
        if set(paths) != set(receipt["artifact_hashes"]):
            return False
        for name, path in paths.items():
            candidate = Path(path)
            if (candidate.is_symlink() or not candidate.resolve().is_relative_to(self.config.state)
                    or not candidate.is_file() or digest_file(candidate) != receipt["artifact_hashes"][name]):
                return False
        return self.repo.tree(receipt["source"]) == receipt["tree"]

    def record(self, number: int, kind: str, source: str, base: str, value: dict, *, accepted=True) -> dict:
        path = self.config.state / "receipts" / str(number) / (kind + "-" + uuid.uuid4().hex + ".json")
        hashes = {"record": write_record(path, value)}
        paths = {"record": str(path)}
        for name, artifact in value.get("artifacts", {}).items():
            if name == "record":
                raise PipelineBlocked("artifact name 'record' is reserved for the immutable receipt")
            candidate = Path(artifact)
            if candidate.is_symlink() or not candidate.resolve().is_relative_to(self.config.state):
                raise PipelineBlocked("receipt artifact lies outside controller evidence storage")
            with candidate.open("rb") as stream:
                os.fsync(stream.fileno())
            directory = os.open(candidate.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            hashes[name] = digest_file(candidate)
            paths[name] = str(candidate)
        return self.state.add_receipt(number, kind, source, self.repo.tree(source), base, hashes,
                                      "accepted" if accepted else "rejected",
                                      {**value, "artifacts": paths})

    def session(self, role: str, source: str, task: dict, *, writable: Path | None = None,
                review_purpose="candidate") -> tuple[dict, str]:
        identity = role + "-" + uuid.uuid4().hex
        worktree = writable if writable is not None else self.config.worktrees / identity
        output = self.config.state / "sessions" / identity
        if writable is None:
            with self.git_lock:
                self.repo.add_worktree(worktree, None, source)
        try:
            result = self.runner.run(role, worktree, encode(task), output, review_purpose=review_purpose)
        except AgentRunError as error:
            if error.kind == "cleanup":
                self.stop.set()
                raise PipelineBlocked("agent process cleanup is uncertain; controller stopped and work preserved") from error
            if writable is None:
                with self.git_lock:
                    self.repo.cleanup_owned(worktree, None, source)
            raise
        validate_result(role, result, worktree)
        # CodexRunner confirms the entire cgroup is gone before returning.
        if writable is None:
            with self.git_lock:
                if self.repo.head(worktree) != source:
                    raise PipelineBlocked("read-only agent changed its source identity")
                self.repo.cleanup_owned(worktree, None, source)
        return result, str(output / "result.json")

    def live_preconditions(self, task: Task, expected_hash: str, *, allow_closed=False) -> None:
        graph, issues = self.snapshot()
        if graph.by_issue.get(task.issue) != task:
            raise PipelineBlocked("task dependency/scope definition changed; replan required")
        if (not allow_closed and issues[task.issue]["state"] != "open") or body_hash(issues[task.issue]) != expected_hash:
            raise PipelineBlocked("issue content or state changed; replan required")
        tip = self.fetch()
        if any(issues[dep]["state"] != "closed" or not self.verified(dep, tip) for dep in task.depends_on):
            raise PipelineBlocked("a prerequisite lacks accepted completion evidence")

    def review_pair(self, task: Task, data: dict, phase: dict, candidate: str, base: str) -> list[dict]:
        self.checkpoint(task.issue, "reviewing", data, candidate=candidate, base=base)
        task_data = {"issue": data["issue"], "phase": phase, "plan": data["plan"],
                     "candidate": candidate, "base": base, "original_base": data["original_base"],
                     "previous_merged_phases": data.get("merged_phases", []),
                     "final_phase": data["phase_index"] == len(data["plan"]["phases"]) - 1,
                     "worker_claims": data.get("worker"),
                     "review_instruction": "Inspect git diff BASE..CANDIDATE. On the final phase also verify the entire original issue across all merged phases. An omitted acceptance requirement is a blocking defect."}
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.session, "reviewer", candidate,
                       {**task_data, "focus": focus}) for focus in (
                           "Independent acceptance, specification and test adequacy review",
                           "Independent security, crash/restart, resource bounds and adversarial failure review")]
            reports = [future.result() for future in futures]
        value = {"reviews": [item[0] for item in reports],
                 "artifacts": {"review-" + str(index): item[1] for index, item in enumerate(reports)}}
        approved = all(item[0]["verdict"] == "approve" for item in reports)
        receipt = self.record(task.issue, "review", candidate, base, value, accepted=approved)
        data["review_receipt"] = receipt["id"]
        if not approved:
            raise PipelineBlocked("independent review requires changes: " + encode(value["reviews"]))
        return value["reviews"]

    def publish_and_promote(self, task: Task, data: dict, phase: dict) -> None:
        candidate, base = data["candidate"], data["base"]
        self.require_candidate_receipts(task.issue, candidate, base)
        self.live_preconditions(task, data["issue_hash"])
        if self.fetch() != base:
            raise PipelineBlocked("main advanced after validation; candidate needs fresh review and gate")
        title = f"{task.key}: {phase['name']}"[:256]
        body = self.pr_body(task, data, phase)
        self.checkpoint(task.issue, "publishing", data, remote_action="push-branch")
        self.repo.push_branch(data["branch"], candidate)
        if not data.get("pr"):
            prs = self.github.api("pulls?state=all&head=" + self.config.repository.split("/")[0] + ":" + data["branch"] + "&per_page=100")
            matches = [pr for pr in prs if pr["head"]["ref"] == data["branch"]]
            if len(matches) > 1:
                raise PipelineBlocked("multiple pull requests claim this owned branch")
            if matches:
                data["pr"] = matches[0]["number"]
            else:
                if data.get("create_pr_attempted"):
                    raise PipelineBlocked("prior PR creation is ambiguous; preserve branch for reconciliation")
                self.checkpoint(task.issue, "publishing", data, remote_action="create-pr", create_pr_attempted=True)
                data["pr"] = self.github.create_pr(data["branch"], title, body, base=self.config.base_branch)["number"]
            self.checkpoint(task.issue, "publishing", data, remote_action=None)
        else:
            self.github.api(f"pulls/{data['pr']}", "PATCH", {"title": title, "body": body})
        url = f"https://github.com/{self.config.repository}/pull/{data['pr']}"
        for context in CONTEXTS:
            self.github.set_status(candidate, "success", context, "Accepted exact-source local evidence; see PR", url)
        deadline = time.monotonic() + 1800
        while True:
            checks = self.github.hosted_checks(candidate, ignore_contexts=CONTEXTS)
            if checks["state"] != "pending" or self.stop.wait(15) or time.monotonic() > deadline:
                break
        self.record(task.issue, "hosted-checks", candidate, base, checks, accepted=not checks["blocking"])
        if checks["blocking"]:
            raise PipelineBlocked("hosted check evidence blocks promotion: " + checks["state"])
        self.live_preconditions(task, data["issue_hash"])
        pr = self.github.pr(data["pr"])
        if (pr["head"]["sha"] != candidate or pr["base"]["ref"] != self.config.base_branch
                or pr["base"]["repo"]["full_name"] != self.config.repository or pr["state"] != "open"):
            raise PipelineBlocked("pull request identity changed before promotion")
        self.require_candidate_receipts(task.issue, candidate, base)
        if self.stop.is_set() or not self.config.auto_merge:
            raise PipelineBlocked("promotion paused by controller policy")
        self.checkpoint(task.issue, "merging", data, remote_action="promote")
        # GitRepo proves base is an ancestor and uses an explicit expected-old ref
        # lease. A race cannot overwrite new main commits or reuse stale evidence.
        self.repo.atomic_promote(candidate, base)
        self.finish_promoted_phase(task, data)

    def require_candidate_receipts(self, number: int, candidate: str, base: str) -> None:
        for kind in ("review", "gate"):
            matching = [receipt for receipt in self.state.receipts(number, kind)
                        if receipt["source"] == candidate and receipt["base"] == base]
            if not matching or matching[-1]["status"] != "accepted" or not self.receipt_valid(matching[-1]):
                raise PipelineBlocked("candidate lacks valid exact-source " + kind + " evidence")

    def finish_promoted_phase(self, task: Task, data: dict) -> None:
        candidate, base = data["candidate"], data["base"]
        self.require_candidate_receipts(task.issue, candidate, base)
        if not self.repo.is_ancestor(candidate, self.fetch()):
            raise PipelineBlocked("candidate is not on remote main")
        pr = None
        for _ in range(12):
            try:
                pr = self.github.merged_pr(data["pr"], candidate)
                break
            except Exception:
                if self.stop.wait(5):
                    break
        if pr is None or self.repo.tree(pr["merge_commit_sha"]) != self.repo.tree(candidate):
            raise PipelineBlocked("GitHub has not confirmed the exact reviewed PR merge; retain worktree")
        self.record(task.issue, "merge", candidate, base, {"pr": data["pr"], "merge_commit": pr["merge_commit_sha"]})
        merged = data.setdefault("merged_phases", [])
        if not any(item["phase_index"] == data["phase_index"] for item in merged):
            merged.append({"phase_index": data["phase_index"], "source": candidate, "base": base, "pr": data["pr"]})
        self.checkpoint(task.issue, "merging", data, remote_action="cleanup")
        path = Path(data["worktree"])
        self.repo.cleanup_owned(path, data["branch"], candidate, generated_roots=("target", "fuzz/target"))
        self.checkpoint(task.issue, "working", data, phase_index=data["phase_index"] + 1,
                        worktree=None, branch=None, candidate=None, pr=None, create_pr_attempted=False,
                        remote_action=None, attempt=0, feedback=None)

    def pr_body(self, task: Task, data: dict, phase: dict) -> str:
        proofs = [r for r in self.state.receipts(task.issue) if r["source"] == data["candidate"]
                  and r["kind"] in ("review", "gate") and r["status"] == "accepted"]
        return (f"Implements phase {data['phase_index'] + 1}/{len(data['plan']['phases'])} of {task.key}. Refs #{task.issue}.\n\n"
                f"{phase['name']}\n\nContract and acceptance:\n" + "\n".join("- " + item for item in phase["acceptance"]) +
                f"\n\nSource `{data['candidate']}`; base `{data['base']}`.\n\n"
                "Validation: two fresh independent Codex reviews accepted; `AGENC_IRCD_RECORD_GATE=1 bash scripts/check-stage-nine.sh` passed on this committed source. "
                "Receipt hashes below bind the archived review results, full gate artifact and log. Hosted checks are assessed separately; empty checks and zero-job startup failures are not reported as passing.\n\n"
                "```json\n" + encode([{"kind": r["kind"], "receipt": r["digest"], "artifacts": r["artifact_hashes"]} for r in proofs]) +
                "```\n\nRemaining work: " + ("later phases in the parent issue" if data["phase_index"] + 1 < len(data["plan"]["phases"]) else "none within this issue after final acceptance") + ".\n")

    def comment_once(self, number: int, marker: str, body: str) -> None:
        if not any(marker in (item.get("body") or "") for item in self.github.comments(number)):
            self.github.comment(number, body + "\n\n" + marker)

    def complete(self, task: Task, data: dict) -> None:
        phases = data.get("merged_phases", [])
        if sorted(item["phase_index"] for item in phases) != list(range(len(data["plan"]["phases"]))):
            raise PipelineBlocked("not every planned phase has merged")
        self.live_preconditions(task, data["issue_hash"], allow_closed=data.get("remote_action") == "close-issue")
        tip = self.fetch()
        proof_ids = []
        for phase in phases:
            self.require_candidate_receipts(task.issue, phase["source"], phase["base"])
            merged = self.github.merged_pr(phase["pr"], phase["source"])
            if (not self.repo.is_ancestor(phase["source"], tip)
                    or self.repo.tree(merged["merge_commit_sha"]) != self.repo.tree(phase["source"])):
                raise PipelineBlocked("a phase no longer has verified merged source")
            proof_ids.extend(r["digest"] for r in self.state.receipts(task.issue)
                             if r["kind"] in ("review", "gate") and r["source"] == phase["source"]
                             and r["base"] == phase["base"] and r["status"] == "accepted")
        last = next(item for item in phases if item["phase_index"] == len(phases) - 1)
        live = self.github.issue(task.issue)
        if body_hash(live) != data["issue_hash"]:
            raise PipelineBlocked("issue changed before closure")
        existing = [r for r in self.state.receipts(task.issue, "completion")
                    if r["source"] == last["source"] and r["base"] == last["base"]
                    and r["data"].get("issue_hash") == data["issue_hash"]
                    and r["data"].get("merged_phases") == phases and self.receipt_valid(r)]
        receipt = existing[-1] if existing else self.record(task.issue, "completion", last["source"], last["base"],
                              {"issue_hash": data["issue_hash"], "merged_phases": phases, "proof_receipts": proof_ids,
                               "acceptance": [phase["acceptance"] for phase in data["plan"]["phases"]]})
        self.checkpoint(task.issue, "merging", data, remote_action="close-issue")
        self.comment_once(task.issue, "<!-- agenc-pipeline-completion:" + receipt["digest"] + " -->",
                          "All planned phases merged and passed the full local gate and two independent reviews on their exact source commits.\n\n" +
                          "\n".join(f"- Phase {item['phase_index'] + 1}: PR #{item['pr']}, `{item['source']}`." for item in data["merged_phases"]) +
                          f"\n\nCompletion receipt: `{receipt['digest']}`. Original issue acceptance was reviewed in the final phase. External qualification remains governed by its separate dependency issues.")
        if live["state"] != "closed":
            self.github.close_issue(task.issue)
        if self.github.issue(task.issue)["state"] != "closed":
            raise PipelineBlocked("issue closure readback failed")
        self.checkpoint(task.issue, "complete", data, remote_action=None)
        self.state.release(task.issue)
        self.log("issue completed", issue=task.issue)

    def discoveries(self, task: Task, data: dict, worker: dict, source: str) -> None:
        from .backlog import Backlog
        for discovery in worker["discoveries"]:
            review, artifact = self.session("reviewer", source, {
                "issue": data["issue"], "discovery": discovery,
                "review_instruction": "Verify whether this proposed blocking issue is correct, necessary, actionable and not already covered. Approve only when its claimed defect and all proposed acceptance criteria are supported by source. This review approves issue registration, not code completion."}, review_purpose="discovery")
            self.record(task.issue, "discovery-review", source, source,
                        {"discovery": discovery, "review": review, "artifacts": {"review": artifact}},
                        accepted=review["verdict"] == "approve")
            if review["verdict"] != "approve":
                raise PipelineBlocked("proposed discovery did not pass independent verification")
            with self.graph_lock:
                number = Backlog(self.github, self.config.state, self.config.master_issue).register(task.issue, discovery, source, review)
            self.log("registered verified prerequisite", issue=task.issue, prerequisite=number)
        self.checkpoint(task.issue, "blocked", data, dependency_replan=True)

    def execute(self, task: Task, issue: dict) -> None:
        saved = self.state.get_task(task.issue)
        data = dict(saved["data"]) if saved else {}
        claimed = False
        try:
            if saved is None:
                self.state.set_task(task.issue, "pending", data)
            self.state.claim(task.issue, scopes=task.locks, owner=str(task.issue))
            claimed = True
            self.state.set_task(task.issue, "planning", data)
            if data.get("dependency_replan"):
                data["completed_plan_phases"] = data["plan"]["phases"][:data["phase_index"]]
                data["plan"] = None
                data["attempt"] = 0
                data["dependency_replan"] = False
            if data.get("remote_action") in ("promote", "cleanup"):
                with self.integration:
                    if self.repo.is_ancestor(data["candidate"], self.fetch()):
                        self.finish_promoted_phase(task, data)
                    else:
                        data["remote_action"] = None
            if data.get("remote_action") in ("push-branch", "create-pr"):
                with self.integration:
                    # Reconcile a journaled push before changing the local head.
                    self.repo.push_branch(data["branch"], data["candidate"])
                    if data["base"] == self.fetch():
                        phase = data["plan"]["phases"][data["phase_index"]]
                        self.publish_and_promote(task, data, phase)
                    else:
                        self.checkpoint(task.issue, "working", data, remote_action=None)
            if not data.get("plan"):
                base = self.fetch()
                planning_source = base
                existing_paths = []
                if data.get("worktree"):
                    existing = Path(data["worktree"])
                    if self.repo.changed_paths(existing):
                        raise PipelineBlocked("replanning requires the retained partial source to be committed")
                    if not self.repo.rebase(existing, base):
                        raise PipelineBlocked("retained partial source conflicts with completed prerequisites; resolve its owned worktree before retry")
                    planning_source = self.repo.head(existing)
                    existing_paths = self.repo.changed_paths(existing, base)
                    data["base"] = base
                plan, artifact = self.session("planner", planning_source, {"issue": issue, "task": asdict(task),
                          "already_merged_phases": data.get("merged_phases", []), "retained_unmerged_paths": existing_paths,
                          "replan_feedback": data.get("replan_feedback"),
                          "remaining_scope_instruction": "Plan every remaining requirement; already merged phases remain accepted only with their stored proof. Every retained unmerged path must be included in the first remaining phase and reviewed as part of that phase.",
                          "maximum_phases": self.config.max_phases,
                          "instruction": "Cover the complete issue, and list exact files. Focused test outputs under target/ and fuzz/target/ are disposable allowed build outputs. Do not schedule changes to controller or gate authority; report such prerequisites explicitly."})
                self.record(task.issue, "plan", planning_source, base, {"plan": plan, "artifacts": {"plan": artifact}}, accepted=plan["status"] == "planned")
                if plan["status"] != "planned" or len(plan["phases"]) > self.config.max_phases:
                    raise PipelineBlocked("planner could not establish a bounded complete plan: " + encode(plan))
                if not set(existing_paths) <= set(plan["phases"][0]["files"]):
                    raise PipelineBlocked("replan omitted retained partial source from its first phase")
                check, review_artifact = self.session("reviewer", planning_source, {"issue": issue, "proposed_plan": plan,
                         "already_merged_phases": data.get("merged_phases", []),
                         "review_instruction": "Review plan coverage and scope against the full original issue and current source. Approve only if every original requirement has a specific phase, test and exact file scope; assess planning completeness, not implementation completion."}, review_purpose="plan")
                self.record(task.issue, "plan-review", planning_source, base, {"review": check, "artifacts": {"review": review_artifact}}, accepted=check["verdict"] == "approve")
                if check["verdict"] != "approve":
                    raise PipelineBlocked("plan did not pass independent acceptance coverage review: " + encode(check))
                previous = data.pop("completed_plan_phases", [])
                plan["phases"] = previous + plan["phases"]
                self.checkpoint(task.issue, "working", data, plan=plan, issue=issue, issue_hash=body_hash(issue),
                                original_base=data.get("original_base", base), phase_index=len(previous),
                                merged_phases=data.get("merged_phases", []), attempt=0)
            files = sorted({path for phase in data["plan"]["phases"] for path in phase["files"]})
            self.state.claim(task.issue, files=tuple(files))
            while data["phase_index"] < len(data["plan"]["phases"]):
                if self.stop.is_set():
                    raise PipelineBlocked("controller stopped; source and checkpoints retained")
                self.live_preconditions(task, data["issue_hash"])
                phase = data["plan"]["phases"][data["phase_index"]]
                if not data.get("worktree"):
                    base = self.fetch()
                    identity = f"i-{task.issue}-p-{data['phase_index'] + 1}-" + uuid.uuid4().hex
                    branch = "codex/pipeline/" + identity
                    path = self.config.worktrees / identity
                    with self.git_lock:
                        self.repo.add_worktree(path, branch, base)
                    self.checkpoint(task.issue, "working", data, worktree=str(path), branch=branch, base=base, candidate=None, pr=None)
                path = Path(data["worktree"])
                attempt = data.get("attempt", 0) + 1
                if attempt > self.config.max_attempts:
                    raise PipelineBlocked("bounded repair budget exhausted; review retained feedback")
                self.checkpoint(task.issue, "working", data, attempt=attempt)
                worker, artifact = self.session("worker", self.repo.head(path), {
                    "issue": data["issue"], "phase": phase, "plan": data["plan"],
                    "feedback": data.get("feedback"), "attempt": attempt,
                    "instruction": "Complete this entire phase. Do not commit. Quote each phase acceptance criterion exactly in the result matrix. Build outputs under target/ and fuzz/target/ are allowed disposable outputs."}, writable=path)
                data["worker"] = worker
                data["worker_artifact"] = artifact
                if worker["discoveries"]:
                    if not set(self.repo.changed_paths(path)) <= set(phase["files"]):
                        raise PipelineBlocked("blocked worker changed undeclared source")
                    if self.repo.changed_paths(path):
                        data["candidate"] = self.repo.commit(path, f"Checkpoint partial {task.key} work before discovered prerequisites")
                    self.discoveries(task, data, worker, self.repo.head(path))
                if worker["status"] != "complete":
                    if (not worker["discoveries"] and worker["needs_new_phase"]
                            and data.get("replans", 0) < self.config.max_attempts):
                        if not set(self.repo.changed_paths(path)) <= set(phase["files"]):
                            raise PipelineBlocked("scope expansion request left undeclared source changes")
                        if self.repo.changed_paths(path):
                            data["candidate"] = self.repo.commit(path, f"Checkpoint partial {task.key} work for reviewed replanning")
                        self.checkpoint(task.issue, "blocked", data, dependency_replan=True,
                                        replans=data.get("replans", 0) + 1, replan_feedback=worker)
                    raise PipelineBlocked("worker blocked: " + encode(worker))
                expected = phase["acceptance"]
                observed = [row["criterion"] for row in worker["acceptance"]]
                if sorted(observed) != sorted(expected) or not worker["tests"]:
                    raise PipelineBlocked("worker omitted an acceptance criterion or test evidence")
                changed = self.repo.changed_paths(path)
                merge_base = data.get("pending_merge_base")
                allowed_integration = set(data.get("merge_changed_paths", []))
                if not set(changed) <= set(phase["files"]) | allowed_integration:
                    raise PipelineBlocked("worker changed undeclared source during integration")
                outside = sorted(allowed_integration - set(phase["files"]))
                if merge_base and outside:
                    self.repo.run(["diff", "--exit-code", merge_base, "--", *outside], cwd=path)
                if changed or merge_base:
                    candidate = self.repo.commit(path, f"{task.key}: {phase['name']}")
                else:
                    candidate = self.repo.head(path)
                    if candidate == data["base"]:
                        raise PipelineBlocked("phase produced no committed change; completion needs explicit evidence")
                self.checkpoint(task.issue, "working", data, candidate=candidate,
                                base=merge_base or data["base"], pending_merge_base=None, merge_changed_paths=[])
                try:
                    with self.integration:
                        newest = self.fetch()
                        if newest != data["base"]:
                            if not self.repo.rebase(path, newest):
                                conflicts = self.repo.begin_merge_owned(path, newest)
                                self.state.claim(task.issue, files=tuple(sorted(set(conflicts))))
                                if not set(conflicts) <= set(phase["files"]):
                                    raise PipelineBlocked("integration conflict requires a reviewed scope expansion: " + repr(conflicts))
                                self.checkpoint(task.issue, "working", data, pending_merge_base=newest,
                                                merge_changed_paths=self.repo.changed_paths(path),
                                                feedback={"merge_conflicts": conflicts, "instruction": "Resolve the controller-prepared merge in declared files; do not operate Git. Nonconflicting staged base changes were prepared by the controller and must be preserved."})
                                continue
                            candidate = self.repo.head(path)
                            self.checkpoint(task.issue, "working", data, candidate=candidate, base=newest)
                        self.review_pair(task, data, phase, candidate, data["base"])
                        self.checkpoint(task.issue, "gating", data)
                        validation = self.config.worktrees / "validation"
                        self.repo.prepare_validation_worktree(validation, candidate)
                        output = self.config.state / "gates" / uuid.uuid4().hex
                        proof = self.gate.run(self.repo, validation, candidate, data["base"], output)
                        if (proof.get("source") != candidate or proof.get("base") != data["base"]
                                or proof.get("tree") != self.repo.tree(candidate) or proof.get("result") != "passed"):
                            raise PipelineBlocked("gate response does not prove this candidate/base/tree")
                        if (set(proof.get("artifact_hashes", {})) != {"gate", "log"}
                                or digest_file(Path(proof["artifact"])) != proof["artifact_hashes"]["gate"]
                                or digest_file(Path(proof["log"])) != proof["artifact_hashes"]["log"]):
                            raise PipelineBlocked("gate artifact hashes differ from the accepted runner output")
                        self.record(task.issue, "gate", candidate, data["base"],
                                    {**proof, "artifacts": {"gate": proof["artifact"], "log": proof["log"]}})
                        self.publish_and_promote(task, data, phase)
                except (PipelineBlocked, GateFailure) as error:
                    if data.get("remote_action") in ("promote", "cleanup"):
                        raise
                    feedback = str(error)
                    if isinstance(error, GateFailure):
                        value = {"failure": str(error), "artifacts": {}}
                        if output.exists() and (output / "full-gate.log").is_file():
                            log = output / "full-gate.log"
                            value["artifacts"]["log"] = str(log)
                            with log.open("rb") as stream:
                                stream.seek(max(0, log.stat().st_size - 48 * 1024))
                                feedback += "\nFinal gate log output:\n" + stream.read().decode("utf-8", errors="replace")
                        self.record(task.issue, "gate", candidate, data["base"], value, accepted=False)
                    self.checkpoint(task.issue, "working", data, feedback=feedback)
                    if attempt >= self.config.max_attempts:
                        raise
                    continue
            self.complete(task, data)
        except ClaimConflict as error:
            if claimed:
                self.checkpoint(task.issue, "pending", data, reason=str(error), retry_after=time.time() + self.config.poll_seconds)
                self.state.release(task.issue, owner=str(task.issue))
            self.log("claim waits for its owner", issue=task.issue, reason=str(error))
        except AgentRunError as error:
            failures = data.get("agent_failures", 0) + 1
            status = "pending" if failures < self.config.max_attempts and not self.stop.is_set() else "blocked"
            self.checkpoint(task.issue, status, data, agent_failures=failures,
                            reason=f"Codex session {error.kind}: {error}", retry_after=time.time() + self.config.poll_seconds)
            if claimed and not self.stop.is_set():
                self.state.release(task.issue, owner=str(task.issue))
            self.log("agent session interrupted", issue=task.issue, status=status, kind=error.kind)
        except Exception as error:
            self.checkpoint(task.issue, "blocked", data, reason=str(error))
            # No cleanup on failure: uncertain source and remote actions remain reviewable.
            if claimed and not self.stop.is_set():
                self.state.release(task.issue, owner=str(task.issue))
            self.log("issue blocked", issue=task.issue, reason=str(error))

    def recover(self) -> None:
        if self.config.use_systemd:
            halt_children(self.config.state)
        from .backlog import Backlog
        with self.graph_lock:
            Backlog(self.github, self.config.state, self.config.master_issue).reconcile()
        for record in self.state.recover_interrupted():
            self.state.release(record["issue"])
            self.log("recovered durable task checkpoint", issue=record["issue"], stage=record["interrupted_from"])

    def run(self, *, once=False) -> None:
        if not self.config.use_systemd:
            raise PipelineBlocked("unattended execution requires systemd cgroup containment")
        with SupervisorLock(self.config.state / "supervisor.lock"):
            self.recover()
            with ThreadPoolExecutor(max_workers=self.config.max_issues) as pool:
                active = {}
                while not self.stop.is_set():
                    for number, future in list(active.items()):
                        if future.done():
                            future.result()
                            del active[number]
                    if not (self.config.state / "PAUSED").exists():
                        graph, issues = self.snapshot()
                        tip = self.fetch()
                        completed = {task.issue for task in graph.tasks if issues[task.issue]["state"] == "closed" and self.verified(task.issue, tip)}
                        # Remote intent reconciliation is independent of issue-open readiness.
                        for row in self.state.list_tasks():
                            number = row["issue"]
                            if (number in graph.by_issue and number not in active and row["status"] != "complete"
                                    and row["data"].get("remote_action") in ("push-branch", "create-pr", "promote", "cleanup", "close-issue")
                                    and len(active) < self.config.max_issues):
                                active[number] = pool.submit(self.execute, graph.by_issue[number], issues[number])
                        for task in graph.ready(issues, completed):
                            record = self.state.get_task(task.issue)
                            if record and record["data"].get("dependency_replan"):
                                self.state.set_task(task.issue, "pending", record["data"])
                                record = self.state.get_task(task.issue)
                            if task.issue in active or (record and (record["status"] in ("blocked", "complete") or record["data"].get("retry_after", 0) > time.time())):
                                continue
                            if task.route != "repository":
                                value = {"route": task.route, "issue": issues[task.issue], "source": tip,
                                         "reason": "Specialized qualification requires an explicitly supplied environment or independent evidence; a generic code worker cannot satisfy it."}
                                self.state.set_task(task.issue, "blocked", value)
                                self.record(task.issue, "handoff", tip, tip, value, accepted=False)
                                self.log("specialized handoff required", issue=task.issue, route=task.route)
                                continue
                            if len(active) >= self.config.max_issues:
                                break
                            active[task.issue] = pool.submit(self.execute, task, issues[task.issue])
                        self.update_master(graph, issues, completed)
                    if once:
                        for future in active.values():
                            future.result()
                        return
                    self.stop.wait(self.config.poll_seconds)

    def update_master(self, graph: Graph, issues: dict, completed: set[int]) -> None:
        """Update only the controller-owned status comment; do not race-edit the DAG."""
        with self.graph_lock:
            graph, issues = self.snapshot()
            tip = self.fetch()
            completed = {task.issue for task in graph.tasks if issues[task.issue]["state"] == "closed" and self.verified(task.issue, tip)}
            marker = "<!-- agenc-pipeline-live-status -->"
            records = {row["issue"]: row for row in self.state.list_tasks()}
            lines = [marker, "Automated execution status (accepted receipts are required for completion).", ""]
            for task in sorted(graph.tasks, key=lambda task: (task.level, task.issue)):
                row = records.get(task.issue, {})
                status = "complete" if task.issue in completed else row.get("status", "waiting for prerequisites")
                reason = row.get("data", {}).get("reason", "")
                lines.append(f"- [{'x' if task.issue in completed else ' '}] #{task.issue} {task.key}: {status}" + (" — " + reason.splitlines()[0][:240] if reason else ""))
            body = "\n".join(lines) + "\n"
            matches = [row for row in self.github.comments(graph.master_issue) if marker in (row.get("body") or "")]
            if len(matches) > 1:
                raise PipelineBlocked("duplicate controller master status comments")
            if matches:
                if matches[0]["body"] != body:
                    self.github.api(f"issues/comments/{matches[0]['id']}", "PATCH", {"body": body})
            else:
                self.github.comment(graph.master_issue, body)
            legacy = int(graph.legacy_umbrella["issue"])
            if set(graph.legacy_umbrella["depends_on"]) <= completed and issues[legacy]["state"] == "open":
                self.comment_once(legacy, "<!-- agenc-pipeline-legacy-complete -->", "Every prerequisite now has accepted completion evidence: " + ", ".join("#" + str(n) for n in graph.legacy_umbrella["depends_on"]) + ".")
                self.github.close_issue(legacy)
            if len(completed) == len(graph.tasks) and self.github.issue(legacy)["state"] == "closed":
                self.comment_once(graph.master_issue, "<!-- agenc-pipeline-master-complete -->", "Every task in the validated dependency graph has accepted completion evidence, including external and final release qualification.")
                self.github.close_issue(graph.master_issue)

    def shutdown(self) -> None:
        self.stop.set()
        self.runner.cancel()
        self.gate.cancel()
