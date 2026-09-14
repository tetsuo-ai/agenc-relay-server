"""Offline lifecycle tests use a real local remote and scripted agent/provider edges."""
from __future__ import annotations

import copy
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from issue_pipeline.config import Config, digest_file
from issue_pipeline.backlog import Backlog
from issue_pipeline.controller import Controller, PipelineBlocked, body_hash, encode, task_hash
from issue_pipeline.gate import GateCleanupUncertain, GateFailure, GateRunner, GateStopped
from issue_pipeline.gitops import GitRepo
from issue_pipeline.github import Github
from issue_pipeline.graph import Graph
from issue_pipeline.github import GithubError
from issue_pipeline_tests.test_github import issue_row


REVIEW = {"verdict": "approve", "summary": "All declared criteria were inspected.",
          "findings": [], "acceptance_complete": True, "contract_separated": True}
PHASE = {"name": "Apply the fixture change", "kind": "implementation",
         "files": ["src/service.rs"], "acceptance": ["The fixture contains the corrected value."],
         "validation": [["python3", "-c", "assert True"]]}
PLAN = {"status": "planned", "summary": "Cover the entire fixture issue.",
        "phases": [PHASE], "blockers": []}
EXTERNAL_STATUS_NAMES = ("agenc-pipeline/recorded-gate", "agenc-pipeline/independent-review")


def git(path, *args):
    return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", *args],
                                   cwd=path, text=True, stderr=subprocess.DEVNULL).strip()


class ScriptedGithub:
    """Only provider behavior is mocked; promotion reaches an actual bare remote."""

    def __init__(self, repo, source, repository):
        self.gitrepo, self.repo, self.repository = repo, repository, repository
        record = {"version": 1, "source": source, "master_issue": 35, "final_issue": 86,
                  "lock_policy": "Claim scopes and files.",
                  "legacy_umbrella": {"issue": 13, "depends_on": [36]}, "tasks": [
                      {"key": "ENC-12", "issue": 36, "depends_on": [], "locks": ["auth-account"], "external_gate": False, "level": 0},
                      {"key": "OPS-02", "issue": 41, "depends_on": [], "locks": ["ci"], "external_gate": False, "level": 0},
                      {"key": "REL-13", "issue": 86, "depends_on": [36, 41], "locks": ["signing"], "external_gate": True, "level": 1}]}
        self.issues = {number: {"number": number, "id": number + 1000, "state": "open", "title": f"Fixture {number}",
                                "body": "Complete every declared fixture requirement."}
                       for number in (13, 35, 36, 41, 86)}
        self.issues[35]["body"] = (
            "Current plan: **3 actionable work items, 2 prerequisite edges, and 2 dependency levels**.\n\n"
            "Completion requires all 3 children and the legacy issue closed with evidence.\n\n"
            "## Ordered backlog\n\n| Order | Level | Work item | Must finish first |\n|---:|---:|---|---|\n"
            "| 1 | 0 | [ENC-12 #36](https://github.com/tetsuo-ai/agenc-ircd/issues/36): Fixture | Ready |\n"
            "| 2 | 0 | [OPS-02 #41](https://github.com/tetsuo-ai/agenc-ircd/issues/41): Fixture | Ready |\n"
            "| 3 | 1 | [REL-13 #86](https://github.com/tetsuo-ai/agenc-ircd/issues/86): Release | #36, #41 |\n\n"
            "## Completion checklist\n\n- [ ] #36\n- [ ] #41\n- [ ] #86\n- [ ] #13\n\n"
            "## Machine-readable scheduling graph\n\n```json\n" + json.dumps(record) + "\n```\n")
        self.graph = Graph.from_master(self.issues[35]["body"])
        self.child_links = {35: {13, 36, 41, 86}}
        self.dependencies = {task.issue: set(task.depends_on) for task in self.graph.tasks}
        self.dependencies[13] = {36}
        self.next_issue = 100
        self.prs = {}
        self.comment_rows = {}
        self.close_calls = []
        self.statuses = []
        self.lose_close_response = False
        self.block_hosted = False

    def issue(self, number):
        return {**issue_row(number, self.repo), **copy.deepcopy(self.issues[number])}

    def children(self, number):
        return [self.issue(child) for child in sorted(self.child_links.get(number, set()))]

    def blockers(self, number):
        return [self.issue(dep) for dep in sorted(self.dependencies.get(number, set()))]

    def api(self, endpoint, method="GET", payload=None):
        if endpoint.startswith("issues?") and method == "GET":
            page = int(endpoint.rsplit("page=", 1)[1])
            return [self.issue(number) for number in sorted(self.issues, reverse=True)][(page - 1) * 100:page * 100]
        if endpoint == "issues" and method == "POST":
            number = self.next_issue
            self.next_issue += 1
            self.issues[number] = {"number": number, "id": number + 1000, "state": "open", **payload}
            return self.issue(number)
        if endpoint.endswith("sub_issues"):
            owner = int(endpoint.split("/")[1])
            child = next(number for number, issue in self.issues.items() if issue["id"] == payload["sub_issue_id"])
            self.child_links.setdefault(owner, set()).add(child)
            return self.issue(child)
        if endpoint.endswith("dependencies/blocked_by"):
            owner = int(endpoint.split("/")[1])
            child = next(number for number, issue in self.issues.items() if issue["id"] == payload["issue_id"])
            self.dependencies.setdefault(owner, set()).add(child)
            return self.issue(child)
        if endpoint.startswith("pulls?"):
            return copy.deepcopy(list(self.prs.values()))
        if endpoint.startswith("pulls/") and method == "PATCH":
            number = int(endpoint.split("/")[-1])
            self.prs[number].update(payload)
            return copy.deepcopy(self.prs[number])
        if endpoint.startswith("issues/comments/") and method == "PATCH":
            identity = int(endpoint.split("/")[-1])
            for rows in self.comment_rows.values():
                for row in rows:
                    if row["id"] == identity:
                        row.update(payload)
                        return copy.deepcopy(row)
        if endpoint.startswith("issues/") and method == "PATCH":
            number = int(endpoint.split("/")[-1])
            self.issues[number].update(payload)
            if number == 35:
                self.graph = Graph.from_master(self.issues[35]["body"])
            return self.issue(number)
        raise AssertionError(f"unexpected provider call: {endpoint} {method}")

    def create_pr(self, branch, title, body, base="main"):
        number = 90 + len(self.prs)
        source = self.gitrepo.run(["rev-parse", "refs/heads/" + branch]).strip()
        self.prs[number] = {"number": number, "title": title, "body": body, "state": "open",
                            "head": {"ref": branch, "sha": source},
                            "base": {"ref": base, "repo": {"full_name": self.repository}}}
        return copy.deepcopy(self.prs[number])

    def pr(self, number):
        return copy.deepcopy(self.prs[number])

    def merged_pr(self, number, source):
        if not self.gitrepo.is_ancestor(source, self.gitrepo.fetch()):
            raise PipelineBlocked("PR has not merged")
        self.prs[number].update(state="closed", merged=True, merge_commit_sha=source)
        return copy.deepcopy(self.prs[number])

    def set_status(self, *args):
        self.statuses.append(args)
        raise AssertionError("controller must not publish commit statuses")

    def hosted_checks(self, source, **kwargs):
        return {"state": "failed" if self.block_hosted else "absent", "blocking": self.block_hosted}

    def comments(self, number):
        return copy.deepcopy(self.comment_rows.get(number, []))

    def comment(self, number, body):
        row = {"id": 1 + sum(map(len, self.comment_rows.values())), "body": body}
        self.comment_rows.setdefault(number, []).append(row)
        return copy.deepcopy(row)

    def close_issue(self, number):
        self.close_calls.append(number)
        self.issues[number]["state"] = "closed"
        if self.lose_close_response:
            self.lose_close_response = False
            raise OSError("simulated lost response after remote issue closure")


class ScriptedAgents:
    def __init__(self):
        self.calls = []
        self.reject_code = False
        self.plan = copy.deepcopy(PLAN)

    def cancel(self):
        pass

    def run(self, role, worktree, prompt, output, **kwargs):
        request = json.loads(prompt)
        self.calls.append((role, worktree, request))
        if role == "planner":
            result = copy.deepcopy(self.plan)
        elif role == "reviewer":
            result = copy.deepcopy(REVIEW)
            if self.reject_code and "focus" in request:
                result.update(verdict="request_changes", acceptance_complete=False,
                              summary="The correction does not satisfy the fixture.", findings=[{
                                  "severity": "high", "path": "src/service.rs", "line": 1,
                                  "description": "The acceptance condition still fails."}])
        else:
            for name in request["phase"]["files"]:
                destination = worktree / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("corrected fixture: " + request["phase"]["name"] + "\n")
            result = {"status": "complete", "summary": "Applied the fixture correction.",
                      "acceptance": [{"criterion": criterion, "evidence": "src/service.rs:1"}
                                     for criterion in request["phase"]["acceptance"]],
                      "tests": [{"argv": ["python3", "-c", "assert True"],
                                 "result": "Scripted adapter reports the fixture check passed."}],
                      "discoveries": [], "needs_new_phase": False}
        output.mkdir(parents=True)
        (output / "result.json").write_text(json.dumps(result))
        return result


class ScriptedGate:
    def __init__(self):
        self.calls = []
        self.failures = 0
        self.wrong_source = False
        self.wrong_hash = False
        self.stopped_error = None

    def assert_available(self):
        if self.stopped_error is not None:
            raise self.stopped_error

    def cancel(self):
        pass

    def run(self, repo, worktree, source, base, output):
        self.calls.append((source, base))
        if self.failures:
            self.failures -= 1
            raise GateFailure("fixture regression failed and requires repair")
        output.mkdir(parents=True)
        artifact, log = output / "artifact.json", output / "gate.log"
        artifact.write_text(json.dumps({"source": source, "result": "scripted adapter success"}))
        log.write_text("offline gate adapter: no Rust gate was executed\n")
        return {"source": base if self.wrong_source else source, "tree": repo.tree(source),
                "base": base, "result": "passed", "commands": 1,
                "artifact": str(artifact), "log": str(log),
                "artifact_hashes": {"gate": "f" * 64 if self.wrong_hash else digest_file(artifact),
                                    "log": digest_file(log)}}


class DiscoveryAgents(ScriptedAgents):
    def __init__(self):
        super().__init__()
        self.discovered = False

    def run(self, role, worktree, prompt, output, **kwargs):
        request = json.loads(prompt)
        number = request["issue"]["number"]
        if role == "planner":
            self.plan = copy.deepcopy(PLAN)
            if number >= 100:
                self.plan["phases"][0].update(name="Implement discovered prerequisite", files=["src/fix.rs"])
            elif self.discovered:
                self.plan["phases"][0]["name"] = "Finish parent after accepted prerequisite"
        result = super().run(role, worktree, prompt, output, **kwargs)
        if role == "worker" and number == 36 and not self.discovered:
            self.discovered = True
            (worktree / "src/service.rs").write_text("retained partial owner change\n")
            result.update(status="blocked", summary="A required fixture prerequisite is absent.",
                          acceptance=[], needs_new_phase=True, discoveries=[{
                              "title": "Add the missing fixture prerequisite", "description":
                              "src/fix.rs is absent. The fixture contract requires a separate prerequisite before the parent correction can be accepted.",
                              "acceptance": ["Create the prerequisite fixture before parent acceptance."]}])
            (output / "result.json").write_text(json.dumps(result))
        return result


class MultipleDiscoveryAgents(DiscoveryAgents):
    def run(self, role, worktree, prompt, output, **kwargs):
        result = super().run(role, worktree, prompt, output, **kwargs)
        if role == "worker" and result["discoveries"]:
            result["discoveries"].append({
                "title": "Add the other required fixture prerequisite",
                "description": "src/other_fix.rs is also absent and required by the parent contract.",
                "acceptance": ["Create the other prerequisite before parent acceptance."]})
        if role == "planner" and json.loads(prompt)["issue"]["number"] == 101:
            result["phases"][0]["files"] = ["src/other_fix.rs"]
        (output / "result.json").write_text(json.dumps(result))
        return result


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="agenc-controller-test-")
        self.addCleanup(self.temporary.cleanup)
        parent = Path(self.temporary.name)
        self.config = Config(state_dir=str(parent / "state"), max_attempts=2, max_issues=1)
        cache_environment = mock.patch.dict("os.environ", {"CARGO_HOME": str(parent / "public-cargo")})
        cache_environment.start()
        self.addCleanup(cache_environment.stop)
        self.config.state.mkdir()
        self.remote, seed = parent / "remote.git", parent / "seed"
        git(parent, "init", "--bare", "--initial-branch=main", str(self.remote))
        git(parent, "init", "--initial-branch=main", str(seed))
        for name, value in (("user.name", "Offline Test"), ("user.email", "offline@example.invalid")):
            git(seed, "config", name, value)
        (seed / "src").mkdir()
        (seed / "src/service.rs").write_text("initial fixture\n")
        git(seed, "add", ".")
        git(seed, "commit", "-m", "Initial fixture")
        git(seed, "remote", "add", "origin", str(self.remote))
        git(seed, "push", "origin", "main")
        git(parent, "clone", str(self.remote), str(self.config.clone))
        for name, value in (("user.name", "Offline Test"), ("user.email", "offline@example.invalid")):
            git(self.config.clone, "config", name, value)
        self.repo = GitRepo(self.config.clone, worktree_root=self.config.worktrees)
        self.base = self.repo.fetch()
        self.github = ScriptedGithub(self.repo, self.base, self.config.repository)
        self.runner, self.gate = ScriptedAgents(), ScriptedGate()
        self.controller = Controller(self.config, repo=self.repo, github=self.github,
                                     runner=self.runner, gate=self.gate)
        self.addCleanup(self.controller.state.close)
        self.controller.log = mock.Mock()
        self.task = self.github.graph.by_issue[36]
        self.issue = self.github.issue(36)

    def graph_record(self):
        return json.loads(self.github.issues[35]["body"].split("```json\n", 1)[1].split("\n```", 1)[0])

    def replace_graph(self, value):
        self.github.issues[35]["body"] = "```json\n" + json.dumps(value) + "\n```\n"
        self.github.graph = Graph.from_master(self.github.issues[35]["body"])
        self.github.dependencies = {task.issue: set(task.depends_on) for task in self.github.graph.tasks}
        self.github.dependencies[13] = set(value["legacy_umbrella"]["depends_on"])
        self.github.child_links[35] = {13, *(task.issue for task in self.github.graph.tasks)}
        for task in self.github.graph.tasks:
            self.github.issues.setdefault(task.issue, {"number": task.issue, "id": task.issue + 1000,
                                                       "state": "open", "title": "Fixture prerequisite",
                                                       "body": "Accepted fixture requirements."})

    def accepted_fixture(self, number):
        """Create a real immutable receipt for a scripted qualification fixture."""
        self.github.issues[number]["state"] = "closed"
        self.controller.state.set_task(number, "complete", {})
        return self.controller.record(number, "completion", self.base, self.base,
                                      {"issue_hash": body_hash(self.github.issue(number))})

    def chain(self):
        value = self.graph_record()
        value["tasks"][1].update(depends_on=[36], level=1)
        value["tasks"][2].update(depends_on=[41], level=2)
        self.replace_graph(value)

    def test_snapshot_refuses_foreign_and_mismatched_native_issue_identities(self):
        for relationship in ("children", "blockers"):
            reader = getattr(self.github, relationship)
            for replacement in (issue_row(36, "foreign/private"),
                                issue_row(36, self.config.repository, id=9000),
                                issue_row(36, self.config.repository, node_id="I_foreign")):
                def altered(number):
                    return [replacement if row["number"] == 36 else row for row in reader(number)]
                with self.subTest(relationship=relationship, replacement=replacement), \
                        mock.patch.object(self.github, relationship, side_effect=altered):
                    with self.assertRaises(GithubError):
                        self.controller.snapshot()
                self.assertEqual(self.github.close_calls, [])
                self.assertEqual(self.github.statuses, [])
        graph, issues = self.controller.snapshot()
        self.assertEqual(set(issues), set(graph.by_issue) | {13})

    def test_reopened_or_edited_ancestor_invalidates_descendant_and_live_preconditions(self):
        self.chain()
        self.accepted_fixture(36)
        self.accepted_fixture(41)
        final = self.github.graph.by_issue[86]
        final_hash = body_hash(self.github.issue(86))
        self.assertTrue(self.controller.verified(41, self.base))
        self.controller.live_preconditions(final, final_hash)
        original = self.github.issues[36]["body"]
        for state, body in (("open", original), ("closed", "Changed ancestor requirements")):
            with self.subTest(state=state, body=body):
                self.github.issues[36].update(state=state, body=body)
                self.assertFalse(self.controller.verified(41, self.base))
                with self.assertRaisesRegex(PipelineBlocked, "ancestor"):
                    self.controller.live_preconditions(final, final_hash)
        self.github.issues[36].update(state="closed", body=original)
        self.assertTrue(self.controller.verified(41, self.base))
        self.github.issues[41]["state"] = "open"
        self.assertFalse(self.controller.verified(41, self.base))

    def test_changed_direct_dependencies_require_a_new_graph_bound_completion(self):
        self.accepted_fixture(36)
        old = self.accepted_fixture(41)
        self.assertTrue(self.controller.verified(41, self.base))
        self.chain()
        self.assertNotEqual(old["data"]["task_hash"], task_hash(self.github.graph.by_issue[41]))
        self.assertFalse(self.controller.verified(41, self.base))
        self.accepted_fixture(41)
        self.assertTrue(self.controller.verified(41, self.base))

    def test_changed_ancestor_dependencies_invalidate_unchanged_descendant_binding(self):
        value = self.graph_record()
        value["tasks"][0].update(depends_on=[100], level=1)
        value["tasks"][1].update(depends_on=[36], level=2)
        value["tasks"][2].update(depends_on=[41, 101], level=3)
        value["tasks"] += [{"key": "FIX-01", "issue": 100, "depends_on": [], "locks": ["one"], "external_gate": False, "level": 0},
                           {"key": "FIX-02", "issue": 101, "depends_on": [], "locks": ["two"], "external_gate": False, "level": 0}]
        self.replace_graph(value)
        for number in (100, 101, 36, 41, 86):
            self.accepted_fixture(number)
        descendant = task_hash(self.github.graph.by_issue[41])
        self.assertTrue(self.controller.verified(86, self.base))
        value["tasks"][0]["depends_on"] = [100, 101]
        self.replace_graph(value)
        self.assertEqual(task_hash(self.github.graph.by_issue[41]), descendant)
        self.assertFalse(self.controller.verified(41, self.base))
        self.assertFalse(self.controller.verified(86, self.base))

    def test_unrelated_task_or_master_prose_change_keeps_existing_task_proofs_valid(self):
        self.accepted_fixture(36)
        self.accepted_fixture(41)
        value = self.graph_record()
        value["tasks"].append({"key": "FIX-01", "issue": 100, "depends_on": [],
                               "locks": ["unrelated"], "external_gate": False, "level": 0})
        value["tasks"][2]["depends_on"].append(100)
        self.replace_graph(value)
        self.github.issues[35]["body"] += "\nUpdated operator status, without changed requirements.\n"
        self.assertTrue(self.controller.verified(36, self.base))
        self.assertTrue(self.controller.verified(41, self.base))

    def test_shared_ancestors_are_verified_once_from_one_snapshot_without_provider_reads(self):
        value = self.graph_record()
        value["tasks"][1].update(depends_on=[36], level=1)
        value["tasks"][2].update(depends_on=[41, 100], level=2)
        value["tasks"].append({"key": "FIX-01", "issue": 100, "depends_on": [36],
                               "locks": ["diamond"], "external_gate": False, "level": 1})
        self.replace_graph(value)
        for number in (36, 41, 100, 86):
            self.accepted_fixture(number)
        graph, issues = self.controller.snapshot()
        with mock.patch.object(self.github, "issue", wraps=self.github.issue) as provider:
            with mock.patch.object(self.controller.state, "receipts", wraps=self.controller.state.receipts) as receipts:
                self.assertEqual(self.controller.verified_tasks(graph, issues, self.base), {36, 41, 100, 86})
                self.assertEqual(sorted(call.args for call in receipts.call_args_list),
                                 [(36, "completion"), (41, "completion"), (86, "completion"), (100, "completion")])
            provider.assert_not_called()
        self.github.issues[36]["state"] = "open"
        graph, issues = self.controller.snapshot()
        self.assertEqual(self.controller.verified_tasks(graph, issues, self.base), set())

    def test_requalified_ancestor_receipt_invalidates_descendant_without_body_or_graph_change(self):
        self.chain()
        ancestor = self.accepted_fixture(36)
        descendant = self.accepted_fixture(41)
        self.assertEqual(descendant["data"]["dependency_receipts"], {"36": ancestor["digest"]})
        (self.config.clone / "qualified.txt").write_text("new prerequisite qualification source\n")
        git(self.config.clone, "add", "qualified.txt")
        git(self.config.clone, "commit", "-m", "Qualify changed prerequisite source")
        git(self.config.clone, "push", "origin", "main")
        tip = self.repo.fetch()
        current = self.controller.record(36, "completion", tip, tip,
                                         {"issue_hash": body_hash(self.github.issue(36))})
        self.assertNotEqual(current["digest"], ancestor["digest"])
        self.assertTrue(self.controller.receipt_valid(descendant))
        self.assertTrue(self.repo.is_ancestor(descendant["source"], tip))
        self.assertTrue(self.controller.verified(36, tip))
        self.assertFalse(self.controller.verified(41, tip))

    def test_newest_matching_rejection_revokes_ancestor_and_descendant_receipts(self):
        self.chain()
        accepted = self.accepted_fixture(36)
        self.accepted_fixture(41)
        self.assertTrue(self.controller.verified(41, self.base))
        rejected = self.controller.record(36, "completion", self.base, self.base,
                                          {"issue_hash": body_hash(self.github.issue(36)),
                                           "reason": "Qualification was found inadequate."}, accepted=False)
        self.assertEqual(rejected["data"]["task_hash"], accepted["data"]["task_hash"])
        self.assertEqual(rejected["data"]["dependency_receipts"], accepted["data"]["dependency_receipts"])
        self.assertFalse(self.controller.verified(36, self.base))
        self.assertFalse(self.controller.verified(41, self.base))
        with self.assertRaisesRegex(PipelineBlocked, "ancestor"):
            self.controller.live_preconditions(self.github.graph.by_issue[86], body_hash(self.github.issue(86)))
        self.accepted_fixture(36)
        self.assertTrue(self.controller.verified(36, self.base))
        # A new positive ancestor proof still needs dependent requalification.
        self.assertFalse(self.controller.verified(41, self.base))

    def test_closure_cannot_attach_changed_prerequisite_receipts_to_older_final_review(self):
        self.chain()
        old = self.accepted_fixture(36)
        self.controller.state.set_task(41, "working", {})
        data = {"plan": copy.deepcopy(PLAN), "issue_hash": body_hash(self.github.issue(41)),
                "dependency_receipts": {"36": old["digest"]},
                "merged_phases": [{"phase_index": 0, "source": self.base, "base": self.base, "pr": 90}]}
        self.accepted_fixture(36)
        with self.assertRaisesRegex(PipelineBlocked, "changed after final review"):
            self.controller.complete(self.github.graph.by_issue[41], data)
        self.assertEqual(self.github.issue(41)["state"], "open")
        self.assertEqual(self.controller.state.receipts(41, "completion"), [])
        self.assertNotIn(41, self.github.close_calls)

    def test_completion_source_cannot_predate_current_prerequisite_even_with_its_new_digest(self):
        self.chain()
        self.accepted_fixture(36)
        self.accepted_fixture(41)
        (self.config.clone / "qualified.txt").write_text("prerequisite changed after dependent source\n")
        git(self.config.clone, "add", "qualified.txt")
        git(self.config.clone, "commit", "-m", "Advance prerequisite qualification source")
        git(self.config.clone, "push", "origin", "main")
        tip = self.repo.fetch()
        prerequisite = self.controller.record(36, "completion", tip, tip,
                                              {"issue_hash": body_hash(self.github.issue(36))})
        value = {"issue_hash": body_hash(self.github.issue(41)),
                 "task_hash": task_hash(self.github.graph.by_issue[41]),
                 "dependency_receipts": {"36": prerequisite["digest"]}}
        with self.assertRaisesRegex(PipelineBlocked, "predates"):
            self.controller.record(41, "completion", self.base, self.base, value)
        # Even a forged historical receipt carrying current binding strings
        # cannot evade the independent prerequisite-source ancestry check.
        forged = self.controller.record(41, "forged-fixture", self.base, self.base, value)
        self.controller.state.add_receipt(41, "completion", forged["source"], forged["tree"], forged["base"],
                                           forged["artifact_hashes"], "accepted", forged["data"])
        self.assertTrue(self.controller.receipt_valid(forged))
        self.assertFalse(self.controller.verified(41, tip))

    def test_unbound_historical_completion_is_not_silently_adopted(self):
        number = 41
        self.github.issues[number]["state"] = "closed"
        self.controller.state.set_task(number, "complete", {})
        old = self.controller.record(number, "historical-fixture", self.base, self.base,
                                     {"issue_hash": body_hash(self.github.issue(number))})
        receipt = self.controller.state.add_receipt(number, "completion", old["source"], old["tree"],
                                                     old["base"], old["artifact_hashes"], "accepted", old["data"])
        self.assertTrue(self.controller.receipt_valid(receipt))
        self.assertFalse(self.controller.verified(number, self.base))

    def test_completion_record_rejects_a_stale_caller_graph_binding(self):
        binding = task_hash(self.github.graph.by_issue[41])
        self.controller.state.set_task(41, "complete", {})
        self.chain()
        with self.assertRaisesRegex(PipelineBlocked, "task definition changed"):
            self.controller.record(41, "completion", self.base, self.base,
                                   {"issue_hash": body_hash(self.github.issue(41)), "task_hash": binding})
        self.assertEqual(self.controller.state.receipts(41, "completion"), [])

    def execute(self):
        self.controller.execute(self.task, self.github.issue(36))

    def receipts(self, source=None, base=None):
        source, base = source or self.base, base or self.base
        if self.controller.state.get_task(36) is None:
            self.controller.state.set_task(36, "pending")
        review = self.controller.record(36, "review", source, base,
                                        {"reviews": [copy.deepcopy(REVIEW), copy.deepcopy(REVIEW)]})
        gate = self.controller.record(36, "gate", source, base,
                                      {"source": source, "tree": self.repo.tree(source), "base": base,
                                       "result": "passed", "commands": 1})
        return review, gate

    def test_full_lifecycle_commits_reviews_gates_promotes_closes_and_cleans(self):
        self.execute()
        record = self.controller.state.get_task(36)
        self.assertEqual(record["status"], "complete", record)
        self.assertNotEqual(self.repo.fetch(), self.base)
        self.assertEqual(self.github.issue(36)["state"], "closed")
        self.assertTrue(self.controller.verified(36, self.repo.fetch()))
        self.assertEqual(len(self.github.prs), 1)
        self.assertEqual(len(self.gate.calls), 1)
        self.assertGreaterEqual(sum(role == "reviewer" for role, *_ in self.runner.calls), 3)
        self.assertEqual(self.controller.state.claims(), [])
        self.assertTrue((self.config.worktrees / "validation").exists())
        self.assertFalse(any(path.name.startswith("i-36-") for path in self.config.worktrees.iterdir()))

    def test_missing_and_wrong_base_receipts_block_promotion(self):
        self.controller.state.set_task(36, "pending")
        with self.assertRaises(PipelineBlocked):
            self.controller.require_candidate_receipts(36, self.base, self.base)
        self.receipts()
        with self.assertRaises(PipelineBlocked):
            self.controller.require_candidate_receipts(36, self.base, "f" * 40)
        self.assertEqual(self.repo.fetch(), self.base)

    def test_tampered_artifact_or_tree_invalidates_receipt(self):
        review, _ = self.receipts()
        self.assertTrue(self.controller.receipt_valid(review))
        wrong = copy.deepcopy(review)
        wrong["tree"] = "f" * 40
        self.assertFalse(self.controller.receipt_valid(wrong))
        Path(review["data"]["artifacts"]["record"]).write_text("tampered\n")
        self.assertFalse(self.controller.receipt_valid(review))
        with self.assertRaises(PipelineBlocked):
            self.controller.require_candidate_receipts(36, self.base, self.base)

    def test_latest_rejected_review_cannot_reuse_old_approval(self):
        self.receipts()
        self.controller.record(36, "review", self.base, self.base,
                               {"reviews": [{**REVIEW, "verdict": "request_changes"}]}, accepted=False)
        with self.assertRaises(PipelineBlocked):
            self.controller.require_candidate_receipts(36, self.base, self.base)

    def test_reserved_artifact_name_cannot_replace_immutable_receipt_record(self):
        self.controller.state.set_task(36, "pending")
        impostor = self.config.state / "impostor.json"
        impostor.write_text("{}")
        with self.assertRaises(PipelineBlocked):
            self.controller.record(36, "review", self.base, self.base, {"artifacts": {"record": str(impostor)}})

    def test_rejected_review_never_gates_or_promotes(self):
        self.runner.reject_code = True
        self.execute()
        self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")
        self.assertEqual(self.repo.fetch(), self.base)
        self.assertFalse(self.gate.calls)
        self.assertFalse(self.github.prs)

    def test_gate_failure_gets_bounded_repair_and_fresh_review(self):
        self.gate.failures = 1
        self.execute()
        self.assertEqual(self.controller.state.get_task(36)["status"], "complete")
        self.assertEqual(len(self.gate.calls), 2)
        self.assertEqual(sum(role == "worker" for role, *_ in self.runner.calls), 2)

    def test_uncertain_cleanup_stops_waiting_candidate_before_shared_checkout_changes(self):
        entered_gate, waiting_for_integration = threading.Event(), threading.Event()
        integration = threading.Lock()
        stopped_before_unlock = []
        controller = self.controller

        class ObservedIntegration:
            def __enter__(self):
                if threading.current_thread().name == "second-candidate":
                    waiting_for_integration.set()
                integration.acquire()

            def __exit__(self, kind, error, traceback):
                if isinstance(error, GateCleanupUncertain):
                    stopped_before_unlock.append(controller.stop.is_set())
                integration.release()

        self.controller.integration = ObservedIntegration()
        original_agent = self.runner.run

        def scoped_agent(role, worktree, prompt, output, **kwargs):
            result = original_agent(role, worktree, prompt, output, **kwargs)
            if role == "planner" and json.loads(prompt)["issue"]["number"] == 41:
                result["phases"][0]["files"] = ["src/other.rs"]
                (output / "result.json").write_text(json.dumps(result))
            return result

        def uncertain_gate(repo, worktree, source, base, output):
            self.gate.calls.append((source, base))
            output.mkdir(parents=True)
            (output / "full-gate.log").write_text("Gate writer may still be alive.\n")
            entered_gate.set()
            if not waiting_for_integration.wait(15):
                raise AssertionError("second candidate never reached the integration queue")
            self.gate.stopped_error = GateCleanupUncertain("owned container removal could not be confirmed")
            raise self.gate.stopped_error

        first = threading.Thread(target=self.execute, name="first-candidate")
        second = threading.Thread(target=lambda: self.controller.execute(
            self.github.graph.by_issue[41], self.github.issue(41)), name="second-candidate")
        with mock.patch.object(self.runner, "run", side_effect=scoped_agent), \
                mock.patch.object(self.gate, "run", side_effect=uncertain_gate), \
                mock.patch.object(self.repo, "prepare_validation_worktree",
                                  wraps=self.repo.prepare_validation_worktree) as prepare:
            first.start()
            self.assertTrue(entered_gate.wait(15))
            second.start()
            first.join(20)
            second.join(20)
            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertEqual(prepare.call_count, 1)
        self.assertEqual(stopped_before_unlock, [True])
        self.assertTrue(self.controller.stop.is_set())
        self.assertEqual(len(self.gate.calls), 1)
        self.assertEqual(sum(role == "worker" for role, *_ in self.runner.calls), 2)
        self.assertEqual(self.repo.head(self.config.worktrees / "validation"), self.gate.calls[0][0])
        for number in (36, 41):
            record = self.controller.state.get_task(number)
            self.assertEqual(record["status"], "blocked", record)
            self.assertTrue(Path(record["data"]["worktree"]).exists())
            self.assertEqual(record["data"]["attempt"], 1)
        self.assertTrue(self.controller.state.claims())
        rejected = self.controller.state.receipts(36, "gate")
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["status"], "rejected")
        self.assertTrue(rejected[0]["data"]["cleanup_uncertain"])
        self.assertEqual(self.repo.fetch(), self.base)
        self.assertFalse(self.github.prs)
        self.assertFalse(self.github.close_calls)

    def test_previously_stopped_gate_blocks_before_any_validation_preparation(self):
        runner = GateRunner(self.config)
        runner.cancel()
        self.controller.gate = runner
        with mock.patch.object(self.repo, "prepare_validation_worktree") as prepare, \
                mock.patch.object(runner, "run") as run:
            self.execute()
        prepare.assert_not_called()
        run.assert_not_called()
        self.assertTrue(self.controller.stop.is_set())
        self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")
        self.assertFalse((self.config.worktrees / "validation").exists())
        calls = len(self.runner.calls)
        self.controller.execute(self.github.graph.by_issue[41], self.github.issue(41))
        self.assertEqual(len(self.runner.calls), calls)
        self.assertEqual(self.controller.state.get_task(41)["status"], "blocked")
        self.assertFalse(self.github.prs)

    def test_wrong_source_gate_result_cannot_be_rebound_to_candidate(self):
        self.gate.wrong_source = True
        self.execute()
        self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")
        self.assertEqual(self.repo.fetch(), self.base)
        self.assertFalse(self.github.prs)

    def test_gate_artifact_hash_mismatch_cannot_be_rebound_by_controller(self):
        self.gate.wrong_hash = True
        self.execute()
        self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")
        self.assertEqual(self.repo.fetch(), self.base)
        self.assertFalse(self.github.prs)

    def test_hosted_failure_never_promotes(self):
        self.github.block_hosted = True
        self.execute()
        self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")
        self.assertEqual(self.repo.fetch(), self.base)
        self.assertFalse(self.github.close_calls)

    @contextmanager
    def mutable_hosted_evidence(self, kind, state, context, *, external_arrives_last=False):
        """A status write changes latest-by-context order, just as the provider does."""
        provider = Github(self.github.repository)
        foreign = {"id": 99, "creator": {"id": 999}, "state": state, "context": context,
                   "description": "External hosted result", "target_url": "https://example.invalid/ci"}
        evidence = {"statuses": [foreign] if kind == "status" else [], "writes": [], "reads": []}
        original_api = self.github.api

        def publish(source, payload):
            row = {"id": 100 + len(evidence["writes"]), "creator": {"id": 100}, **payload}
            evidence["writes"].append({"source": source, "payload": copy.deepcopy(payload)})
            evidence["statuses"].insert(0, row)
            if kind == "status" and external_arrives_last:
                evidence["statuses"].remove(foreign)
                evidence["statuses"].insert(0, foreign)
            return row

        def legacy_set_status(source, value, name, description, target_url):
            # Keep the old entry point only in this mutation-sensitive fixture,
            # so the regression demonstrates the original overwrite failure.
            row = publish(source, {"state": value, "context": name, "description": description,
                                   "target_url": target_url})
            return {"version": 1, "repository": self.github.repository, "sha": source,
                    "id": row["id"], "creator_id": row["creator"]["id"],
                    **{field: row[field] for field in ("state", "context", "description", "target_url")}}

        def api(endpoint, method="GET", payload=None):
            relative = endpoint.removeprefix("repos/" + self.github.repository + "/")
            if relative.startswith("statuses/") and method == "POST":
                return publish(relative.split("/", 1)[1], payload)
            return original_api(endpoint, method, payload)

        def classify(source, **kwargs):
            checks = [] if kind != "check" else [
                {"name": context, "head_sha": source,
                 "status": "in_progress" if state == "pending" else "completed",
                 "conclusion": None if state == "pending" else "failure"}]

            def pages(path, member=None):
                if "/check-runs" in path:
                    return copy.deepcopy(checks)
                if "/statuses" in path:
                    return copy.deepcopy(evidence["statuses"])
                if path.startswith("actions/runs?"):
                    return []
                self.fail("unexpected classifier endpoint: " + path)

            with mock.patch.object(provider, "_pages", side_effect=pages):
                result = provider.hosted_checks(source, **kwargs)
            evidence["reads"].append(copy.deepcopy(result))
            return result

        with mock.patch.object(self.github, "set_status", side_effect=legacy_set_status), \
                mock.patch.object(self.github, "api", side_effect=api), \
                mock.patch.object(self.github, "hosted_checks", side_effect=classify):
            yield evidence

    def assert_same_named_external_evidence_blocks(self, kind, state, context, *, external_arrives_last=False):
        with self.mutable_hosted_evidence(kind, state, context, external_arrives_last=external_arrives_last) as evidence, \
                mock.patch.object(self.controller.stop, "wait", return_value=True), \
                mock.patch.object(self.repo, "atomic_promote", wraps=self.repo.atomic_promote) as promote:
            self.execute()
            promote.assert_not_called()
        self.assertEqual(evidence["writes"], [])
        self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")
        self.assertEqual(self.repo.fetch(), self.base)
        self.assertFalse(self.github.close_calls)
        hosted = self.controller.state.receipts(36, "hosted-checks")
        self.assertEqual(hosted[-1]["status"], "rejected")
        self.assertEqual(hosted[-1]["data"]["state"], "pending" if state == "pending" else "failed")

    def test_failed_check_named_for_recorded_gate_blocks_actual_promotion(self):
        self.assert_same_named_external_evidence_blocks("check", "failure", EXTERNAL_STATUS_NAMES[0])

    def test_pending_check_named_for_review_blocks_actual_promotion(self):
        self.assert_same_named_external_evidence_blocks("check", "pending", EXTERNAL_STATUS_NAMES[1])

    def test_preexisting_foreign_failure_cannot_be_overwritten_before_promotion(self):
        self.assert_same_named_external_evidence_blocks("status", "failure", EXTERNAL_STATUS_NAMES[0])

    def test_preexisting_foreign_pending_cannot_be_overwritten_before_promotion(self):
        self.assert_same_named_external_evidence_blocks("status", "pending", EXTERNAL_STATUS_NAMES[1])

    def test_later_foreign_failure_blocks_without_status_writes(self):
        self.assert_same_named_external_evidence_blocks("status", "failure", EXTERNAL_STATUS_NAMES[1],
                                                       external_arrives_last=True)

    def test_later_foreign_pending_blocks_without_status_writes(self):
        self.assert_same_named_external_evidence_blocks("status", "pending", EXTERNAL_STATUS_NAMES[0],
                                                       external_arrives_last=True)

    def test_successful_local_proof_promotes_without_writing_commit_statuses(self):
        with self.mutable_hosted_evidence("empty", None, EXTERNAL_STATUS_NAMES[0]) as evidence:
            self.execute()
        self.assertEqual(evidence["writes"], [])
        self.assertEqual(self.controller.state.get_task(36)["status"], "complete")
        self.assertNotEqual(self.repo.fetch(), self.base)
        self.assertEqual(evidence["reads"][-1]["state"], "empty")
        self.assertFalse(evidence["reads"][-1]["blocking"])
        self.assertEqual(len(self.github.prs), 1)
        pr = next(iter(self.github.prs.values()))
        candidate = pr["head"]["sha"]
        self.assertIn("Source `" + candidate + "`; base `" + self.base + "`", pr["body"])
        published = json.loads(pr["body"].split("```json\n", 1)[1].split("\n```", 1)[0])
        receipts = [row for row in self.controller.state.receipts(36)
                    if row["source"] == candidate and row["kind"] in {"review", "gate"}
                    and row["status"] == "accepted"]
        self.assertEqual(published, [{"kind": row["kind"], "receipt": row["digest"],
                                      "artifacts": row["artifact_hashes"]} for row in receipts])
        self.assertEqual({row["kind"] for row in receipts}, {"review", "gate"})
        review = next(row for row in receipts if row["kind"] == "review")
        self.assertEqual(len(review["data"]["reviews"]), 2)

    def test_scope_conflict_preserves_other_issue_claims(self):
        self.controller.state.set_task(41, "working")
        self.controller.state.claim(41, scopes=self.task.locks)
        original = self.controller.state.claims()
        self.execute()
        self.assertEqual(self.controller.state.get_task(36)["status"], "pending")
        self.assertEqual(self.controller.state.claims(), original)
        self.assertFalse(self.runner.calls)

    def test_conflicting_owner_of_same_issue_keeps_its_claim(self):
        self.controller.state.set_task(36, "working")
        self.controller.state.claim(36, scopes=self.task.locks, owner="foreign-owner")
        original = self.controller.state.claims()
        self.execute()
        self.assertEqual(self.controller.state.claims(), original)
        self.assertFalse(self.runner.calls)

    def test_stale_issue_content_blocks_before_worker(self):
        self.controller.state.set_task(36, "pending", {
            "plan": copy.deepcopy(PLAN), "issue": self.issue, "issue_hash": body_hash(self.issue),
            "original_base": self.base, "phase_index": 0, "merged_phases": [], "attempt": 0})
        self.controller.record(36, "plan", self.base, self.base, {"plan": copy.deepcopy(PLAN)})
        self.controller.record(36, "plan-review", self.base, self.base, {"review": copy.deepcopy(REVIEW)})
        self.github.issues[36]["body"] += " New required behavior."
        self.execute()
        self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")
        self.assertFalse(any(role == "worker" for role, *_ in self.runner.calls))

    def test_plan_approval_cannot_substitute_for_candidate_code_review(self):
        self.controller.state.set_task(36, "pending")
        self.controller.record(36, "plan-review", self.base, self.base, {"review": copy.deepcopy(REVIEW)})
        self.controller.record(36, "gate", self.base, self.base, {"result": "passed"})
        with self.assertRaises(PipelineBlocked):
            self.controller.require_candidate_receipts(36, self.base, self.base)

    def test_positive_source_proof_does_not_authorize_a_changed_issue_body(self):
        self.receipts()
        data = {"candidate": self.base, "base": self.base, "issue_hash": body_hash(self.issue)}
        self.github.issues[36]["body"] += " A new requirement must also be completed."
        with self.assertRaises(PipelineBlocked):
            self.controller.publish_and_promote(self.task, data, PHASE)
        self.assertFalse(self.github.prs)
        self.assertFalse(self.github.statuses)
        self.assertEqual(self.repo.fetch(), self.base)

    def test_crash_after_atomic_promotion_recovers_without_duplicate_worker_or_pr(self):
        promote = self.repo.atomic_promote

        def crash(source, base):
            promote(source, base)
            raise SystemExit("simulated controller crash after remote CAS")

        with mock.patch.object(self.repo, "atomic_promote", side_effect=crash):
            with self.assertRaises(SystemExit):
                self.execute()
        checkpoint = self.controller.state.get_task(36)
        self.assertEqual(checkpoint["data"]["remote_action"], "promote")
        worker_count = sum(role == "worker" for role, *_ in self.runner.calls)
        self.controller.state.recover_interrupted()
        self.controller.state.release(36)
        self.execute()
        self.assertEqual(self.controller.state.get_task(36)["status"], "complete")
        self.assertEqual(sum(role == "worker" for role, *_ in self.runner.calls), worker_count)
        self.assertEqual(len(self.github.prs), 1)

    def test_lost_close_response_reconciles_closed_issue_once(self):
        self.github.lose_close_response = True
        self.execute()
        self.assertEqual(self.github.issue(36)["state"], "closed")
        # Only the interrupted closure remains eligible; ordinary closed or
        # externally blocked tasks must not be turned into fresh code work.
        self.github.issues[41]["state"] = "closed"
        with mock.patch.object(self.controller, "recover"):
            self.controller.run(once=True)
        self.assertEqual(self.controller.state.get_task(36)["status"], "complete")
        self.assertEqual(self.github.close_calls.count(36), 1)
        markers = [row for row in self.github.comments(36) if "agenc-pipeline-completion:" in row["body"]]
        self.assertEqual(len(markers), 1)

    def assert_closure_mutation_is_retained(self, boundary, change):
        if change == "prerequisite":
            graph = self.graph_record()
            graph["tasks"][0].update(depends_on=[41], level=1)
            graph["tasks"][2]["level"] = 2
            self.replace_graph(graph)
            self.task = self.github.graph.by_issue[36]
            self.accepted_fixture(41)

        def mutate():
            if change in ("body", "title"):
                self.github.issues[36][change] += " Changed after final acceptance."
            elif change == "task":
                graph = self.graph_record()
                graph["tasks"][0]["locks"].append("new-scope")
                self.replace_graph(graph)
            else:
                # Even another accepted proof for unchanged prerequisite text
                # must not be attached to the older dependent final review.
                self.accepted_fixture(41)

        comment, close = self.github.comment, self.github.close_issue

        def publish(number, body):
            result = comment(number, body)
            if boundary == "comment" and number == 36 and "agenc-pipeline-completion:" in body:
                mutate()
            return result

        def close_then_change(number):
            result = close(number)
            if boundary == "close" and number == 36:
                mutate()
            return result

        with mock.patch.object(self.github, "comment", side_effect=publish), \
                mock.patch.object(self.github, "close_issue", side_effect=close_then_change):
            self.execute()
        row = self.controller.state.get_task(36)
        self.assertEqual(row["status"], "blocked", row)
        self.assertEqual(row["data"]["remote_action"], "close-issue")
        receipts = self.controller.state.receipts(36, "completion")
        self.assertEqual(len(receipts), 1)
        self.assertEqual(row["data"]["completion_receipt"], receipts[0]["digest"])
        self.assertEqual(self.github.issue(36)["state"], "open" if boundary == "comment" else "closed")
        self.assertFalse(self.controller.verified(36, self.repo.fetch()))
        self.assertTrue(any(claim["issue"] == 36 for claim in self.controller.state.claims()))
        closes, comments = len(self.github.close_calls), len(self.github.comments(36))

        # A fresh controller receives the *new* task definition on restart.
        # It must retain the original intent, not mint a newly bound receipt.
        self.controller = Controller(self.config, repo=self.repo, github=self.github,
                                     runner=self.runner, gate=self.gate)
        self.addCleanup(self.controller.state.close)
        self.controller.log = mock.Mock()
        self.controller.execute(self.github.graph.by_issue[36], self.github.issue(36))
        restarted = self.controller.state.get_task(36)
        self.assertEqual(restarted["status"], "blocked", restarted)
        self.assertEqual(restarted["data"]["completion_receipt"], receipts[0]["digest"])
        self.assertEqual(self.controller.state.receipts(36, "completion"), receipts)
        self.assertEqual(len(self.github.close_calls), closes)
        self.assertEqual(len(self.github.comments(36)), comments)
        self.assertTrue(any(claim["issue"] == 36 for claim in self.controller.state.claims()))

    def test_comment_requirement_edit_preserves_original_closure_intent(self):
        self.assert_closure_mutation_is_retained("comment", "body")

    def test_comment_title_edit_preserves_original_closure_intent(self):
        self.assert_closure_mutation_is_retained("comment", "title")

    def test_close_requirement_edit_cannot_finalize_or_rebind_on_restart(self):
        self.assert_closure_mutation_is_retained("close", "body")

    def test_comment_task_edit_cannot_rebind_original_closure_receipt_on_restart(self):
        self.assert_closure_mutation_is_retained("comment", "task")

    def test_close_task_edit_cannot_rebind_original_closure_receipt_on_restart(self):
        self.assert_closure_mutation_is_retained("close", "task")

    def test_comment_prerequisite_proof_change_blocks_closure_and_restart(self):
        self.assert_closure_mutation_is_retained("comment", "prerequisite")

    def test_close_prerequisite_proof_change_blocks_finalization_and_restart(self):
        self.assert_closure_mutation_is_retained("close", "prerequisite")

    def test_final_issue_readback_follows_slow_prerequisite_verification(self):
        verify = self.controller.verified_receipts

        def verify_then_edit(*args):
            result = verify(*args)
            if 36 in self.github.close_calls:
                self.github.issues[36]["body"] += " Requirement changed during final proof reads."
            return result

        with mock.patch.object(self.controller, "verified_receipts", side_effect=verify_then_edit):
            self.execute()
        row = self.controller.state.get_task(36)
        self.assertEqual(row["status"], "blocked", row)
        self.assertIn("final readback", row["data"]["reason"])
        self.assertEqual(row["data"]["remote_action"], "close-issue")
        self.assertTrue(self.controller.state.claims())

    def test_legacy_close_intent_without_pinned_receipt_cannot_be_adopted(self):
        self.github.lose_close_response = True
        self.execute()
        data = self.controller.state.get_task(36)["data"]
        del data["completion_receipt"]
        self.controller.state.set_task(36, "blocked", data)
        self.execute()
        row = self.controller.state.get_task(36)
        self.assertEqual(row["status"], "blocked")
        self.assertIn("original completion receipt", row["data"]["reason"])
        self.assertEqual(len(self.controller.state.receipts(36, "completion")), 1)
        self.assertEqual(self.github.close_calls, [36])

    def test_specialized_ready_issue_gets_handoff_without_generic_agent(self):
        body = self.github.issues[35]["body"].replace('"ENC-12"', '"STO-01"')
        self.github.issues[35]["body"] = body
        self.github.graph = Graph.from_master(body)
        self.github.issues[41]["state"] = "closed"
        with mock.patch.object(self.controller, "recover"):
            self.controller.run(once=True)
        self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")
        self.assertEqual(self.controller.state.get_task(36)["data"]["route"], "upstream")
        self.assertFalse(self.runner.calls)

    def test_duplicate_phase_indices_cannot_substitute_for_a_missing_phase(self):
        self.execute()
        data = self.controller.state.get_task(36)["data"]
        data["plan"]["phases"].append(copy.deepcopy(PHASE))
        data["merged_phases"].append(copy.deepcopy(data["merged_phases"][0]))
        with self.assertRaises(PipelineBlocked):
            self.controller.complete(self.task, data)

    def test_closure_requires_every_earlier_phase_receipt_to_remain_valid(self):
        self.runner.plan["phases"].append({**copy.deepcopy(PHASE), "name": "Finish second phase",
                                             "files": ["src/second.rs"]})
        self.execute()
        record = self.controller.state.get_task(36)
        self.assertEqual(record["status"], "complete", record)
        data = record["data"]
        first_source = data["merged_phases"][0]["source"]
        receipts = [receipt for receipt in self.controller.state.receipts(36, "review")
                    if receipt["source"] == first_source]
        Path(receipts[-1]["data"]["artifacts"]["record"]).unlink()
        with self.assertRaises(PipelineBlocked):
            self.controller.complete(self.task, data)

    def test_closure_requires_merged_source_still_reachable_from_remote_main(self):
        self.execute()
        data = self.controller.state.get_task(36)["data"]
        with mock.patch.object(self.repo, "fetch", return_value=self.base):
            with self.assertRaises(PipelineBlocked):
                self.controller.complete(self.task, data)

    def test_repeated_closure_reuses_completion_receipt_and_comment(self):
        self.execute()
        data = self.controller.state.get_task(36)["data"]
        # A fully finalized repeat may return or refuse the already-closed
        # issue; neither outcome may publish a second closure receipt/comment.
        try:
            self.controller.complete(self.task, data)
        except PipelineBlocked:
            pass
        self.assertEqual(len(self.controller.state.receipts(36, "completion")), 1)
        self.assertEqual(self.github.close_calls.count(36), 1)
        comments = [row for row in self.github.comments(36) if "agenc-pipeline-completion:" in row["body"]]
        self.assertEqual(len(comments), 1)

    def discover_parent(self):
        self.runner = DiscoveryAgents()
        self.controller.runner = self.runner
        self.github.issues[41]["state"] = "closed"
        self.execute()
        record = self.controller.state.get_task(36)
        self.assertEqual(record["status"], "blocked", record)
        self.assertTrue(record["data"].get("dependency_replan"), record["data"].get("reason"))
        retained = Path(record["data"]["worktree"])
        self.assertTrue(retained.exists())
        self.assertEqual(self.repo.changed_paths(retained), [])
        self.assertEqual(self.github.graph.by_issue[100].key, "FIX-01")
        self.assertIn(100, self.github.graph.by_issue[36].depends_on)
        return retained

    def test_discovered_fix_closure_automatically_replans_and_resumes_parent(self):
        retained = self.discover_parent()
        with mock.patch.object(self.controller, "recover"):
            self.controller.run(once=True)
            self.assertEqual(self.controller.state.get_task(100)["status"], "complete")
            self.assertEqual(self.github.issue(100)["state"], "closed")
            self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")
            self.controller.run(once=True)
        parent = self.controller.state.get_task(36)
        self.assertEqual(parent["status"], "complete", parent)
        self.assertEqual(self.github.issue(36)["state"], "closed")
        self.assertFalse(retained.exists())
        plans = [request for role, _, request in self.runner.calls
                 if role == "planner" and request["issue"]["number"] == 36]
        self.assertEqual(len(plans), 2)
        self.assertEqual(plans[-1]["retained_unmerged_paths"], ["src/service.rs"])
        self.assertEqual(body_hash(plans[-1]["issue"]), body_hash(self.github.issue(36)))
        self.assertNotEqual(body_hash(plans[0]["issue"]), body_hash(plans[-1]["issue"]))
        self.assertTrue((self.config.worktrees / "validation/src/fix.rs").exists())
        self.assertEqual(self.github.next_issue, 101)

    def test_discovered_fix_closed_without_proof_does_not_resume_parent(self):
        self.discover_parent()
        calls = len(self.runner.calls)
        self.github.issues[100]["state"] = "closed"
        with mock.patch.object(self.controller, "recover"):
            self.controller.run(once=True)
        self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")
        self.assertEqual(len(self.runner.calls), calls)

    def interrupt_discovery_registration(self, boundary):
        self.runner = MultipleDiscoveryAgents() if boundary == "between-entries" else DiscoveryAgents()
        self.controller.runner = self.runner
        self.github.issues[41]["state"] = "closed"
        original = Backlog.register
        original_api = self.github.api

        def interrupted_register(backlog, *args, **kwargs):
            if boundary == "before-register":
                raise SystemExit("crash before Backlog creates its journal")
            number = original(backlog, *args, **kwargs)
            if boundary == "after-register":
                raise SystemExit("crash after remote registration, before cursor checkpoint")
            return number

        def interrupted_log(message, **kwargs):
            if boundary == "between-entries" and message == "registered verified prerequisite":
                raise SystemExit("crash after first cursor checkpoint, before next review")

        def interrupted_api(endpoint, method="GET", payload=None):
            result = original_api(endpoint, method, payload)
            if boundary == "during-register" and endpoint == "issues" and method == "POST":
                raise SystemExit("crash after creation, before linking the new child")
            return result

        with mock.patch.object(Backlog, "register", interrupted_register):
            with mock.patch.object(self.controller, "log", side_effect=interrupted_log):
                with mock.patch.object(self.github, "api", side_effect=interrupted_api):
                    with self.assertRaises(SystemExit):
                        self.execute()
        record = self.controller.state.get_task(36)
        pending = record["data"]["pending_discoveries"]
        self.assertEqual(record["data"]["remote_action"], "register-discoveries")
        self.assertTrue(record["data"]["dependency_replan"])
        self.assertEqual(pending["cursor"], 1 if boundary == "between-entries" else 0)
        retained = Path(record["data"]["worktree"])
        self.assertEqual(self.repo.head(retained), pending["source"])
        self.assertEqual(self.repo.changed_paths(retained), [])
        if boundary == "before-register":
            self.assertEqual(list((self.config.state / "backlog").glob("*.json")), [])
            self.assertNotIn(100, self.github.issues)
        elif boundary == "during-register":
            self.assertIn(100, self.github.issues)
            self.assertNotIn(100, self.github.graph.by_issue)
        else:
            self.assertIn(100, self.github.graph.by_issue[36].depends_on)
        # New controller and SQLite connection exercise actual restart recovery;
        # native child containment is the only recovery boundary mocked here.
        self.controller = Controller(self.config, repo=self.repo, github=self.github,
                                     runner=self.runner, gate=self.gate)
        self.controller.log = mock.Mock()
        self.addCleanup(self.controller.state.close)
        return retained, len(pending["entries"])

    def assert_discovery_restart_completes(self, boundary):
        retained, count = self.interrupt_discovery_registration(boundary)
        with mock.patch("issue_pipeline.controller.halt_children"):
            # First dispatch reconciles intent; then each dependency and the
            # parent complete in DAG order with real local Git promotion.
            for _ in range(count + 2):
                self.controller.run(once=True)
        parent = self.controller.state.get_task(36)
        self.assertEqual(parent["status"], "complete", parent)
        self.assertFalse(parent["data"].get("pending_discoveries"))
        self.assertIsNone(parent["data"].get("remote_action"))
        self.assertEqual(self.github.next_issue, 100 + count)
        self.assertFalse(retained.exists())
        for number in range(100, 100 + count):
            self.assertEqual(self.controller.state.get_task(number)["status"], "complete")
            self.assertTrue(self.controller.verified(number, self.repo.fetch()))
        plans = [request for role, _, request in self.runner.calls
                 if role == "planner" and request["issue"]["number"] == 36]
        self.assertEqual(len(plans), 2)
        self.assertEqual(plans[-1]["retained_unmerged_paths"], ["src/service.rs"])
        self.assertEqual(body_hash(plans[-1]["issue"]), body_hash(self.github.issue(36)))
        self.assertNotEqual(body_hash(plans[0]["issue"]), body_hash(plans[-1]["issue"]))
        reviews = self.controller.state.receipts(36, "discovery-review")
        self.assertEqual(len(reviews), count)
        self.assertTrue(all(item["status"] == "accepted" and self.controller.receipt_valid(item)
                            for item in reviews))
        original_catalog = json.loads(Path(reviews[0]["data"]["artifacts"]["backlog"]).read_text())
        self.assertNotIn(100, {item["number"] for item in original_catalog["issues"]})
        self.assertIn(100, self.github.graph.by_issue)

    def test_discovery_restart_after_remote_registration_replans_parent(self):
        self.assert_discovery_restart_completes("after-register")

    def test_discovery_restart_before_backlog_journal_still_registers_prerequisite(self):
        self.assert_discovery_restart_completes("before-register")

    def test_discovery_restart_between_entries_preserves_remaining_discoveries(self):
        self.assert_discovery_restart_completes("between-entries")

    def assert_discovery_recovery_refuses_without_publication(self, expected="no matching approved pending queue"):
        issues = copy.deepcopy(self.github.issues)
        dependencies = copy.deepcopy(self.github.dependencies)
        children = copy.deepcopy(self.github.child_links)
        journals = {path: path.read_bytes() for path in (self.config.state / "backlog").glob("*.json")}
        with mock.patch("issue_pipeline.controller.halt_children") as halt, \
                mock.patch.object(self.github, "api", wraps=self.github.api) as api:
            with self.assertRaisesRegex(PipelineBlocked, expected):
                self.controller.recover()
        halt.assert_called_once_with(self.config.state)
        self.assertTrue(all((call.args[1] if len(call.args) > 1 else call.kwargs.get("method", "GET")) == "GET"
                            for call in api.call_args_list))
        self.assertEqual(self.github.issues, issues)
        self.assertEqual(self.github.dependencies, dependencies)
        self.assertEqual(self.github.child_links, children)
        self.assertEqual({path: path.read_bytes() for path in journals}, journals)

    def test_recovery_rejects_legacy_orphan_journal_without_queue_proof(self):
        self.interrupt_discovery_registration("during-register")
        row = self.controller.state.get_task(36)
        row["data"].pop("pending_discoveries")
        self.controller.state.set_task(36, "blocked", row["data"])
        self.assert_discovery_recovery_refuses_without_publication()

    def test_recovery_rejects_pending_journal_without_its_queue_approval(self):
        self.interrupt_discovery_registration("during-register")
        row = self.controller.state.get_task(36)
        del row["data"]["pending_discoveries"]["entries"][0]["review_receipt"]
        self.controller.state.set_task(36, "blocked", row["data"])
        self.assert_discovery_recovery_refuses_without_publication()

    def test_recovery_rejects_journal_source_or_review_differing_from_valid_queue_receipt(self):
        self.interrupt_discovery_registration("during-register")
        path = next((self.config.state / "backlog").glob("*.json"))
        journal = json.loads(path.read_text())
        for changes in ({"source": self.base}, {"review": {**journal["review"], "summary": "Different approval"}}):
            with self.subTest(changes=changes):
                path.write_text(json.dumps({**journal, **changes}))
                self.assert_discovery_recovery_refuses_without_publication()

    def test_every_pending_journal_is_validated_before_any_recovery_replay(self):
        self.interrupt_discovery_registration("during-register")
        backlog = Backlog(self.github, self.config.state, self.config.master_issue)
        original_path = next(backlog.directory.glob("*.json"))
        original = json.loads(original_path.read_text())
        # Simulate a second inherited journal whose queue proof is missing.
        # Put it after the valid operation in replay order so streaming
        # validate/replay would already have changed GitHub before refusing it.
        for index in range(1000):
            discovery = {**original["discovery"], "title": f"Orphan operation {index}"}
            identity, orphan_path = backlog._identity_path(41, discovery)
            if orphan_path.name > original_path.name:
                break
        else:
            self.fail("could not construct deterministic journal replay ordering")
        orphan = {**original, "parent": 41, "discovery": discovery,
                  "marker": f"<!-- issue-pipeline-discovery:{identity} -->"}
        orphan_path.write_text(json.dumps(orphan))
        orphan_path.chmod(0o600)
        self.assert_discovery_recovery_refuses_without_publication()

    def test_matching_interrupted_journal_replays_original_review_without_new_catalog_approval(self):
        self.interrupt_discovery_registration("during-register")
        reviews = self.controller.state.receipts(36, "discovery-review")
        self.assertNotIn(100, self.github.graph.by_issue)
        calls = len(self.runner.calls)
        with mock.patch("issue_pipeline.controller.halt_children"):
            self.controller.recover()
        self.assertIn(100, self.github.graph.by_issue)
        self.assertEqual(self.github.next_issue, 101)
        self.assertEqual(len(self.runner.calls), calls)
        row = self.controller.state.get_task(36)
        self.controller.resume_discoveries(self.github.graph.by_issue[36], row["data"])
        self.assertIsNone(self.controller.state.get_task(36)["data"]["pending_discoveries"])
        self.assertEqual(self.controller.state.receipts(36, "discovery-review"), reviews)
        self.assertEqual(self.github.next_issue, 101)
        self.assertEqual(len(self.runner.calls), calls)

    def test_discovery_restart_refuses_missing_approved_review_artifact(self):
        retained, _ = self.interrupt_discovery_registration("before-register")
        receipt = self.controller.state.receipts(36, "discovery-review")[0]
        Path(receipt["data"]["artifacts"]["review"]).unlink()
        calls = len(self.runner.calls)
        with mock.patch("issue_pipeline.controller.halt_children"):
            for _ in range(2):
                with self.assertRaisesRegex(PipelineBlocked, "source-bound review artifact"):
                    self.controller.run(once=True)
        parent = self.controller.state.get_task(36)
        self.assertEqual(parent["status"], "blocked")
        self.assertIn("source-bound review artifact", parent["data"]["reason"])
        self.assertIsNone(parent["data"].get("remote_action"))
        self.assertTrue(parent["data"]["pending_discoveries"])
        self.assertEqual(self.github.next_issue, 100)
        self.assertTrue(retained.exists())
        self.assertEqual(len(self.runner.calls), calls)

    def test_discovery_snapshot_is_complete_and_granted_as_one_exact_readonly_evidence_file(self):
        self.runner = DiscoveryAgents()
        self.controller.runner = self.runner
        self.github.issues[41].update(state="closed", body="Complete existing acceptance.\n" * 1000 + "FULL-BODY-END")
        expected = {number: self.github.issue(number) for number in (13, 36, 41, 86)}
        original = self.runner.run
        observed = []

        def inspect_context(role, worktree, prompt, output, **kwargs):
            request = json.loads(prompt)
            if kwargs.get("review_purpose") == "discovery":
                reference = request["managed_backlog"]
                path = Path(reference["path"])
                # session forwards one trusted exact file to the permission
                # profile, whose evidence-path rule grants read access only.
                self.assertEqual(kwargs["evidence_paths"], (path,))
                self.assertTrue(path.is_file())
                self.assertFalse(path.is_relative_to(worktree))
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(digest_file(path), reference["sha256"])
                self.assertLess(len(prompt.encode()), 512 * 1024)
                catalog = json.loads(path.read_text())
                self.assertEqual(reference["issue_count"], 4)
                self.assertEqual(catalog["master"]["number"], 35)
                self.assertEqual({item["issue"] for item in catalog["graph"]["tasks"]}, {36, 41, 86})
                self.assertEqual({item["number"] for item in catalog["issues"]}, set(expected))
                for row in catalog["issues"]:
                    for field in ("title", "body", "state"):
                        self.assertEqual(row[field], expected[row["number"]][field])
                    self.assertIn("locks", row)
                    self.assertIn("depends_on", row)
                self.assertIn("outside this managed backlog are not included", catalog["scope"])
                observed.append(path)
            return original(role, worktree, prompt, output, **kwargs)

        with mock.patch.object(self.runner, "run", side_effect=inspect_context):
            self.execute()
        self.assertEqual(len(observed), 1)
        receipt = self.controller.state.receipts(36, "discovery-review")[0]
        self.assertEqual(receipt["data"]["artifacts"]["backlog"], str(observed[0]))
        self.assertEqual(receipt["artifact_hashes"]["backlog"], receipt["data"]["backlog_hash"])
        self.assertTrue(self.controller.receipt_valid(receipt))

    def test_stale_discovery_catalog_gets_fresh_review_before_any_publication(self):
        self.runner = DiscoveryAgents()
        self.controller.runner = self.runner
        original = self.runner.run
        catalogs = []

        def change_coverage(role, worktree, prompt, output, **kwargs):
            result = original(role, worktree, prompt, output, **kwargs)
            if kwargs.get("review_purpose") == "discovery":
                reference = json.loads(prompt)["managed_backlog"]
                catalogs.append(json.loads(Path(reference["path"]).read_text()))
                if len(catalogs) == 1:
                    self.github.issues[41]["body"] += "\nExisting issue covers the proposed prerequisite."
                else:
                    existing = next(item for item in catalogs[-1]["issues"] if item["number"] == 41)
                    self.assertIn("covers the proposed prerequisite", existing["body"])
                    result.update(verdict="request_changes", acceptance_complete=False,
                                  summary="Issue41 already covers this proposed prerequisite.")
                    (output / "result.json").write_text(json.dumps(result))
            return result

        with mock.patch.object(self.runner, "run", side_effect=change_coverage):
            with mock.patch.object(Backlog, "register") as register:
                self.execute()
                register.assert_not_called()
        self.assertEqual(len(catalogs), 2)
        self.assertEqual(self.github.next_issue, 100)
        self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")
        reviews = self.controller.state.receipts(36, "discovery-review")
        self.assertEqual([item["status"] for item in reviews], ["accepted", "rejected"])
        self.assertNotEqual(reviews[0]["data"]["backlog_hash"], reviews[1]["data"]["backlog_hash"])

    def test_repeated_catalog_changes_exhaust_bounded_review_budget_without_publication(self):
        self.runner = DiscoveryAgents()
        self.controller.runner = self.runner
        original = self.runner.run

        def change_every_review(role, worktree, prompt, output, **kwargs):
            result = original(role, worktree, prompt, output, **kwargs)
            if kwargs.get("review_purpose") == "discovery":
                self.github.issues[41]["body"] += "\nChanged requirement."
            return result

        with mock.patch.object(self.runner, "run", side_effect=change_every_review):
            with mock.patch.object(Backlog, "register") as register:
                self.execute()
                register.assert_not_called()
        self.assertEqual(len(self.controller.state.receipts(36, "discovery-review")), self.config.max_attempts)
        self.assertIn("review budget exhausted", self.controller.state.get_task(36)["data"]["reason"])
        self.assertEqual(self.github.next_issue, 100)

    def test_damaged_catalog_blocks_recovery_before_incomplete_backlog_publication(self):
        self.interrupt_discovery_registration("during-register")
        receipt = self.controller.state.receipts(36, "discovery-review")[0]
        snapshot = Path(receipt["data"]["artifacts"]["backlog"])
        snapshot.write_text(snapshot.read_text() + "\ncorrupted")
        issues = copy.deepcopy(self.github.issues)
        dependencies = copy.deepcopy(self.github.dependencies)
        with mock.patch("issue_pipeline.controller.halt_children"):
            for _ in range(2):
                with self.assertRaisesRegex(PipelineBlocked, "managed backlog snapshot"):
                    self.controller.recover()
        self.assertEqual(self.github.issues, issues)
        self.assertEqual(self.github.dependencies, dependencies)
        self.assertNotIn(100, self.github.graph.by_issue)
        self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")

    def test_complete_catalog_size_bound_is_exact_and_never_truncates(self):
        catalog, digest = self.controller.managed_backlog()
        size = len(encode(catalog).encode())
        with mock.patch("issue_pipeline.controller.MAX_MANAGED_BACKLOG_BYTES", size):
            self.assertEqual(self.controller.managed_backlog(), (catalog, digest))
        with mock.patch("issue_pipeline.controller.MAX_MANAGED_BACKLOG_BYTES", size - 1):
            with self.assertRaisesRegex(PipelineBlocked, "snapshot byte bound"):
                self.controller.managed_backlog()
        self.runner = DiscoveryAgents()
        self.controller.runner = self.runner
        with mock.patch("issue_pipeline.controller.MAX_MANAGED_BACKLOG_BYTES", 1):
            self.execute()
        self.assertEqual(self.github.next_issue, 100)
        self.assertFalse((self.config.state / "backlog-reviews").exists())
        self.assertFalse(any("discovery" in request for _, _, request in self.runner.calls))

    def test_rejected_later_discovery_cannot_be_skipped_when_first_prerequisite_completes(self):
        self.runner = MultipleDiscoveryAgents()
        self.controller.runner = self.runner
        self.github.issues[41]["state"] = "closed"
        original = self.runner.run

        def reject_second(role, worktree, prompt, output, **kwargs):
            result = original(role, worktree, prompt, output, **kwargs)
            request = json.loads(prompt)
            if (kwargs.get("review_purpose") == "discovery"
                    and request["discovery"]["title"] == "Add the other required fixture prerequisite"):
                result.update(verdict="request_changes", acceptance_complete=False,
                              summary="The second proposed prerequisite is not supported.")
                (output / "result.json").write_text(json.dumps(result))
            return result

        with mock.patch.object(self.runner, "run", side_effect=reject_second):
            self.execute()
        parent = self.controller.state.get_task(36)
        self.assertEqual(parent["data"]["pending_discoveries"]["cursor"], 1)
        self.assertTrue(parent["data"]["dependency_replan"])
        self.assertIsNone(parent["data"].get("remote_action"))
        with mock.patch("issue_pipeline.controller.halt_children"):
            self.controller.run(once=True)
            self.controller.run(once=True)
        self.assertEqual(self.controller.state.get_task(100)["status"], "complete")
        self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")
        self.assertEqual(self.github.next_issue, 101)
        parent_plans = [request for role, _, request in self.runner.calls
                        if role == "planner" and request["issue"]["number"] == 36]
        self.assertEqual(len(parent_plans), 1)


if __name__ == "__main__":
    unittest.main()
