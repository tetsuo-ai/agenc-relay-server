"""Offline operator-command admission and retained external-attestation behavior.

Network, authentication and systemd are mocked. Artifact copying and SQLite
checkpoints use private temporary directories, including ambiguous close retry.
"""
from __future__ import annotations

import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from issue_pipeline.config import Config, digest_file, private_directory
from issue_pipeline.controller import Controller, PipelineBlocked
from issue_pipeline.graph import Graph, Task
from issue_pipeline.github import GithubError
from issue_pipeline_tests.test_github import issue_row
from issue_pipeline.state import ClaimConflict, State, SupervisorLock

CLI_PATH = Path(__file__).resolve().parents[1] / "issue-pipeline.py"
SPEC = importlib.util.spec_from_file_location("issue_pipeline_operator_cli", CLI_PATH)
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)
SOURCE, TREE, TIP = "a" * 40, "b" * 40, "c" * 40


def graph_body():
    return '```json\n' + json.dumps({
        "version": 1, "source": SOURCE, "master_issue": 35, "final_issue": 43,
        "lock_policy": "Claim exact files.",
        "legacy_umbrella": {"issue": 13, "depends_on": [36]},
        "tasks": [
            {"key": "ENC-01", "issue": 36, "depends_on": [], "locks": ["normative"],
             "external_gate": False, "level": 0},
            {"key": "REL-01", "issue": 43, "depends_on": [36], "locks": ["host"],
             "external_gate": False, "level": 1},
        ],
    }) + '\n```\n'


class CommandFixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agenc-cli-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = Config(state_dir=str(self.root / "state"), minimum_free_gib=1)
        self.config_file = self.root / "config.toml"
        self.config_file.write_text('version = 1\nstate_dir = ' + json.dumps(str(self.config.state)) + '\n')

    def invoke(self, *args):
        output = io.StringIO()
        with mock.patch.object(sys, "argv", [str(CLI_PATH), "--config", str(self.config_file), *args]), redirect_stdout(output):
            self.assertEqual(cli.main(), 0)
        return output.getvalue()


class LocalCommandTests(CommandFixture, unittest.TestCase):
    def test_fresh_status_does_not_create_database_or_start_controller(self):
        with mock.patch.object(cli, "Controller") as controller:
            value = json.loads(self.invoke("status"))
        self.assertEqual(value["status"], "not started")
        self.assertFalse(self.config.state.exists())
        controller.assert_not_called()

    def test_pause_resume_are_idempotent_local_controls(self):
        with mock.patch.object(cli, "Controller") as controller:
            self.invoke("pause")
            self.invoke("pause")
            flag = self.config.state / "PAUSED"
            self.assertEqual(flag.stat().st_mode & 0o777, 0o600)
            self.invoke("resume")
            self.invoke("resume")
        self.assertFalse(flag.exists())
        controller.assert_not_called()

    def test_retry_preserves_checkpoint_and_resets_only_attempt_controls(self):
        private_directory(self.config.state)
        data = {"attempt": 3, "reason": "test failed", "retry_after": 999,
                "plan": {"phases": ["retained"]}, "worktree": "/retained/worktree",
                "candidate": SOURCE, "phase_index": 2, "pr": 89,
                "remote_action": "promote", "feedback": "retained failure evidence"}
        with State(self.config.state / "state.sqlite3") as state:
            state.set_task(43, "blocked", data)
        result = json.loads(self.invoke("retry", "43"))
        self.assertEqual(result["status"], "pending")
        with State(self.config.state / "state.sqlite3") as state:
            row = state.get_task(43)
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["data"], {**data, "attempt": 0, "reason": None, "retry_after": 0})

    def test_retry_resets_only_remaining_discovery_budgets_and_preserves_approval_bindings(self):
        private_directory(self.config.state)
        data = {"attempt": 3, "reason": "discovery review budget exhausted", "retry_after": 999,
                "worktree": "/retained/worktree", "candidate": SOURCE, "phase_index": 2,
                "plan": {"phases": ["retained"]}, "remote_action": None, "dependency_replan": True,
                "pending_discoveries": {"source": SOURCE, "cursor": 1, "entries": [
                    {"discovery": {"title": "Already registered"}, "review_receipt": 11, "review_attempts": 1},
                    {"discovery": {"title": "Approved pending registration"}, "review_receipt": 12, "review_attempts": 3},
                    {"discovery": {"title": "Unreviewed pending entry"}, "review_attempts": 3}]}}
        expected = copy.deepcopy(data)
        expected.update(attempt=0, reason=None, retry_after=0, remote_action="register-discoveries")
        for entry in expected["pending_discoveries"]["entries"][1:]:
            entry["review_attempts"] = 0
        with State(self.config.state / "state.sqlite3") as state:
            state.set_task(43, "blocked", data)
        self.invoke("retry", "43")
        with State(self.config.state / "state.sqlite3") as state:
            row = state.get_task(43)
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["data"], expected)

    def test_retry_refuses_unknown_active_complete_tasks_and_live_supervisor(self):
        private_directory(self.config.state)
        with State(self.config.state / "state.sqlite3") as state:
            for status in ("pending", "working", "complete"):
                state.set_task(43, status, {})
                with self.subTest(status=status), self.assertRaises(PipelineBlocked):
                    self.invoke("retry", "43")
            with self.assertRaises(PipelineBlocked):
                self.invoke("retry", "999")
            state.set_task(43, "blocked", {})
            with SupervisorLock(self.config.state / "supervisor.lock"), self.assertRaises(ClaimConflict):
                self.invoke("retry", "43")
            self.assertEqual(state.get_task(43)["status"], "blocked")

    def test_status_reports_retained_reason_without_reading_session_contents(self):
        private_directory(self.config.state)
        with State(self.config.state / "state.sqlite3") as state:
            state.set_task(43, "blocked", {"phase_index": 2, "reason": "qualification required",
                                         "worker": {"transcript": "PRIVATE_ARTIFACT_CONTENT"}})
        result = self.invoke("status")
        value = json.loads(result)
        self.assertEqual(value["tasks"][0]["phase"], 2)
        self.assertEqual(value["tasks"][0]["reason"], "qualification required")
        self.assertNotIn("PRIVATE_ARTIFACT_CONTENT", result)

    def test_plan_orders_tasks_and_preserves_specialized_routes_without_launching(self):
        github = mock.Mock()
        github.issue.return_value = {"body": graph_body()}
        with mock.patch.object(cli, "Github", return_value=github), mock.patch.object(cli, "Controller") as controller:
            rows = json.loads(self.invoke("plan"))
        self.assertEqual([row["issue"] for row in rows], [36, 43])
        self.assertEqual(rows[1]["route"], "host")
        self.assertEqual(rows[1]["depends_on"], [36])
        controller.assert_not_called()
        github.comment.assert_not_called()
        github.close_issue.assert_not_called()

    def test_halt_children_passes_only_configured_state_without_constructing_controller(self):
        with mock.patch.object(cli, "halt_children") as halt, mock.patch.object(cli, "Controller") as controller:
            self.invoke("halt-children")
        halt.assert_called_once_with(self.config.state)
        controller.assert_not_called()

    def test_external_import_requires_supervisor_lock_before_controller_initialization(self):
        private_directory(self.config.state)
        with mock.patch.object(cli, "Controller") as controller:
            with SupervisorLock(self.config.state / "supervisor.lock"), self.assertRaises(ClaimConflict):
                self.invoke("accept-external", "43", "--evidence", "/not/read.json")
        controller.assert_not_called()

    def test_retry_refuses_to_convert_external_import_into_generic_pending_work(self):
        private_directory(self.config.state)
        with State(self.config.state / "state.sqlite3") as state:
            state.set_task(43, "blocked", {"remote_action": "external-import"})
        with self.assertRaisesRegex(PipelineBlocked, "accept-external"):
            self.invoke("retry", "43")
        with State(self.config.state / "state.sqlite3") as state:
            self.assertEqual(state.get_task(43)["status"], "blocked")

    def test_run_always_shuts_down_and_closes_state_on_exception(self):
        controller = mock.Mock()
        controller.run.side_effect = PipelineBlocked("retain source")
        with mock.patch.object(cli, "Controller", return_value=controller), mock.patch.object(cli.signal, "signal"):
            with self.assertRaisesRegex(PipelineBlocked, "retain source"):
                self.invoke("run", "--once")
        controller.run.assert_called_once_with(once=True)
        controller.shutdown.assert_called_once_with()
        controller.state.close.assert_called_once_with()


class DoctorTests(CommandFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.github = mock.Mock()
        self.github.issue.side_effect = lambda number: issue_row(
            number, self.config.repository, body=graph_body() if number == 35 else "Task requirements")
        self.github.children.return_value = [self.github.issue(n) for n in (36, 43, 13)]
        self.github.blockers.side_effect = lambda number: [self.github.issue(n) for n in {36: [], 43: [36], 13: [36]}[number]]
        self.secret = "DOCTOR_AUTH_OUTPUT_MUST_NOT_BE_LOGGED"
        self.patches = [
            mock.patch.object(cli.shutil, "which", side_effect=lambda command: "/bin/" + command),
            mock.patch.object(Config, "executable", return_value="/bin/codex"),
            mock.patch.object(cli.shutil, "disk_usage", return_value=SimpleNamespace(free=512 * 2**30)),
            mock.patch.object(cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, self.secret, self.secret)),
            mock.patch.object(cli, "Github", return_value=self.github),
        ]
        self.mocks = [patch.start() for patch in self.patches]
        self.mocks[3].side_effect = lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 0, cli.IMAGE if "inspect" in argv else self.secret, self.secret)
        for patch in self.patches:
            self.addCleanup(patch.stop)

    def test_doctor_checks_dag_and_does_not_emit_authentication_outputs(self):
        output = io.StringIO()
        with redirect_stdout(output):
            value = cli.doctor(self.config)
        self.assertEqual(value["tasks"], 2)
        self.assertEqual(value["dependency_edges"], 1)
        self.assertNotIn(self.secret, cli.encode(value) + output.getvalue())
        self.assertFalse(self.config.state.exists())
        for call in self.mocks[3].call_args_list:
            self.assertTrue(call.kwargs["capture_output"])
            self.assertLessEqual(call.kwargs["timeout"], 30)
        self.github.comment.assert_not_called()

    def test_doctor_refuses_foreign_and_mismatched_native_identities(self):
        children = copy.deepcopy(self.github.children.return_value)
        blockers = self.github.blockers.side_effect
        for replacement in (issue_row(36, "foreign/private"),
                            issue_row(36, self.config.repository, id=9000),
                            issue_row(36, self.config.repository, node_id="I_foreign")):
            for relationship in ("children", "blockers"):
                self.github.children.return_value = [replacement if row["number"] == 36 else row
                                                     for row in children] if relationship == "children" else children
                self.github.blockers.side_effect = (lambda number: [
                    replacement if row["number"] == 36 else row for row in blockers(number)
                ]) if relationship == "blockers" else blockers
                with self.subTest(relationship=relationship, replacement=replacement), self.assertRaises(GithubError):
                    cli.doctor(self.config)
                self.assertFalse(self.config.state.exists())
                self.github.comment.assert_not_called()

    def test_doctor_checks_global_identity_for_new_clone_and_reads_existing_clone_only(self):
        cli.doctor(self.config)
        git_calls = [call.args[0] for call in self.mocks[3].call_args_list if call.args[0][0] == "git"]
        self.assertEqual(git_calls, [["git", "config", "--global", "--get", field]
                                    for field in ("user.name", "user.email")])
        self.config.clone.mkdir(parents=True)
        repo = mock.Mock()
        values = {("remote", "get-url", "origin"): "https://github.com/" + self.config.repository + ".git",
                  ("rev-parse", "--is-shallow-repository"): "false",
                  ("config", "--get", "user.name"): "Operator",
                  ("config", "--get", "user.email"): "operator@example.test"}
        repo.run.side_effect = lambda argv: values[tuple(argv)]
        with mock.patch.object(cli, "GitRepo", return_value=repo):
            cli.doctor(self.config)
            values[("remote", "get-url", "origin")] = "https://example.test/foreign.git"
            with self.assertRaisesRegex(PipelineBlocked, "remote"):
                cli.doctor(self.config)
            values[("remote", "get-url", "origin")] = "https://github.com/" + self.config.repository + ".git"
            values[("rev-parse", "--is-shallow-repository")] = "true"
            with self.assertRaisesRegex(PipelineBlocked, "full source history"):
                cli.doctor(self.config)
        self.assertFalse(self.config.worktrees.exists())
        self.assertFalse(any("--local" in call.args[0] for call in repo.run.call_args_list))

    def test_doctor_refuses_missing_executable_auth_failure_disk_floor_and_divergent_links(self):
        self.mocks[0].side_effect = lambda command: None if command == "cargo" else "/bin/" + command
        with self.assertRaisesRegex(PipelineBlocked, "missing executable"):
            cli.doctor(self.config)
        self.mocks[0].side_effect = lambda command: "/bin/" + command
        self.mocks[3].side_effect = subprocess.CalledProcessError(1, ["gh", "auth", "status"], stderr=self.secret)
        with self.assertRaises(subprocess.CalledProcessError) as error:
            cli.doctor(self.config)
        self.assertNotIn(self.secret, str(error.exception))
        self.mocks[3].side_effect = lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 0, cli.IMAGE if "inspect" in argv else self.secret, self.secret)
        self.mocks[2].return_value = SimpleNamespace(free=0)
        with self.assertRaisesRegex(PipelineBlocked, "free disk"):
            cli.doctor(self.config)
        self.mocks[2].return_value = SimpleNamespace(free=512 * 2**30)
        self.github.blockers.side_effect = lambda _number: []
        with self.assertRaises(ValueError):
            cli.doctor(self.config)

    def test_doctor_rejects_wrong_gate_image(self):
        self.mocks[3].side_effect = None
        with self.assertRaisesRegex(PipelineBlocked, "pinned gate image"):
            cli.doctor(self.config)


class ExternalImportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agenc-external-import-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        config = Config(state_dir=str(self.root / "state"))
        private_directory(config.state)
        controller = Controller.__new__(Controller)
        controller.config = config
        controller.graph_lock = threading.RLock()
        controller.state = State(config.state / "state.sqlite3")
        self.addCleanup(controller.state.close)
        controller.repo = mock.Mock()
        controller.repo.is_ancestor.return_value = True
        controller.repo.tree.return_value = TREE
        controller.fetch = mock.Mock(return_value=TIP)
        controller.verified_receipts = mock.Mock(return_value={36: {"digest": "d" * 64, "source": SOURCE}})
        self.graph = Graph.from_master(graph_body())
        self.issues = {36: {"number": 36, "state": "closed", "body": "Prerequisite", "title": "Contract"},
                       43: {"number": 43, "state": "open", "body": "Host qualification", "title": "Host"}}
        controller.snapshot = mock.Mock(side_effect=lambda: (self.graph, self.issues))
        controller.github = mock.Mock()
        controller.github.issue.side_effect = lambda number: copy.deepcopy(self.issues[number])
        controller.github.close_issue.side_effect = lambda number: self.issues[number].update(state="closed")
        controller.comment_once = mock.Mock()
        self.controller = controller
        self.artifact = self.root / "qualification.json"
        self.artifact.write_text('{"observed": "native qualification result"}\n')
        self.value = {"version": 1, "issue": 43, "route": "host", "source": SOURCE,
                      "approver": "Operator, host qualification owner",
                      "qualification_url": "https://github.com/tetsuo-ai/agenc-ircd/issues/43#issuecomment-123",
                      "acceptance": [{"criterion": "Service identity tested", "evidence": "Native host evidence"}],
                      "artifacts": [{"path": str(self.artifact), "sha256": digest_file(self.artifact)}]}
        self.evidence = self.root / "import.json"

    def accept(self, value=None):
        self.evidence.write_text(json.dumps(self.value if value is None else value))
        return cli.accept_external(self.controller, 43, self.evidence)

    def test_valid_import_retains_hash_bound_artifacts_and_explicit_human_attestation(self):
        result = self.accept()
        self.assertEqual(result["status"], "complete")
        record = self.controller.state.get_task(43)
        self.assertEqual(record["status"], "complete")
        receipts = self.controller.state.receipts(43, "completion")
        self.assertEqual(len(receipts), 1)
        receipt = receipts[0]
        self.assertEqual(receipt["source"], SOURCE)
        self.assertEqual(receipt["tree"], TREE)
        self.assertTrue(self.controller.receipt_valid(receipt))
        retained = Path(receipt["data"]["artifacts"]["0"])
        self.assertTrue(retained.is_relative_to(self.controller.config.state))
        self.assertEqual(retained.read_bytes(), self.artifact.read_bytes())
        self.assertEqual(retained.stat().st_mode & 0o777, 0o600)
        body = self.controller.comment_once.call_args.args[2]
        self.assertIn("external attestation", body)
        self.assertIn(self.value["approver"], body)
        self.assertNotIn(self.artifact.read_text(), body)
        self.artifact.write_text("source changed after successful import")
        self.assertTrue(self.controller.receipt_valid(receipt))
        retained.write_text("retained evidence corrupted")
        self.assertFalse(self.controller.receipt_valid(receipt))

    def test_wrong_schema_route_or_empty_acceptance_refuses_remote_mutations(self):
        variants = [{**self.value, "extra": 1}, {**self.value, "version": True},
                    {**self.value, "issue": True}, {**self.value, "issue": 44},
                    {**self.value, "route": "native"}, {**self.value, "approver": " "},
                    {**self.value, "qualification_url": "file:///local"},
                    {**self.value, "acceptance": []}, {**self.value, "artifacts": []},
                    {**self.value, "acceptance": [{"criterion": "x", "evidence": ""}]},
                    {**self.value, "acceptance": [{"criterion": "x", "evidence": "y", "extra": 1}]}]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(PipelineBlocked):
                self.accept(value)
        self.controller.github.close_issue.assert_not_called()
        self.controller.comment_once.assert_not_called()
        self.assertIsNone(self.controller.state.get_task(43))

    def test_repository_issue_cannot_be_completed_with_external_attestation(self):
        tasks = tuple(Task("REL-02", task.issue, task.depends_on, task.locks, False, task.level)
                      if task.issue == 43 else task for task in self.graph.tasks)
        self.graph = Graph(self.graph.source, 35, 43, self.graph.lock_policy, self.graph.legacy_umbrella, tasks)
        with self.assertRaisesRegex(PipelineBlocked, "route"):
            self.accept({**self.value, "route": "repository"})
        self.controller.github.close_issue.assert_not_called()

    def test_foreign_source_open_dependency_or_missing_dependency_receipt_refused(self):
        self.controller.repo.is_ancestor.return_value = False
        with self.assertRaisesRegex(PipelineBlocked, "remote main"):
            self.accept()
        self.controller.repo.is_ancestor.return_value = True
        self.issues[36]["state"] = "open"
        with self.assertRaisesRegex(PipelineBlocked, "prerequisites"):
            self.accept()
        self.issues[36]["state"] = "closed"
        self.controller.verified_receipts.return_value = {}
        with self.assertRaisesRegex(PipelineBlocked, "prerequisites"):
            self.accept()
        self.controller.github.close_issue.assert_not_called()

    def test_wrong_digest_or_symlink_artifact_refuses_completion(self):
        with self.assertRaisesRegex(PipelineBlocked, "digest"):
            self.accept({**self.value, "artifacts": [{"path": str(self.artifact), "sha256": "f" * 64}]})
        link = self.root / "symlink.json"
        link.symlink_to(self.artifact)
        with self.assertRaises(PipelineBlocked):
            self.accept({**self.value, "artifacts": [{"path": str(link), "sha256": digest_file(self.artifact)}]})
        self.controller.github.close_issue.assert_not_called()
        self.assertIsNone(self.controller.state.get_task(43))

    def test_qualification_source_must_include_prerequisite_source(self):
        self.controller.repo.is_ancestor.side_effect = lambda first, last: last == TIP
        with self.assertRaisesRegex(PipelineBlocked, "predates"):
            self.accept()
        self.controller.github.close_issue.assert_not_called()

    def test_reimport_cannot_rebind_an_unfinished_attestation_to_new_prerequisite_proof(self):
        self.controller.github.close_issue.side_effect = RuntimeError("response lost")
        with self.assertRaisesRegex(RuntimeError, "response lost"):
            self.accept()
        self.controller.verified_receipts.return_value = {36: {"digest": "e" * 64, "source": SOURCE}}
        self.controller.github.close_issue.reset_mock()
        with self.assertRaisesRegex(PipelineBlocked, "unfinished external import"):
            self.accept()
        self.controller.github.close_issue.assert_not_called()

    def test_import_refuses_prerequisite_receipt_change_during_copy(self):
        self.controller.verified_receipts.side_effect = [
            {36: {"digest": "d" * 64, "source": SOURCE}},
            {36: {"digest": "e" * 64, "source": SOURCE}},
        ]
        with self.assertRaisesRegex(PipelineBlocked, "prerequisite evidence changed"):
            self.accept()
        self.controller.github.close_issue.assert_not_called()

    def test_explicit_reimport_repairs_ambiguous_remote_closure_without_losing_evidence(self):
        def closed_then_disconnected(number):
            self.issues[number]["state"] = "closed"
            raise RuntimeError("remote response lost")
        self.controller.github.close_issue.side_effect = closed_then_disconnected
        with self.assertRaisesRegex(RuntimeError, "response lost"):
            self.accept()
        self.assertNotEqual(self.controller.state.get_task(43)["status"], "complete")
        old = self.controller.state.receipts(43, "completion")[0]
        retained = Path(old["data"]["artifacts"]["0"])
        inode = retained.stat().st_ino
        self.controller.github.close_issue.side_effect = lambda number: self.issues[number].update(state="closed")
        self.assertEqual(self.accept()["status"], "complete")
        self.assertEqual(retained.stat().st_ino, inode)
        self.assertTrue(self.controller.receipt_valid(old))

    def test_interrupted_copy_never_publishes_partial_final_and_identical_retry_succeeds(self):
        with mock.patch.object(cli.os, "fsync", side_effect=OSError("simulated disk failure")):
            with self.assertRaisesRegex(OSError, "disk failure"):
                self.accept()
        self.assertEqual(list(self.controller.config.state.glob("imports/*/*")), [])
        self.controller.github.close_issue.assert_not_called()
        self.assertEqual(self.accept()["status"], "complete")

    def test_import_reuses_same_receipt_after_lost_close_and_blocks_different_import(self):
        self.controller.github.close_issue.side_effect = RuntimeError("response lost")
        with self.assertRaisesRegex(RuntimeError, "response lost"):
            self.accept()
        row = self.controller.state.get_task(43)
        self.assertEqual(row["status"], "blocked")
        self.assertEqual(row["data"]["remote_action"], "external-import")
        receipt = self.controller.state.receipts(43, "completion")[0]
        with self.assertRaisesRegex(PipelineBlocked, "unfinished external import"):
            self.accept({**self.value, "approver": "Another qualification owner"})
        self.controller.github.close_issue.side_effect = lambda number: self.issues[number].update(state="closed")
        self.assertEqual(self.accept()["receipt"], receipt["digest"])
        self.assertEqual(len(self.controller.state.receipts(43, "completion")), 1)

    def test_import_rechecks_requirements_after_artifact_copy(self):
        original = self.controller.snapshot.side_effect
        snapshots = 0
        def snapshot():
            nonlocal snapshots
            snapshots += 1
            if snapshots == 2:
                self.issues[43]["body"] = "Additional qualification requirement"
            return original()
        self.controller.snapshot.side_effect = snapshot
        with self.assertRaisesRegex(PipelineBlocked, "changed during import"):
            self.accept()
        self.controller.github.close_issue.assert_not_called()
        self.assertEqual(self.controller.state.get_task(43)["status"], "blocked")

    def test_malformed_types_duplicate_json_and_input_bounds_refuse_before_network(self):
        variants = [{**self.value, "source": source} for source in (None, True, 34, [], "a" * 39)]
        variants += [{**self.value, "qualification_url": url} for url in ("https://", "https://user:password@example.test", "https://example.test:bad")]
        variants += [{**self.value, "artifacts": [{"path": path, "sha256": "a" * 64}]}
                     for path in (None, [], 42, "relative/path", "/absolute/../other")]
        variants += [{**self.value, "artifacts": [{"path": str(self.artifact), "sha256": sha}]}
                     for sha in (None, 42, True, "a" * 63)]
        variants += [{**self.value, "acceptance": self.value["acceptance"] * 2}]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(PipelineBlocked):
                self.accept(value)
        for raw in ('{"version":1,"version":1}', '{"version":NaN}', '[' * 2000,
                    ' ' * (cli.IMPORT_JSON_LIMIT + 1)):
            self.evidence.write_text(raw)
            with self.assertRaises(PipelineBlocked):
                cli.accept_external(self.controller, 43, self.evidence)
        self.controller.snapshot.assert_not_called()
        self.controller.github.close_issue.assert_not_called()

    def test_artifact_byte_limit_rejects_without_final_or_remote_mutation(self):
        with mock.patch.object(cli, "IMPORT_ARTIFACT_LIMIT", 4), self.assertRaisesRegex(PipelineBlocked, "byte limit"):
            self.accept()
        self.assertEqual(list(self.controller.config.state.glob("imports/*/*")), [])
        self.controller.github.close_issue.assert_not_called()

    def test_failed_closure_readback_never_marks_complete(self):
        self.controller.github.close_issue.side_effect = None
        with self.assertRaisesRegex(PipelineBlocked, "readback"):
            self.accept()
        self.assertNotEqual(self.controller.state.get_task(43)["status"], "complete")

    def assert_import_publication_mutation_is_retained(self, boundary, change):
        def mutate():
            if change == "body":
                self.issues[43]["body"] += " Additional unqualified requirement."
            elif change == "task":
                tasks = tuple(Task(task.key, task.issue, task.depends_on,
                                   (*task.locks, "new-host-scope") if task.issue == 43 else task.locks,
                                   task.external_gate, task.level) for task in self.graph.tasks)
                self.graph = Graph(self.graph.source, 35, 43, self.graph.lock_policy,
                                   self.graph.legacy_umbrella, tasks)
            else:
                self.controller.verified_receipts.return_value = {36: {"digest": "e" * 64, "source": SOURCE}}

        def publish(*args):
            if boundary == "comment":
                mutate()

        def close_then_change(number):
            self.issues[number]["state"] = "closed"
            if boundary == "close":
                mutate()

        self.controller.state.set_task(43, "blocked")
        self.controller.state.claim(43, scopes=self.graph.by_issue[43].locks)
        claims = self.controller.state.claims()
        self.controller.comment_once.side_effect = publish
        self.controller.github.close_issue.side_effect = close_then_change
        with self.assertRaises(PipelineBlocked):
            self.accept()
        row = self.controller.state.get_task(43)
        self.assertEqual(row["status"], "blocked")
        self.assertEqual(row["data"]["remote_action"], "external-import")
        self.assertEqual(self.controller.state.claims(), claims)
        self.assertEqual(self.issues[43]["state"], "open" if boundary == "comment" else "closed")
        receipts = self.controller.state.receipts(43, "completion")
        self.assertEqual(len(receipts), 1)
        self.controller.comment_once.reset_mock(side_effect=True)
        self.controller.github.close_issue.reset_mock(side_effect=True)
        with self.assertRaisesRegex(PipelineBlocked, "unfinished external import"):
            self.accept()
        self.controller.comment_once.assert_not_called()
        self.controller.github.close_issue.assert_not_called()
        self.assertEqual(self.controller.state.receipts(43, "completion"), receipts)
        self.assertEqual(self.controller.state.claims(), claims)

    def test_import_comment_requirement_edit_preserves_attestation_binding(self):
        self.assert_import_publication_mutation_is_retained("comment", "body")

    def test_import_close_requirement_edit_preserves_attestation_binding(self):
        self.assert_import_publication_mutation_is_retained("close", "body")

    def test_import_comment_task_edit_preserves_attestation_binding(self):
        self.assert_import_publication_mutation_is_retained("comment", "task")

    def test_import_close_task_edit_preserves_attestation_binding(self):
        self.assert_import_publication_mutation_is_retained("close", "task")

    def test_import_comment_prerequisite_change_preserves_attestation_binding(self):
        self.assert_import_publication_mutation_is_retained("comment", "prerequisite")

    def test_import_close_prerequisite_change_preserves_attestation_binding(self):
        self.assert_import_publication_mutation_is_retained("close", "prerequisite")


if __name__ == "__main__":
    unittest.main()
