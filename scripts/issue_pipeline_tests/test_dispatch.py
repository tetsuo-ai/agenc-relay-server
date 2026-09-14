"""Dispatch regressions use actual executor threads, run-loop code and SQLite claims."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from issue_pipeline.config import Config
from issue_pipeline.controller import Controller
from issue_pipeline.graph import Graph


class DispatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agenc-dispatch-test-")
        self.addCleanup(temporary.cleanup)
        config = Config(state_dir=str(Path(temporary.name) / "state"), max_issues=2, use_systemd=True)
        self.controller = Controller(config, repo=object(), github=object(), runner=object(), gate=object())
        self.addCleanup(self.controller.state.close)
        self.record = {"version": 1, "source": "a" * 40, "master_issue": 35, "final_issue": 86,
                       "lock_policy": "Claim named scopes and exact files.",
                       "legacy_umbrella": {"issue": 13, "depends_on": [36]}, "tasks": [
                           {"key": "ENC-01", "issue": 36, "depends_on": [], "locks": ["normative"], "external_gate": False, "level": 0},
                           {"key": "ENC-06", "issue": 37, "depends_on": [], "locks": ["normative"], "external_gate": False, "level": 0},
                           {"key": "ENC-12", "issue": 38, "depends_on": [], "locks": ["auth-account"], "external_gate": False, "level": 0},
                           {"key": "REL-13", "issue": 86, "depends_on": [36, 37, 38], "locks": ["release"], "external_gate": True, "level": 1}]}
        self.refresh_graph()
        self.issues = {task.issue: {"number": task.issue, "state": "open", "body": "Complete this fixture."}
                       for task in self.graph.tasks}
        self.controller.recover = mock.Mock()
        self.controller.snapshot = mock.Mock(side_effect=lambda: (self.graph, self.issues))
        self.controller.fetch = mock.Mock(return_value=self.record["source"])
        self.controller.verified_tasks = mock.Mock(return_value=set())
        self.controller.update_master = mock.Mock()
        self.controller.log = mock.Mock()
        self.submitted = []
        self.futures = {}
        self.events = []
        self.polls = 0

    def refresh_graph(self):
        self.graph = Graph.from_master("```json\n" + json.dumps(self.record) + "\n```\n")

    def event(self):
        value = threading.Event()
        self.events.append(value)
        return value

    def wait(self, event):
        self.assertTrue(event.wait(2), "bounded executor barrier expired")

    def finish(self, task):
        self.controller.state.set_task(task.issue, "complete")
        self.issues[task.issue]["state"] = "closed"

    def hold(self, task, acquired, release):
        previous = self.controller.state.get_task(task.issue)
        self.controller.state.set_task(task.issue, "working", previous["data"] if previous else {})
        self.controller.state.claim(task.issue, scopes=task.locks, owner=str(task.issue))
        acquired.set()
        try:
            self.wait(release)
        finally:
            self.controller.state.release(task.issue, owner=str(task.issue))
        self.finish(task)

    def run_loop(self, execute, on_wait=None, *, once=False):
        test = self

        class Executor(ThreadPoolExecutor):
            def submit(self, function, task, issue):
                test.submitted.append(task.issue)
                future = super().submit(function, task, issue)
                test.futures[task.issue] = future
                return future

            def __exit__(self, kind, value, traceback):
                if kind is not None:
                    for event in test.events:
                        event.set()
                return super().__exit__(kind, value, traceback)

        class Stop:
            stopped = False

            def is_set(self):
                return self.stopped

            def wait(self, _seconds):
                test.polls += 1
                test.assertLessEqual(test.polls, 3, "scheduler exceeded bounded test polls")
                self.stopped = bool(on_wait(test.polls))
                return self.stopped

        self.controller.stop = Stop()
        self.controller.execute = execute
        with mock.patch("issue_pipeline.controller.ThreadPoolExecutor", Executor), \
                mock.patch("issue_pipeline.sandbox.prepare_cargo_cache") as prepare:
            self.controller.run(once=once)
            prepare.assert_called_once_with(self.controller.config)
        self.assertTrue(all(future.done() for future in self.futures.values()))
        for future in self.futures.values():
            future.result(timeout=0)

    def test_delayed_first_claim_dispatches_independent_work_then_waiting_peer(self):
        before_claim, allow_claim = self.event(), self.event()
        acquired = {number: self.event() for number in (36, 37, 38)}
        release = {number: self.event() for number in (36, 37, 38)}

        def execute(task, _issue):
            if task.issue == 36:
                before_claim.set()
                self.wait(allow_claim)
            self.hold(task, acquired[task.issue], release[task.issue])

        def poll(number):
            if number == 1:
                self.wait(before_claim)
                self.wait(acquired[38])
                self.assertEqual(self.submitted, [36, 38])
                self.assertIsNone(self.controller.state.get_task(36))
                self.assertEqual({row["issue"] for row in self.controller.state.claims()}, {38})
                allow_claim.set()
                self.wait(acquired[36])
                release[36].set()
                self.futures[36].result(timeout=2)
                return False
            self.wait(acquired[37])
            self.assertEqual(self.submitted, [36, 38, 37])
            self.assertEqual({row["issue"] for row in self.controller.state.claims()}, {37, 38})
            release[37].set()
            release[38].set()
            return True

        self.run_loop(execute, poll)
        self.assertFalse(self.controller.state.claims())

    def test_original_submitted_scopes_survive_graph_refresh_before_claim(self):
        before_claim, allow_claim = self.event(), self.event()
        first_acquired, first_release = self.event(), self.event()
        independent_acquired, independent_release = self.event(), self.event()

        def execute(task, _issue):
            if task.issue == 36:
                before_claim.set()
                self.wait(allow_claim)
                self.hold(task, first_acquired, first_release)
            elif task.issue == 38:
                self.hold(task, independent_acquired, independent_release)
            else:
                self.fail("conflicting issue entered an executor slot")

        def poll(number):
            if number == 1:
                self.wait(before_claim)
                self.wait(independent_acquired)
                self.assertEqual(self.submitted, [36, 38])
                independent_release.set()
                self.futures[38].result(timeout=2)
                self.record["tasks"][0]["locks"] = ["changed-normative"]
                self.refresh_graph()
                return False
            self.assertEqual(self.submitted, [36, 38])
            self.assertFalse(self.controller.state.claims())
            allow_claim.set()
            self.wait(first_acquired)
            first_release.set()
            return True

        self.run_loop(execute, poll)

    def test_durable_foreign_scope_skips_both_remote_and_normal_conflicts(self):
        self.controller.state.set_task(99, "working")
        self.controller.state.claim(99, scopes=("normative",), owner="another-owner")
        original = self.controller.state.claims()
        self.controller.state.set_task(36, "pending", {"remote_action": "close-issue"})
        self.issues[36]["state"] = "closed"
        self.run_loop(lambda task, issue: self.finish(task), once=True)
        self.assertEqual(self.submitted, [38])
        self.assertEqual(self.controller.state.claims(), original)
        self.assertEqual(self.controller.state.get_task(36)["data"], {"remote_action": "close-issue"})

    def test_foreign_owner_of_same_issue_blocks_even_without_shared_scope(self):
        self.controller.state.set_task(36, "working")
        self.controller.state.claim(36, files=("docs/owned.md",), owner="another-owner")
        original = self.controller.state.claims()
        self.run_loop(lambda task, issue: self.finish(task), once=True)
        self.assertEqual(self.submitted, [37, 38])
        self.assertEqual(self.controller.state.claims(), original)

    def test_remote_intents_reserve_scopes_and_reuse_same_owner_claims(self):
        for number in (36, 37):
            self.controller.state.set_task(number, "pending", {"remote_action": "close-issue"})
            self.issues[number]["state"] = "closed"
        self.controller.state.claim(36, scopes=("normative",), files=("docs/owned.md",), owner="36")
        acquired = {number: self.event() for number in (36, 37, 38)}
        release = {number: self.event() for number in (36, 37, 38)}

        def execute(task, _issue):
            self.hold(task, acquired[task.issue], release[task.issue])

        def poll(number):
            if number == 1:
                self.wait(acquired[36])
                self.wait(acquired[38])
                self.assertEqual(self.submitted, [36, 38])
                self.assertTrue(any(row["kind"] == "file" and row["issue"] == 36
                                    for row in self.controller.state.claims()))
                release[36].set()
                self.futures[36].result(timeout=2)
                return False
            self.wait(acquired[37])
            self.assertEqual(self.submitted, [36, 38, 37])
            release[37].set()
            release[38].set()
            return True

        self.run_loop(execute, poll)
        self.assertFalse(self.controller.state.claims())


if __name__ == "__main__":
    unittest.main()
