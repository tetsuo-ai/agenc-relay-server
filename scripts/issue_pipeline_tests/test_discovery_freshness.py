"""Real Controller/SQLite/Git restart boundaries retain original discovery coverage."""
import copy
import json
from pathlib import Path
import unittest
from unittest import mock

from issue_pipeline.backlog import Backlog, BacklogError
from issue_pipeline.controller import Controller, PipelineBlocked
from issue_pipeline.github import GithubError, GithubIdentityError
from issue_pipeline_tests import test_controller as fixture
from issue_pipeline_tests import test_master_blockers as master


class DiscoveryFreshnessTests(unittest.TestCase):
    setUp = fixture.ControllerTests.setUp
    execute = fixture.ControllerTests.execute
    accepted_fixture = fixture.ControllerTests.accepted_fixture
    graph_record = fixture.ControllerTests.graph_record
    update = master.MasterBlockerTests.update
    entry = master.MasterBlockerTests.entry
    assert_blocked_open = master.MasterBlockerTests.assert_blocked_open

    def interrupt(self, boundary):
        self.runner = fixture.DiscoveryAgents()
        self.controller.runner = self.runner
        self.github.issues[41]["state"] = "closed"
        save, api = Backlog._save, self.github.api

        def save_then_crash(backlog, path, journal):
            save(backlog, path, journal)
            if boundary == "prepared" and journal["intent"] == "prepared":
                raise SystemExit("after durable preparation, before first POST")

        def publish_then_crash(endpoint, method="GET", payload=None):
            result = api(endpoint, method, payload)
            if ((boundary == "created" and endpoint == "issues" and method == "POST")
                    or (boundary == "linked" and endpoint == "issues/35/sub_issues")
                    or (boundary == "parent" and endpoint == "issues/36" and method == "PATCH")
                    or (boundary == "master" and endpoint == "issues/35" and method == "PATCH")):
                raise SystemExit("after applied publication, before local checkpoint")
            return result

        with mock.patch.object(Backlog, "_save", save_then_crash), \
                mock.patch.object(self.github, "api", side_effect=publish_then_crash), \
                self.assertRaises(SystemExit):
            self.execute()
        row = self.controller.state.get_task(36)
        self.assertEqual(row["data"]["pending_discoveries"]["cursor"], 0)
        self.assertTrue(row["data"]["dependency_replan"])
        self.assertEqual(row["data"]["remote_action"], "register-discoveries")
        retained = Path(row["data"]["worktree"])
        self.assertEqual(self.repo.head(retained), row["data"]["pending_discoveries"]["source"])
        self.assertEqual(self.repo.changed_paths(retained), [])
        self.controller = Controller(self.config, repo=self.repo, github=self.github,
                                     runner=self.runner, gate=self.gate)
        self.controller.log = mock.Mock()
        self.addCleanup(self.controller.state.close)
        return retained

    def refused_replay(self, boundary, *, number=41, field="body"):
        retained = self.interrupt(boundary)
        if field == "state":
            self.github.issues[number][field] = "open"
        else:
            self.github.issues[number][field] += "\nExisting managed work now covers the proposed prerequisite."
        original = copy.deepcopy(self.controller.state.get_task(36))
        reviews = self.controller.state.receipts(36, "discovery-review")
        journals = {p: p.read_bytes() for p in (self.config.state / "backlog").glob("*.json")}
        issues, deps, children = copy.deepcopy((self.github.issues, self.github.dependencies, self.github.child_links))
        calls = len(self.runner.calls)
        for _ in range(2):
            with mock.patch("issue_pipeline.controller.halt_children"), \
                    mock.patch.object(self.github, "api", wraps=self.github.api) as api, \
                    self.assertRaisesRegex(BacklogError, "reviewed managed backlog issue"):
                self.controller.recover()
            self.assertTrue(all(len(c.args) < 2 or c.args[1] == "GET" for c in api.call_args_list))
        self.assertEqual((self.github.issues, self.github.dependencies, self.github.child_links), (issues, deps, children))
        self.assertEqual(self.controller.state.get_task(36), original)
        self.assertEqual(self.controller.state.receipts(36, "discovery-review"), reviews)
        self.assertTrue(all(self.controller.receipt_valid(r) for r in reviews))
        self.assertEqual({p: p.read_bytes() for p in journals}, journals)
        self.assertEqual(len(self.runner.calls), calls)
        self.assertTrue(retained.exists())

    def test_changed_coverage_after_journal_preparation_cannot_create_on_restart(self):
        self.refused_replay("prepared")
        self.assertEqual(self.github.next_issue, 100)

    def test_changed_coverage_after_lost_create_cannot_link_on_restart(self):
        self.refused_replay("created")
        self.assertEqual(self.github.next_issue, 101)
        self.assertNotIn(100, self.github.child_links[35])

    def test_changed_coverage_during_partial_native_registration_cannot_continue(self):
        self.refused_replay("linked")
        self.assertNotIn(100, self.github.graph.by_issue)

    def test_changed_coverage_after_owned_parent_patch_cannot_update_master(self):
        self.refused_replay("parent")
        self.assertNotIn(100, self.github.graph.by_issue)

    def test_changed_coverage_after_owned_master_patch_cannot_accept_journal(self):
        self.refused_replay("master")
        journal = json.loads(next((self.config.state / "backlog").glob("*.json")).read_text())
        self.assertEqual(journal["status"], "pending")

    def test_changed_managed_title_cannot_resume_original_approval(self):
        self.refused_replay("prepared", field="title")

    def test_reopened_managed_issue_cannot_resume_original_approval(self):
        self.refused_replay("created", field="state")

    def test_changed_legacy_coverage_cannot_resume_original_approval(self):
        self.refused_replay("created", number=13)

    def test_original_catalog_allows_prepared_restart_through_child_and_parent_completion(self):
        retained = self.interrupt("prepared")
        reviews = self.controller.state.receipts(36, "discovery-review")
        with mock.patch("issue_pipeline.controller.halt_children"):
            for _ in range(3):
                self.controller.run(once=True)
        self.assertEqual(self.github.next_issue, 101)
        self.assertEqual(self.controller.state.receipts(36, "discovery-review"), reviews)
        for number in (100, 36):
            self.assertEqual(self.controller.state.get_task(number)["status"], "complete")
            self.assertTrue(self.controller.verified(number, self.repo.fetch()))
        self.assertFalse(retained.exists())

    def test_uncheckpointed_complete_registration_still_checks_original_catalog(self):
        fixture.ControllerTests.interrupt_discovery_registration(self, "after-register")
        self.github.issues[41]["body"] += "\nCoverage changed before local adoption."
        row = self.controller.state.get_task(36)
        with self.assertRaisesRegex(BacklogError, "reviewed managed backlog issue"):
            self.controller.resume_discoveries(self.github.graph.by_issue[36], row["data"])
        self.assertEqual(self.controller.state.get_task(36)["data"]["pending_discoveries"]["cursor"], 0)
        self.assertEqual(self.github.next_issue, 101)

    def test_final_native_read_cannot_hide_changed_catalog_before_journal_completion(self):
        self.interrupt("created")
        blockers = self.github.blockers
        changed = False

        def final_read(number):
            nonlocal changed
            if number == 86 and 100 in self.github.graph.by_issue:
                self.github.issues[41]["body"] += "\nChanged during final native verification."
                changed = True
            return blockers(number)

        with mock.patch.object(self.github, "blockers", side_effect=final_read), \
                mock.patch("issue_pipeline.controller.halt_children"), \
                self.assertRaisesRegex(BacklogError, "reviewed managed backlog issue"):
            self.controller.recover()
        self.assertTrue(changed)
        journal = json.loads(next((self.config.state / "backlog").glob("*.json")).read_text())
        self.assertEqual(journal["status"], "pending")

    def test_completed_journal_rechecks_catalog_after_slow_native_read_before_cursor_advance(self):
        fixture.ControllerTests.interrupt_discovery_registration(self, "after-register")
        blockers = self.github.blockers

        def final_read(number):
            if number == 35:
                self.github.issues[41]["body"] += "\nCoverage changed during completed-journal validation."
            return blockers(number)

        row = self.controller.state.get_task(36)
        with mock.patch.object(self.github, "blockers", side_effect=final_read), \
                self.assertRaisesRegex(BacklogError, "reviewed managed backlog issue"):
            self.controller.resume_discoveries(self.github.graph.by_issue[36], row["data"])
        self.assertEqual(self.controller.state.get_task(36)["data"]["pending_discoveries"]["cursor"], 0)
        self.assertEqual(self.github.next_issue, 101)

    def test_confirmed_catalog_revocation_compensates_owned_legacy_during_partial_recovery(self):
        terminal = master.MasterBlockerTests.pending_discovery_with_completed_legacy(self)
        original = self.controller.state.get_task(36)["data"]["pending_discoveries"]
        self.github.issues[41]["body"] += "\nThe accepted prerequisite requirements changed."
        with mock.patch("issue_pipeline.controller.halt_children"), \
                mock.patch.object(self.github, "api", wraps=self.github.api) as api, \
                self.assertRaisesRegex(BacklogError, "reviewed managed backlog issue"):
            self.controller.recover()
        mutations = [c for c in api.call_args_list if len(c.args) > 1 and c.args[1] != "GET"]
        self.assertEqual([(c.args[0], c.args[2]) for c in mutations], [("issues/13", {"state": "open"})])
        self.assert_blocked_open(13)
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertEqual(self.controller.state.get_task(36)["data"]["pending_discoveries"], original)
        self.assertNotIn(100, self.github.graph.by_issue)

    def test_catalog_read_transport_error_preserves_partial_journal_and_closed_legacy(self):
        terminal = master.MasterBlockerTests.pending_discovery_with_completed_legacy(self)
        issue = self.github.issue

        def disconnected(number):
            if number == 41:
                raise GithubError("coverage read transport unavailable")
            return issue(number)

        with mock.patch.object(self.github, "issue", side_effect=disconnected), \
                mock.patch("issue_pipeline.controller.halt_children"), self.assertRaises(BacklogError):
            self.controller.recover()
        self.assertEqual(self.github.issues[13]["state"], "closed")
        self.assertEqual(self.entry(13)["stage"], "complete")
        with mock.patch("issue_pipeline.controller.halt_children"):
            self.controller.recover()
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertEqual(self.entry(13)["stage"], "complete")
        self.assertEqual(self.github.next_issue, 101)

    def test_unrelated_catalog_drift_preserves_valid_legacy_during_owned_partial_graph(self):
        terminal = master.MasterBlockerTests.pending_discovery_with_completed_legacy(self)
        original = self.github.issues[86]["body"]
        self.github.issues[86]["body"] += "\nUnrelated final issue now covers the proposed discovery."
        journals = {p: p.read_bytes() for p in (self.config.state / "backlog").glob("*.json")}
        with mock.patch("issue_pipeline.controller.halt_children"), \
                mock.patch.object(self.github, "api", wraps=self.github.api) as api, \
                self.assertRaisesRegex(BacklogError, "reviewed managed backlog issue #86"):
            self.controller.recover()
        self.assertTrue(all(len(c.args) < 2 or c.args[1] == "GET" for c in api.call_args_list))
        self.assertEqual(self.github.issues[13]["state"], "closed")
        self.assertEqual(self.entry(13)["stage"], "complete")
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertEqual({p: p.read_bytes() for p in journals}, journals)
        self.github.issues[86]["body"] = original
        with mock.patch("issue_pipeline.controller.halt_children"):
            self.controller.recover()
        self.assertEqual(self.entry(13)["stage"], "complete")
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertEqual(self.github.next_issue, 101)

    def test_catalog_conflict_still_checks_legacy_native_prerequisites_before_preserving_it(self):
        terminal = master.MasterBlockerTests.pending_discovery_with_completed_legacy(self)
        self.github.issues[86]["body"] += "\nUnrelated changed acceptance."
        self.github.dependencies[41].add(36)
        with mock.patch("issue_pipeline.controller.halt_children"), \
                self.assertRaisesRegex(BacklogError, "reviewed managed backlog issue #86"):
            self.controller.recover()
        self.assert_blocked_open(13)
        self.assertEqual(self.entry(13)["terminal"], terminal)

    def test_scoped_legacy_rechecks_after_later_owned_master_compensation(self):
        for number in (36, 41, 86):
            self.accepted_fixture(number)
        self.update()
        original = {n: self.entry(n)["terminal"] for n in (13, 35)}
        self.github.issues[41]["body"] += "\nUnrelated catalog acceptance changed."
        api = self.github.api

        def compensate_then_change(endpoint, method="GET", payload=None):
            result = api(endpoint, method, payload)
            if endpoint == "issues/35" and method == "PATCH" and payload == {"state": "open"}:
                self.github.issues[36]["body"] += "\nLegacy prerequisite changed during master compensation."
            return result

        with mock.patch.object(self.github, "api", side_effect=compensate_then_change), \
                self.assertRaises(PipelineBlocked):
            self.controller.reconcile_aggregates(recheck_only=True, preserve_valid_legacy=True)
        self.assert_blocked_open(13, 35)
        self.assertEqual({n: self.entry(n)["terminal"] for n in (13, 35)}, original)
        self.assertEqual(self.github.close_calls, [13, 35])

    def test_confirmed_catalog_identity_revocation_compensates_owned_legacy(self):
        terminal = master.MasterBlockerTests.pending_discovery_with_completed_legacy(self)
        issue = self.github.issue

        def transferred(number):
            if number == 41:
                raise GithubIdentityError("reviewed issue now has a foreign repository identity")
            return issue(number)

        with mock.patch.object(self.github, "issue", side_effect=transferred), \
                mock.patch("issue_pipeline.controller.halt_children"), \
                self.assertRaisesRegex(BacklogError, "invalid identity"):
            self.controller.recover()
        self.assert_blocked_open(13)
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertNotIn(100, self.github.graph.by_issue)


if __name__ == "__main__":
    unittest.main()
