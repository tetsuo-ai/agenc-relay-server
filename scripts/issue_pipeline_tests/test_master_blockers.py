"""Master blocker admission and closure use real local Git and immutable evidence."""
import copy
import json
import unittest
from unittest import mock

from issue_pipeline.controller import PipelineBlocked
from issue_pipeline.github import GithubError, GithubIdentityError
from issue_pipeline.backlog import Backlog, BacklogError, MasterBlockerInvalid
from issue_pipeline_tests import test_aggregate_closure as aggregates
from issue_pipeline_tests import test_controller as fixture
from issue_pipeline_tests.test_github import issue_row


class MasterBlockerTests(unittest.TestCase):
    setUp = fixture.ControllerTests.setUp
    accepted_fixture = fixture.ControllerTests.accepted_fixture
    graph_record = fixture.ControllerTests.graph_record
    execute = fixture.ControllerTests.execute
    ready = aggregates.AggregateClosureTests.ready
    update = aggregates.AggregateClosureTests.update
    entry = aggregates.AggregateClosureTests.entry
    restart = aggregates.AggregateClosureTests.restart
    assert_blocked_open = aggregates.AggregateClosureTests.assert_blocked_open

    def unmanaged(self):
        self.github.issues[99] = {"number": 99, "id": 1099, "state": "open", "title": "Unmanaged requirement",
                                  "body": "This prerequisite has no accepted proof in the managed DAG."}
        self.github.dependencies[35] = {99}

    def test_snapshot_reads_redundant_master_links_with_independent_identity_validation(self):
        self.github.dependencies[35] = {13, 36, 86}
        graph, issues = self.controller.snapshot()
        self.assertEqual(graph, self.github.graph)
        self.assertEqual(set(issues), {13, 36, 41, 86})
        blockers = self.github.blockers
        for rows in ([issue_row(99, self.config.repository)], [self.github.issue(35)],
                     [issue_row(36, "foreign/private")], [issue_row(36, self.config.repository, id=9000)],
                     [issue_row(36, self.config.repository, node_id="I_foreign")],
                     [self.github.issue(36), self.github.issue(36)]):
            with self.subTest(rows=rows), mock.patch.object(self.github, "blockers", side_effect=lambda n: rows if n == 35 else blockers(n)):
                with self.assertRaises(GithubIdentityError):
                    self.controller.snapshot()

    def test_unmanaged_master_blocker_blocks_before_closure_preparation(self):
        self.ready()
        self.unmanaged()
        with self.assertRaises(PipelineBlocked):
            self.update()
        self.assertEqual(self.github.close_calls, [])
        self.assertIsNone(self.controller.state.get_task(13))
        self.assertIsNone(self.controller.state.get_task(35))
        self.assertEqual(self.github.issue(35)["state"], "open")

    def test_redundant_master_member_still_requires_closed_state_and_accepted_receipts(self):
        self.ready(all_tasks=False)
        self.github.dependencies[35] = {13, 41}
        self.update()
        legacy = self.entry(13)["terminal"]
        self.assertEqual(self.github.close_calls, [13])
        self.github.issues[41]["state"] = "closed"
        self.update()
        self.assertEqual(self.github.close_calls, [13])
        self.assertIsNone(self.controller.state.get_task(35))
        self.accepted_fixture(41)
        self.accepted_fixture(86)
        self.update()
        self.assertEqual(self.github.close_calls, [13, 35])
        self.assertEqual(self.entry(35)["legacy_terminal"], legacy)

    def assert_publication_boundary(self, boundary):
        self.ready()
        comment, close = self.github.comment, self.github.close_issue

        def publish(number, body):
            result = comment(number, body)
            if ((boundary == "status" and "agenc-pipeline-live-status" in body)
                    or (boundary == "legacy-comment" and number == 13)
                    or (boundary == "master-comment" and number == 35 and "agenc-pipeline-aggregate:" in body)):
                self.unmanaged()
            return result

        def finish(number):
            result = close(number)
            if boundary == "master-close" and number == 35:
                self.unmanaged()
            return result

        with mock.patch.object(self.github, "comment", side_effect=publish), mock.patch.object(self.github, "close_issue", side_effect=finish):
            with self.assertRaises(PipelineBlocked):
                self.update()
        self.assert_blocked_open(13, 35)
        preparations = {n: self.entry(n)["preparation"] for n in (13, 35)}
        self.restart()
        with mock.patch("issue_pipeline.controller.halt_children"), self.assertRaises(PipelineBlocked):
            self.controller.recover()
        self.assertEqual({n: self.entry(n)["preparation"] for n in (13, 35)}, preparations)
        for number in (13, 35):
            self.assertEqual(len(self.controller.state.receipts(number, "aggregate-preparation")), 1)
        self.assert_blocked_open(13, 35)

    def test_master_blocker_added_during_initial_status_blocks_both_closures(self):
        self.assert_publication_boundary("status")

    def test_master_blocker_added_during_legacy_comment_blocks_both_closures(self):
        self.assert_publication_boundary("legacy-comment")

    def test_master_blocker_added_during_master_comment_reopens_owned_legacy(self):
        self.assert_publication_boundary("master-comment")

    def test_master_blocker_added_during_master_close_reopens_both_owned_aggregates(self):
        self.assert_publication_boundary("master-close")

    def test_restart_reopens_both_completed_owned_aggregates_after_new_master_blocker(self):
        self.ready()
        self.update()
        original = {n: copy.deepcopy(self.entry(n)) for n in (13, 35)}
        self.unmanaged()
        self.restart()
        with mock.patch("issue_pipeline.controller.halt_children"), self.assertRaises(PipelineBlocked):
            self.controller.recover()
        self.assert_blocked_open(13, 35)
        self.assertEqual({n: self.entry(n)["intent"] for n in (13, 35)}, {n: original[n]["intent"] for n in (13, 35)})

    def test_foreign_master_link_revokes_owned_closures_through_typed_identity_failure(self):
        self.ready()
        self.update()
        blockers = self.github.blockers
        with mock.patch.object(self.github, "blockers", side_effect=lambda n: [issue_row(36, "foreign/private")] if n == 35 else blockers(n)):
            with self.assertRaises(PipelineBlocked):
                self.controller.reconcile_aggregates()
        self.assert_blocked_open(13, 35)

    def test_already_required_managed_link_added_during_publication_preserves_acceptance(self):
        self.ready()
        comment = self.github.comment

        def publish(number, body):
            result = comment(number, body)
            if number == 35 and "agenc-pipeline-aggregate:" in body:
                self.github.dependencies[35] = {13, 36, 86}
            return result

        with mock.patch.object(self.github, "comment", side_effect=publish):
            self.update()
        self.assertEqual(self.github.close_calls, [13, 35])
        self.assertEqual(self.entry(35)["legacy_terminal"], self.entry(13)["terminal"])

    def pending_discovery_with_completed_legacy(self):
        graph = self.graph_record()
        changed = copy.deepcopy(graph)
        changed["legacy_umbrella"]["depends_on"] = [41]
        self.github.issues[35]["body"] = self.github.issues[35]["body"].replace(json.dumps(graph), json.dumps(changed))
        self.github.graph = fixture.Graph.from_master(self.github.issues[35]["body"])
        self.github.dependencies[13] = {41}
        self.accepted_fixture(41)
        self.update()
        terminal = self.entry(13)["terminal"]
        fixture.ControllerTests.interrupt_discovery_registration(self, "during-register")
        self.github.child_links[35].add(100)
        return terminal

    def test_confirmed_master_revocation_compensates_owned_legacy_before_pending_graph_replay(self):
        terminal = self.pending_discovery_with_completed_legacy()
        self.unmanaged()
        with mock.patch.object(self.github, "api", wraps=self.github.api) as api:
            with mock.patch("issue_pipeline.controller.halt_children"), self.assertRaises(MasterBlockerInvalid):
                self.controller.recover()
        mutations = [call for call in api.call_args_list if len(call.args) > 1 and call.args[1] != "GET"]
        self.assertEqual([(call.args[0], call.args[2]) for call in mutations], [("issues/13", {"state": "open"})])
        self.assert_blocked_open(13)
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertNotIn(100, self.github.graph.by_issue)
        self.assertEqual(self.github.next_issue, 101)
        self.assertTrue(list((self.config.state / "backlog").glob("*.json")))

    def test_transport_during_partial_graph_repair_preserves_closed_legacy_until_repair(self):
        terminal = self.pending_discovery_with_completed_legacy()
        blockers = self.github.blockers

        def disconnected(number):
            if number == 35:
                raise GithubError("master relationship transport unavailable")
            return blockers(number)

        with mock.patch.object(self.github, "blockers", side_effect=disconnected):
            with mock.patch("issue_pipeline.controller.halt_children"), self.assertRaises(BacklogError) as raised:
                self.controller.recover()
        self.assertNotIsInstance(raised.exception, MasterBlockerInvalid)
        self.assertEqual(self.entry(13)["stage"], "complete")
        self.assertEqual(self.github.issue(13)["state"], "closed")
        self.assertNotIn(100, self.github.graph.by_issue)
        with mock.patch("issue_pipeline.controller.halt_children"):
            self.controller.recover()
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertEqual(self.entry(13)["stage"], "complete")
        self.assertIn(100, self.github.graph.by_issue)
        self.assertEqual(self.github.next_issue, 101)

    def test_final_master_blocker_read_revokes_owned_legacy_after_valid_replay_guard(self):
        terminal = self.pending_discovery_with_completed_legacy()
        guard, blockers = Backlog._guard, self.github.blockers
        final_guard_seen = False

        def guarded(backlog, journal, path):
            nonlocal final_guard_seen
            guard(backlog, journal, path)
            if 100 in self.github.graph.by_issue:
                final_guard_seen = True

        def late_blocker(number):
            if number == 35 and final_guard_seen:
                self.unmanaged()
            return blockers(number)

        with mock.patch.object(Backlog, "_guard", guarded), mock.patch.object(self.github, "blockers", side_effect=late_blocker):
            with mock.patch("issue_pipeline.controller.halt_children"), self.assertRaises(MasterBlockerInvalid):
                self.controller.recover()
        self.assertTrue(final_guard_seen)
        self.assert_blocked_open(13)
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertIn(100, self.github.graph.by_issue)
        self.assertEqual(self.github.next_issue, 101)
        journal = json.loads(next((self.config.state / "backlog").glob("*.json")).read_text())
        self.assertEqual(journal["status"], "pending")
