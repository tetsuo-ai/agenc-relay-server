"""Flat native hierarchy admission and races use real Git, SQLite and receipt files."""
import copy
import json
import unittest
from unittest import mock

from issue_pipeline.backlog import Backlog, BacklogError, NativeChildrenInvalid
from issue_pipeline.controller import PipelineBlocked, body_hash
from issue_pipeline.github import GithubError, GithubIdentityError
from issue_pipeline.graph import GraphError
from issue_pipeline_tests import test_aggregate_closure as aggregate
from issue_pipeline_tests import test_controller as fixture
from issue_pipeline_tests import test_master_blockers as master
from issue_pipeline_tests.test_github import issue_row


class NestedChildrenTests(unittest.TestCase):
    setUp = fixture.ControllerTests.setUp
    execute = fixture.ControllerTests.execute
    graph_record = fixture.ControllerTests.graph_record
    accepted_fixture = fixture.ControllerTests.accepted_fixture
    ready = aggregate.AggregateClosureTests.ready
    update = aggregate.AggregateClosureTests.update
    entry = aggregate.AggregateClosureTests.entry
    restart = aggregate.AggregateClosureTests.restart
    assert_blocked_open = aggregate.AggregateClosureTests.assert_blocked_open
    pending_discovery_with_completed_legacy = master.MasterBlockerTests.pending_discovery_with_completed_legacy

    def nested(self, owner=36, child=41):
        self.github.child_links.setdefault(owner, set()).add(child)

    def test_snapshot_requires_every_managed_owner_empty_with_strict_child_identities(self):
        reader = self.github.children
        with mock.patch.object(self.github, "children", wraps=reader) as calls:
            self.controller.snapshot()
        self.assertEqual(sorted(c.args[0] for c in calls.call_args_list), [13, 35, 36, 41, 86])
        for owner in (13, 36, 41, 86):
            for rows in ([self.github.issue(36)], [issue_row(99, self.config.repository)],
                         [issue_row(36, "foreign/private")],
                         [issue_row(36, self.config.repository, id=9000)],
                         [issue_row(36, self.config.repository, node_id="I_foreign")],
                         [self.github.issue(36), self.github.issue(36)]):
                with self.subTest(owner=owner, rows=rows), \
                        mock.patch.object(self.github, "children", side_effect=lambda n: rows if n == owner else reader(n)), \
                        self.assertRaises((GraphError, GithubIdentityError)):
                    self.controller.snapshot()
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(self.github.close_calls, [])
        self.assertEqual(self.controller.state.list_tasks(), [])

    def test_nested_task_prevents_first_worker_admission_and_completion(self):
        self.nested()
        self.execute()
        self.assertEqual(self.controller.state.get_task(36)["status"], "blocked")
        # Direct execute bypasses the scheduler snapshot; planning is read-only.
        # Its first live worker precondition must still refuse this hierarchy.
        self.assertEqual([call[0] for call in self.runner.calls], ["planner", "reviewer"])
        self.assertEqual(self.github.close_calls, [])
        self.assertEqual(self.repo.fetch(), self.base)

    def task_publication(self, boundary):
        comment, close = self.github.comment, self.github.close_issue
        def publish(number, body):
            result = comment(number, body)
            if boundary == "comment" and number == 36 and "agenc-pipeline-completion:" in body:
                self.nested()
            return result
        def finish(number):
            result = close(number)
            if boundary == "close" and number == 36:
                self.nested()
            return result
        with mock.patch.object(self.github, "comment", side_effect=publish), \
                mock.patch.object(self.github, "close_issue", side_effect=finish):
            self.execute()
        row = self.controller.state.get_task(36)
        self.assertEqual(row["status"], "blocked")
        self.assertEqual(row["data"]["remote_action"], "close-issue")
        receipt = row["data"]["completion_receipt"]
        calls = copy.deepcopy(self.github.close_calls)
        self.restart()
        self.execute()
        row = self.controller.state.get_task(36)
        self.assertEqual(row["status"], "blocked")
        self.assertEqual(row["data"]["completion_receipt"], receipt)
        self.assertEqual(self.github.close_calls, calls)
        self.assertEqual(len(self.controller.state.receipts(36, "completion")), 1)
        self.assertEqual(self.github.issue(36)["state"], "open" if boundary == "comment" else "closed")

    def test_nested_task_added_during_completion_comment_preserves_original_receipt(self):
        self.task_publication("comment")

    def test_nested_task_added_during_close_cannot_finalize_on_restart(self):
        self.task_publication("close")

    def test_final_task_children_read_follows_slow_receipt_validation(self):
        receipt = self.accepted_fixture(36)
        validate = self.controller.receipt_valid
        def mutate(value):
            result = validate(value)
            self.nested()
            return result
        with mock.patch.object(self.controller, "receipt_valid", side_effect=mutate), \
                self.assertRaisesRegex(PipelineBlocked, "target native children"):
            self.controller.completion_preconditions(self.task, body_hash(self.github.issue(36)), receipt,
                                                     require_closed=True)

    def aggregate_publication(self, boundary):
        self.ready()
        comment, close = self.github.comment, self.github.close_issue
        def publish(number, body):
            result = comment(number, body)
            if ((boundary == "status" and "agenc-pipeline-live-status" in body)
                    or (boundary == "legacy-comment" and number == 13)
                    or (boundary == "master-comment" and number == 35 and "agenc-pipeline-aggregate:" in body)):
                self.nested(13, 36)
            return result
        def finish(number):
            result = close(number)
            if boundary == "close" and number == 35:
                self.nested(13, 36)
            return result
        with mock.patch.object(self.github, "comment", side_effect=publish), \
                mock.patch.object(self.github, "close_issue", side_effect=finish), self.assertRaises(PipelineBlocked):
            self.update()
        self.assert_blocked_open(13, 35)
        original = {n: self.entry(n)["preparation"] for n in (13, 35)}
        self.restart()
        with mock.patch("issue_pipeline.controller.halt_children"), self.assertRaises(PipelineBlocked):
            self.controller.recover()
        self.assert_blocked_open(13, 35)
        self.assertEqual({n: self.entry(n)["preparation"] for n in (13, 35)}, original)

    def test_nested_legacy_added_during_initial_status_closes_neither(self):
        self.aggregate_publication("status")

    def test_nested_legacy_added_during_legacy_comment_closes_neither(self):
        self.aggregate_publication("legacy-comment")

    def test_nested_legacy_added_during_master_comment_compensates_owned_legacy(self):
        self.aggregate_publication("master-comment")

    def test_nested_legacy_added_during_master_close_compensates_both(self):
        self.aggregate_publication("close")

    def test_new_nested_requirement_revokes_both_owned_terminals_on_restart(self):
        self.ready()
        self.update()
        terminals = {n: self.entry(n)["terminal"] for n in (13, 35)}
        self.nested(36, 41)
        self.restart()
        with mock.patch("issue_pipeline.controller.halt_children"), self.assertRaises(PipelineBlocked):
            self.controller.recover()
        self.assert_blocked_open(13, 35)
        self.assertEqual({n: self.entry(n)["terminal"] for n in (13, 35)}, terminals)

    def test_final_legacy_child_read_follows_slow_proof_validation(self):
        self.ready()
        self.update()
        ancestor = self.repo.is_ancestor
        def mutate(left, right):
            result = ancestor(left, right)
            self.nested(13, 36)
            return result
        with mock.patch.object(self.repo, "is_ancestor", side_effect=mutate), \
                self.assertRaisesRegex(PipelineBlocked, "target native children"):
            self.controller.check_aggregate(self.entry(13), closed=True)

    def test_final_master_children_read_rejects_late_missing_direct_member(self):
        self.ready()
        self.update()
        proof = self.controller.aggregate_proof
        def mutate(*args):
            result = proof(*args)
            if args[1] == "aggregate-completion":
                self.github.child_links[35].remove(86)
            return result
        with mock.patch.object(self.controller, "aggregate_proof", side_effect=mutate), \
                self.assertRaisesRegex(PipelineBlocked, "target native children"):
            self.controller.check_aggregate(self.entry(35), closed=True)

    def test_child_transport_failure_does_not_revoke_owned_terminals(self):
        self.ready()
        self.update()
        original = {n: copy.deepcopy(self.entry(n)) for n in (13, 35)}
        reader = self.github.children
        def disconnected(number):
            if number == 13:
                raise GithubError("child read transport unavailable")
            return reader(number)
        with mock.patch.object(self.github, "children", side_effect=disconnected), self.assertRaises(PipelineBlocked):
            self.update()
        self.assertEqual({n: self.entry(n) for n in (13, 35)}, original)
        self.assertEqual([self.github.issue(n)["state"] for n in (13, 35)], ["closed", "closed"])
        self.update()
        self.assertEqual(self.github.close_calls, [13, 35])

    def blocked_partial(self, *, owner=None, missing=None):
        terminal = self.pending_discovery_with_completed_legacy()
        if owner is not None:
            self.nested(owner, 36)
        if missing is not None:
            self.github.child_links[35].remove(missing)
        queue = copy.deepcopy(self.controller.state.get_task(36)["data"]["pending_discoveries"])
        journal = next((self.config.state / "backlog").glob("*.json")).read_bytes()
        with mock.patch("issue_pipeline.controller.halt_children"), self.assertRaises(NativeChildrenInvalid):
            self.controller.recover()
        self.assertEqual(self.controller.state.get_task(36)["data"]["pending_discoveries"], queue)
        self.assertEqual(next((self.config.state / "backlog").glob("*.json")).read_bytes(), journal)
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertEqual(self.github.next_issue, 101)
        return terminal

    def test_pending_discovery_nested_own_legacy_prerequisite_reopens_owned_legacy(self):
        self.blocked_partial(owner=41)
        self.assert_blocked_open(13)

    def test_pending_discovery_missing_legacy_master_membership_reopens_owned_legacy(self):
        self.blocked_partial(missing=13)
        self.assert_blocked_open(13)

    def test_pending_discovery_missing_required_master_membership_reopens_owned_legacy(self):
        self.blocked_partial(missing=41)
        self.assert_blocked_open(13)

    def test_unrelated_nested_requirement_preserves_valid_legacy_and_original_partial_repair(self):
        terminal = self.blocked_partial(owner=86)
        self.assertEqual(self.entry(13)["stage"], "complete")
        self.assertEqual(self.github.issue(13)["state"], "closed")
        self.github.child_links[86].clear()
        with mock.patch("issue_pipeline.controller.halt_children"):
            self.controller.recover()
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertEqual(self.entry(13)["stage"], "complete")
        self.assertIn(100, self.github.graph.by_issue)
        self.assertEqual(self.github.next_issue, 101)

    def test_prospective_lost_response_discovery_must_itself_remain_a_leaf(self):
        self.blocked_partial(owner=100)
        self.assertEqual(self.entry(13)["stage"], "complete")
        self.assertNotIn(100, self.github.graph.by_issue)

    def test_transport_during_partial_repair_preserves_approval_and_owned_legacy(self):
        terminal = self.pending_discovery_with_completed_legacy()
        reader = self.github.children
        def disconnected(number):
            if number == 41:
                raise GithubError("nested collection transport unavailable")
            return reader(number)
        with mock.patch.object(self.github, "children", side_effect=disconnected), \
                mock.patch("issue_pipeline.controller.halt_children"), self.assertRaises(BacklogError) as raised:
            self.controller.recover()
        self.assertNotIsInstance(raised.exception, NativeChildrenInvalid)
        self.assertEqual(self.entry(13)["stage"], "complete")
        self.assertEqual(self.github.issue(13)["state"], "closed")
        with mock.patch("issue_pipeline.controller.halt_children"):
            self.controller.recover()
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertIn(100, self.github.graph.by_issue)
        self.assertEqual(self.github.next_issue, 101)

    def test_late_final_master_membership_loss_cannot_complete_pending_discovery(self):
        terminal = self.pending_discovery_with_completed_legacy()
        guard, blockers = Backlog._guard, self.github.blockers
        final_seen = False
        def guarded(backlog, journal, path, **kwargs):
            nonlocal final_seen
            result = guard(backlog, journal, path, **kwargs)
            if 100 in self.github.graph.by_issue:
                final_seen = True
            return result
        def late_remove(number):
            if number == 35 and final_seen:
                self.github.child_links[35].discard(100)
            return blockers(number)
        with mock.patch.object(Backlog, "_guard", guarded), \
                mock.patch.object(self.github, "blockers", side_effect=late_remove), \
                mock.patch("issue_pipeline.controller.halt_children"), self.assertRaises(NativeChildrenInvalid):
            self.controller.recover()
        journal = json.loads(next((self.config.state / "backlog").glob("*.json")).read_text())
        self.assertEqual(journal["status"], "pending")
        self.assertEqual(self.entry(13)["terminal"], terminal)
        self.assertEqual(self.entry(13)["stage"], "complete")
        self.assertEqual(self.github.next_issue, 101)

    def test_uncheckpointed_completed_discovery_requires_current_leaf_hierarchy(self):
        fixture.ControllerTests.interrupt_discovery_registration(self, "after-register")
        self.nested(100, 36)
        data = self.controller.state.get_task(36)["data"]
        pending = copy.deepcopy(data["pending_discoveries"])
        with self.assertRaises(NativeChildrenInvalid):
            self.controller.resume_discoveries(self.task, data)
        self.assertEqual(self.controller.state.get_task(36)["data"]["pending_discoveries"], pending)
        self.assertEqual(self.github.next_issue, 101)


if __name__ == "__main__":
    unittest.main()
